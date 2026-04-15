//! PEB/EAT walk — finds loaded modules and resolves exports without calling
//! GetProcAddress or GetModuleHandle (both are IOCs visible to EDR hooks).
//!
//! PEB pointer: gs:[0x60] on x86_64 Windows (TEB.ProcessEnvironmentBlock).
//! gs:[0x30] is TEB.Self (self-pointer to TEB, not PEB).

// --- PEB / LDR structures (offsets from InMemoryOrderLinks pointer) --------

// When walking InMemoryOrderModuleList, the Flink pointer points to the
// InMemoryOrderLinks field *within* an LDR_DATA_TABLE_ENTRY at offset +0x10.
// To reach other fields, subtract 0x10 and add the full entry offset:
//
//   DllBase          at full-entry 0x30  → from InMemoryOrderLinks: +0x20
//   BaseDllName.Len  at full-entry 0x58  → from InMemoryOrderLinks: +0x48 (u16)
//   BaseDllName.Buf  at full-entry 0x60  → from InMemoryOrderLinks: +0x50 (*u16)
//
// UNICODE_STRING layout (x64, #[repr(C)]):
//   0x00 Length (u16), 0x02 MaxLength (u16), 0x04 padding (u32), 0x08 Buffer (*u16)
// sizeof(UNICODE_STRING) = 16 bytes due to natural alignment of *u16 (8-byte pointer).

const IMO_DLLBASE_OFFSET: usize = 0x20;
const IMO_NAME_LEN_OFFSET: usize = 0x48;
const IMO_NAME_BUF_OFFSET: usize = 0x50;

/// Read the PEB address from gs:[0x60] (x86_64 Windows, TEB.ProcessEnvironmentBlock).
///
/// # Safety
/// Must run on Windows x86_64 with a valid TEB in GS.
#[cfg(target_arch = "x86_64")]
unsafe fn peb_address() -> *const u8 {
    let peb: *const u8;
    core::arch::asm!(
        "mov {}, qword ptr gs:[0x60]",
        out(reg) peb,
        options(nostack, preserves_flags),
    );
    peb
}

/// Walk the PEB InMemoryOrderModuleList to find a loaded DLL's base address.
/// Comparison is case-insensitive ASCII; does NOT call any Win32 API.
///
/// Returns `None` if the module is not currently loaded.
///
/// # Safety
/// PEB must be valid (always true in a healthy Windows process).
#[cfg(target_arch = "x86_64")]
pub unsafe fn find_module(name: &str) -> Option<*const u8> {
    let peb = peb_address();
    // PEB.Ldr (pointer to PEB_LDR_DATA) at PEB offset 0x18
    let ldr = *(peb.add(0x18) as *const *const u8);
    // PEB_LDR_DATA.InMemoryOrderModuleList.Flink at LDR_DATA offset 0x20
    let mut entry = *(ldr.add(0x20) as *const *const u8);
    let list_head = entry;

    loop {
        let name_len = *(entry.add(IMO_NAME_LEN_OFFSET) as *const u16);
        let name_buf = *(entry.add(IMO_NAME_BUF_OFFSET) as *const *const u16);

        if !name_buf.is_null() && name_len > 0 {
            let chars = core::slice::from_raw_parts(name_buf, (name_len / 2) as usize);
            if utf16_eq_ascii_icase(chars, name) {
                let dll_base = *(entry.add(IMO_DLLBASE_OFFSET) as *const *const u8);
                return Some(dll_base);
            }
        }

        let next = *(entry as *const *const u8);
        if next == list_head || next.is_null() {
            break;
        }
        entry = next;
    }

    None
}

/// Walk the PE export directory to resolve a named export's virtual address.
/// Does NOT call GetProcAddress.
///
/// `name` must be an ASCII byte slice without null terminator (e.g. `b"NtTraceEvent"`).
///
/// # Safety
/// `module_base` must point to a valid PE image mapped in memory.
#[cfg(target_arch = "x86_64")]
pub unsafe fn resolve_export(module_base: *const u8, name: &[u8]) -> Option<*const u8> {
    // IMAGE_DOS_HEADER.e_lfanew at offset 0x3C
    let e_lfanew = *(module_base.add(0x3C) as *const i32) as usize;
    let nt_hdrs = module_base.add(e_lfanew);

    // IMAGE_NT_HEADERS64.OptionalHeader.DataDirectory[0].VirtualAddress
    // NtHeaders + 0x18 (OptionalHeader start) + 0x70 (DataDirectory[0].VirtualAddress offset)
    // = NtHeaders + 0x88
    let export_rva = *(nt_hdrs.add(0x88) as *const u32) as usize;
    if export_rva == 0 {
        return None;
    }

    let exp = module_base.add(export_rva);
    // IMAGE_EXPORT_DIRECTORY:
    //   0x18 NumberOfNames (u32)
    //   0x1C AddressOfFunctions (u32 RVA)
    //   0x20 AddressOfNames (u32 RVA)
    //   0x24 AddressOfNameOrdinals (u32 RVA)
    // IMAGE_DATA_DIRECTORY[0].Size is the u32 immediately after VirtualAddress (NtHeaders+0x8C)
    let export_dir_size = *(nt_hdrs.add(0x8C) as *const u32) as usize;

    let num_names = *(exp.add(0x18) as *const u32) as usize;
    let fn_rva_table = module_base.add(*(exp.add(0x1C) as *const u32) as usize) as *const u32;
    let name_rva_table = module_base.add(*(exp.add(0x20) as *const u32) as usize) as *const u32;
    let ord_table = module_base.add(*(exp.add(0x24) as *const u32) as usize) as *const u16;

    // Strip null terminator if present (defensive)
    let target = name.strip_suffix(b"\0").unwrap_or(name);

    for i in 0..num_names {
        let name_ptr = module_base.add(*name_rva_table.add(i) as usize);
        if cstr_eq(name_ptr, target) {
            let ordinal = *ord_table.add(i) as usize;
            let fn_rva = *fn_rva_table.add(ordinal) as usize;
            // Forwarder RVA: fn_rva falls inside the export directory itself.
            // It points to an ASCII forwarder string, not executable code — skip it.
            if fn_rva >= export_rva && fn_rva < export_rva + export_dir_size {
                return None;
            }
            return Some(module_base.add(fn_rva));
        }
    }

    None
}

// --- helpers -----------------------------------------------------------------

/// Case-insensitive ASCII comparison of a UTF-16 slice against an ASCII &str.
/// Strips ".DLL" / ".dll" suffix before comparing, matching dinvk's behaviour.
fn utf16_eq_ascii_icase(utf16: &[u16], ascii: &str) -> bool {
    let ascii_upper: Vec<u8> = ascii.bytes()
        .map(|b| b.to_ascii_uppercase())
        .collect();
    let ascii_trimmed = ascii_upper
        .strip_suffix(b".DLL")
        .unwrap_or(&ascii_upper);

    // Non-ASCII code unit in the DLL name → cannot match an ASCII query.
    let utf16_ascii: Option<Vec<u8>> = utf16.iter()
        .map(|&c| if c < 128 { Some((c as u8).to_ascii_uppercase()) } else { None })
        .collect();
    let Some(utf16_upper) = utf16_ascii else { return false; };
    let utf16_trimmed = utf16_upper
        .strip_suffix(b".DLL")
        .unwrap_or(&utf16_upper);

    utf16_trimmed == ascii_trimmed
}

/// Compare a null-terminated C string at `ptr` with an ASCII byte slice.
/// Returns true only on exact match (target fully consumed and C string ends there).
unsafe fn cstr_eq(ptr: *const u8, target: &[u8]) -> bool {
    for (i, &expected) in target.iter().enumerate() {
        let actual = *ptr.add(i);
        if actual == 0 || actual != expected {
            return false;
        }
    }
    *ptr.add(target.len()) == 0
}

// --- tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_eq_ascii_icase_exact() {
        let s: Vec<u16> = "ntdll.dll".encode_utf16().collect();
        assert!(utf16_eq_ascii_icase(&s, "ntdll.dll"));
        assert!(utf16_eq_ascii_icase(&s, "NTDLL.DLL"));
        assert!(utf16_eq_ascii_icase(&s, "Ntdll"));
    }

    #[test]
    fn utf16_eq_ascii_icase_no_match() {
        let s: Vec<u16> = "kernel32.dll".encode_utf16().collect();
        assert!(!utf16_eq_ascii_icase(&s, "ntdll.dll"));
    }

    #[test]
    fn cstr_eq_match() {
        let s = b"NtTraceEvent\0";
        unsafe {
            assert!(cstr_eq(s.as_ptr(), b"NtTraceEvent"));
            assert!(!cstr_eq(s.as_ptr(), b"NtTraceEven"));   // prefix — C string continues
            assert!(!cstr_eq(s.as_ptr(), b"NtTraceEventX")); // target longer than C string
        }
    }
}
