use anyhow::Result;
use serde_json::Value;
use std::process::Command;
use crate::commands::CommandHandler;

pub struct ShellHandler;

impl CommandHandler for ShellHandler {
    fn execute(&self, args: Value) -> Result<Value> {
        let command = args.get("command")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing 'command' argument"))?;

        let shell = if cfg!(target_os = "windows") { "cmd" } else { "/bin/sh" };
        let flag = if cfg!(target_os = "windows") { "/c" } else { "-c" };

        let output = Command::new(shell).args([flag, command]).output()?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        Ok(serde_json::json!({
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": output.status.code(),
        }))
    }
}
