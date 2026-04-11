use crate::commands::CommandHandler;
use anyhow::Result;
use serde_json::Value;

pub struct ProcessListHandler;

impl CommandHandler for ProcessListHandler {
    fn execute(&self, _args: Value) -> Result<Value> {
        let mut processes = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let pid_str = name.to_string_lossy().to_string();
                let pid: u32 = match pid_str.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let proc_name = std::fs::read_to_string(format!("/proc/{pid}/status"))
                    .unwrap_or_default()
                    .lines()
                    .find(|l| l.starts_with("Name:"))
                    .map(|l| l.split_whitespace().nth(1).unwrap_or("").to_string())
                    .unwrap_or_default();
                let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
                    .unwrap_or_default()
                    .replace('\0', " ")
                    .trim()
                    .to_string();
                let uid: u32 = std::fs::read_to_string(format!("/proc/{pid}/status"))
                    .unwrap_or_default()
                    .lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                processes.push(serde_json::json!({
                    "pid": pid,
                    "name": proc_name,
                    "cmdline": cmdline,
                    "uid": uid,
                }));
            }
        }
        Ok(serde_json::json!({"processes": processes}))
    }
}
