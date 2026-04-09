use anyhow::Result;
use serde_json::Value;
use std::fs;
use crate::commands::CommandHandler;

pub struct FileListHandler;

impl CommandHandler for FileListHandler {
    fn execute(&self, args: Value) -> Result<Value> {
        let path = args.get("path").and_then(|v| v.as_str()).unwrap_or(".");
        let mut entries = Vec::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            let modified = metadata.modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            entries.push(serde_json::json!({
                "name": entry.file_name().to_string_lossy(),
                "is_dir": metadata.is_dir(),
                "size": metadata.len(),
                "modified": modified,
            }));
        }
        Ok(serde_json::json!({"entries": entries}))
    }
}
