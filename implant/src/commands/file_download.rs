use anyhow::Result;
use serde_json::Value;
use base64::Engine;
use crate::commands::CommandHandler;

pub struct FileDownloadHandler;

impl CommandHandler for FileDownloadHandler {
    fn execute(&self, args: Value) -> Result<Value> {
        let path = args.get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing 'path' argument"))?;
        let data = std::fs::read(path)?;
        let size = data.len();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
        Ok(serde_json::json!({
            "path": path,
            "size": size,
            "data_b64": b64,
        }))
    }
}
