use crate::commands::CommandHandler;
use anyhow::Result;
use serde_json::Value;

pub struct ScreenshotHandler;

impl CommandHandler for ScreenshotHandler {
    fn execute(&self, _args: Value) -> Result<Value> {
        #[cfg(target_os = "linux")]
        {
            use base64::Engine;
            use std::process::Command;
            let tmp_path = "/tmp/.sc.tmp";
            let status = Command::new("scrot").args(["-o", tmp_path]).status();
            match status {
                Ok(s) if s.success() => {
                    let data = std::fs::read(tmp_path)?;
                    let _ = std::fs::remove_file(tmp_path);
                    let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                    Ok(serde_json::json!({
                        "format": "png",
                        "size": data.len(),
                        "data_b64": b64,
                    }))
                }
                Ok(s) => anyhow::bail!("capture failed: {}", s),
                Err(e) => anyhow::bail!("capture unavailable: {e}"),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("screenshot not supported on this platform")
        }
    }
}
