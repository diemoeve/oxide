use anyhow::Result;
use serde_json::Value;
use base64::Engine;
use std::process::Command;
use crate::commands::CommandHandler;

pub struct ScreenshotHandler;

impl CommandHandler for ScreenshotHandler {
    fn execute(&self, _args: Value) -> Result<Value> {
        let tmp_path = "/tmp/.oxide_screenshot.png";
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
            Ok(s) => anyhow::bail!("scrot exited with status: {}", s),
            Err(e) => anyhow::bail!("screenshot capture failed: {e} (is scrot installed? is DISPLAY set?)"),
        }
    }
}
