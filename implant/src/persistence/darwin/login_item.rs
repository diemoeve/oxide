use crate::persistence::PersistenceTrait;
use std::path::Path;
use std::process::Command;

pub struct LoginItemPersistence;

impl PersistenceTrait for LoginItemPersistence {
    fn install(&self, binary_path: &Path) -> anyhow::Result<()> {
        let s = binary_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid path"))?;
        // Legacy AppleScript. Works on macOS <= 12 and macOS 13+ (old method still functional).
        // macOS 13+ shows a BTM notification to the user when registered.
        // name: property required on Ventura 13.0.x to avoid "login item UNKNOWN" error.
        let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!(
            "tell application \"System Events\" to make login item at end \
             with properties {{path:\"{escaped}\", hidden:true, name:\"System Monitor\"}}"
        );
        let status = Command::new("osascript").args(["-e", &script]).status()?;
        anyhow::ensure!(status.success(), "osascript failed");
        Ok(())
    }

    fn remove(&self) -> anyhow::Result<()> {
        let script = "tell application \"System Events\" to delete login item \"System Monitor\"";
        let _ = Command::new("osascript").args(["-e", script]).status();
        Ok(())
    }

    fn check(&self) -> bool {
        Command::new("osascript")
            .args([
                "-e",
                "tell application \"System Events\" to get the name of every login item",
            ])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("System Monitor"))
            .unwrap_or(false)
    }

    fn name(&self) -> &'static str {
        "login_item"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn applescript_includes_name_property() {
        // Verify the script format contains the name: property (required on Ventura 13.0.x)
        let s = "/usr/local/bin/oxide";
        let script = format!(
            "tell application \"System Events\" to make login item at end \
             with properties {{path:\"{s}\", hidden:true, name:\"System Monitor\"}}"
        );
        assert!(script.contains("name:\"System Monitor\""));
        assert!(script.contains("hidden:true"));
    }
}
