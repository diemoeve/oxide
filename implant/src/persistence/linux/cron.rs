use crate::persistence::PersistenceTrait;
use std::path::Path;
use std::io::Write;
use std::process::{Command, Stdio};

pub struct CronPersistence;

fn entry_string(path: &Path) -> String {
    format!("@reboot {}\n", path.display())
}

fn entry_present(crontab: &str, path: &Path) -> bool {
    let marker = path.to_str().unwrap_or("");
    crontab.lines()
        .any(|l| l.trim_start().starts_with("@reboot") && l.contains(marker))
}

fn entry_removed(crontab: &str, path: &Path) -> String {
    let marker = path.to_str().unwrap_or("");
    let lines: Vec<&str> = crontab.lines()
        .filter(|l| !(l.trim_start().starts_with("@reboot") && l.contains(marker)))
        .collect();
    if lines.is_empty() { String::new() } else { lines.join("\n") + "\n" }
}

fn read_crontab() -> String {
    Command::new("crontab").arg("-l").output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

fn write_crontab(content: &str) -> anyhow::Result<()> {
    if content.trim().is_empty() {
        // crontab -r exits 1 if no crontab exists — treat as non-fatal no-op.
        let _ = Command::new("crontab").arg("-r").status();
        return Ok(());
    }
    let mut child = Command::new("crontab").arg("-").stdin(Stdio::piped()).spawn()?;
    child.stdin.take()
        .ok_or_else(|| anyhow::anyhow!("no stdin"))?
        .write_all(content.as_bytes())?;
    let status = child.wait()?;
    anyhow::ensure!(status.success(), "crontab write failed");
    Ok(())
}

impl PersistenceTrait for CronPersistence {
    fn install(&self, binary_path: &Path) -> anyhow::Result<()> {
        let existing = read_crontab();
        if entry_present(&existing, binary_path) { return Ok(()); }
        write_crontab(&format!("{}{}", existing, entry_string(binary_path)))
    }

    fn remove(&self) -> anyhow::Result<()> {
        let stable = crate::persistence::stable_path()?;
        let existing = read_crontab();
        if !entry_present(&existing, &stable) { return Ok(()); }
        write_crontab(&entry_removed(&existing, &stable))
    }

    fn check(&self) -> bool {
        crate::persistence::stable_path()
            .map(|p| entry_present(&read_crontab(), &p))
            .unwrap_or(false)
    }

    fn name(&self) -> &'static str { "cron" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_string_format() {
        let p = Path::new("/home/user/.local/share/oxide/oxide-update");
        assert_eq!(entry_string(p), "@reboot /home/user/.local/share/oxide/oxide-update\n");
    }

    #[test]
    fn entry_present_detects_reboot_line() {
        let tab = "@reboot /home/user/.local/share/oxide/oxide-update\n*/5 * * * * other\n";
        assert!(entry_present(tab, Path::new("/home/user/.local/share/oxide/oxide-update")));
    }

    #[test]
    fn entry_present_ignores_non_reboot() {
        let tab = "*/5 * * * * /home/user/.local/share/oxide/oxide-update\n";
        assert!(!entry_present(tab, Path::new("/home/user/.local/share/oxide/oxide-update")));
    }

    #[test]
    fn entry_present_false_empty() {
        assert!(!entry_present("", Path::new("/home/user/.local/share/oxide/oxide-update")));
    }

    #[test]
    fn entry_removed_strips_reboot_line() {
        let tab = "*/5 * * * * /usr/bin/cleanup\n@reboot /home/user/.local/share/oxide/oxide-update\n";
        let r = entry_removed(tab, Path::new("/home/user/.local/share/oxide/oxide-update"));
        assert!(!r.contains("oxide-update"));
        assert!(r.contains("/usr/bin/cleanup"));
    }

    #[test]
    fn entry_removed_single_entry_gives_empty() {
        let tab = "@reboot /home/user/.local/share/oxide/oxide-update\n";
        assert_eq!(entry_removed(tab, Path::new("/home/user/.local/share/oxide/oxide-update")), "");
    }
}
