#![allow(dead_code)] // stub replaced in Task 2/3/4
use crate::persistence::PersistenceTrait;
use std::path::Path;
pub struct CronPersistence;
impl PersistenceTrait for CronPersistence {
    fn install(&self, _: &Path) -> anyhow::Result<()> { anyhow::bail!("not yet") }
    fn remove(&self) -> anyhow::Result<()> { Ok(()) }
    fn check(&self) -> bool { false }
    fn name(&self) -> &'static str { "cron" }
}
