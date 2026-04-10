use crate::persistence::PersistenceTrait;
use std::path::Path;
pub struct BashProfilePersistence;
impl PersistenceTrait for BashProfilePersistence {
    fn install(&self, _: &Path) -> anyhow::Result<()> { anyhow::bail!("not yet") }
    fn remove(&self) -> anyhow::Result<()> { Ok(()) }
    fn check(&self) -> bool { false }
    fn name(&self) -> &'static str { "bash_profile" }
}
