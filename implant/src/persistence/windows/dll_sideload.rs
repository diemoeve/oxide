use crate::persistence::PersistenceTrait;
use std::path::Path;

pub struct DllSideloadPersistence;

#[cfg(target_os = "windows")]
impl PersistenceTrait for DllSideloadPersistence {
    fn install(&self, _: &Path) -> anyhow::Result<()> {
        // Requires a cdylib build target. EXE/DLL mismatch deferred to S5 loader chain.
        anyhow::bail!("DLL sideloading deferred to S5")
    }
    fn remove(&self) -> anyhow::Result<()> { Ok(()) }
    fn check(&self) -> bool { false }
    fn name(&self) -> &'static str { "dll_sideload" }
}

#[cfg(not(target_os = "windows"))]
impl PersistenceTrait for DllSideloadPersistence {
    fn install(&self, _: &Path) -> anyhow::Result<()> {
        anyhow::bail!("DLL sideloading not available on this platform")
    }
    fn remove(&self) -> anyhow::Result<()> { Ok(()) }
    fn check(&self) -> bool { false }
    fn name(&self) -> &'static str { "dll_sideload" }
}
