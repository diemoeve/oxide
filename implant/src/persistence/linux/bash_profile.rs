use crate::persistence::PersistenceTrait;
use std::io::Write;
use std::path::Path;

pub struct BashProfilePersistence;

const MARKER: &str = "# user-autostart";

fn append_block(binary_path: &Path) -> String {
    format!("{}\n{} &\n", MARKER, binary_path.display())
}

fn is_present(content: &str) -> bool {
    content.contains(MARKER)
}

fn remove_block(content: &str) -> String {
    let mut result = String::new();
    let mut skip_next = false;
    for line in content.lines() {
        if line == MARKER {
            skip_next = true;
            continue;
        }
        if skip_next {
            skip_next = false;
            continue;
        }
        result.push_str(line);
        result.push('\n');
    }
    result
}

fn profile_paths() -> Vec<std::path::PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();
    vec![
        std::path::PathBuf::from(&home).join(".bashrc"),
        std::path::PathBuf::from(&home).join(".bash_profile"),
    ]
}

impl PersistenceTrait for BashProfilePersistence {
    fn install(&self, binary_path: &Path) -> anyhow::Result<()> {
        let block = append_block(binary_path);
        let mut ok = false;
        for path in &profile_paths() {
            let existing = std::fs::read_to_string(path).unwrap_or_default();
            if is_present(&existing) {
                ok = true;
                continue;
            }
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)?;
            f.write_all(block.as_bytes())?;
            ok = true;
        }
        anyhow::ensure!(ok, "no writable shell profile found");
        Ok(())
    }

    fn remove(&self) -> anyhow::Result<()> {
        for path in &profile_paths() {
            if let Ok(content) = std::fs::read_to_string(path) {
                if is_present(&content) {
                    std::fs::write(path, remove_block(&content))?;
                }
            }
        }
        Ok(())
    }

    fn check(&self) -> bool {
        profile_paths().iter().any(|p| {
            std::fs::read_to_string(p)
                .map(|c| is_present(&c))
                .unwrap_or(false)
        })
    }

    fn name(&self) -> &'static str {
        "bash_profile"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_block_has_marker_and_exec_line() {
        let b = append_block(Path::new("/home/user/.local/share/oxide/oxide-update"));
        assert!(b.contains(MARKER));
        assert!(b.contains("/home/user/.local/share/oxide/oxide-update &"));
    }

    #[test]
    fn is_present_true_with_marker() {
        assert!(is_present(
            "export PATH=$PATH\n# user-autostart\n/path &\n"
        ));
    }

    #[test]
    fn is_present_false_clean() {
        assert!(!is_present("export PATH=$PATH\nalias ll='ls -la'\n"));
    }

    #[test]
    fn remove_block_strips_marker_and_line() {
        let c = "export PATH=$PATH\n# user-autostart\n/path/oxide &\nalias ll='ls -la'\n";
        let r = remove_block(c);
        assert!(!r.contains(MARKER) && !r.contains("/path/oxide"));
        assert!(r.contains("alias ll"));
    }

    #[test]
    fn remove_block_unchanged_without_marker() {
        assert_eq!(remove_block("export PATH=$PATH\n"), "export PATH=$PATH\n");
    }

    #[test]
    fn remove_block_handles_double_install() {
        // If install was called twice (double marker), remove_block removes both pairs
        let c = "export PATH=$PATH\n# user-autostart\n/path/oxide &\n# user-autostart\n/path/oxide &\nalias ll='ls -la'\n";
        let r = remove_block(c);
        assert!(!r.contains("# user-autostart"));
        assert!(!r.contains("/path/oxide"));
        assert!(r.contains("alias ll"));
    }
}
