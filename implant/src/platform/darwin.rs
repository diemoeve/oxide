use super::SystemInfo;

pub fn gather_system_info() -> SystemInfo {
    SystemInfo {
        hwid: "darwin-not-implemented".to_string(),
        hostname: "unknown".to_string(),
        os: "macos".to_string(),
        arch: std::env::consts::ARCH.to_string(),
        username: "unknown".to_string(),
        privileges: "unknown".to_string(),
        av: vec![],
        exe_path: "unknown".to_string(),
    }
}
