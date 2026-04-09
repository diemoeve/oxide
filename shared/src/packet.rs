use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub id: String,
    pub seq: u64,
    pub timestamp: u64,
    #[serde(rename = "type")]
    pub packet_type: String,
    #[serde(default)]
    pub data: serde_json::Value,
}

impl Packet {
    pub fn new(packet_type: &str, data: serde_json::Value) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            seq: 0,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            packet_type: packet_type.to_string(),
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_deserialize_roundtrip() {
        let pkt = Packet::new("checkin", serde_json::json!({"hwid": "abc123"}));
        let bytes = serde_json::to_vec(&pkt).unwrap();
        let decoded: Packet = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.packet_type, "checkin");
        assert_eq!(decoded.data["hwid"], "abc123");
    }

    #[test]
    fn packet_has_uuid_id() {
        let pkt = Packet::new("heartbeat", serde_json::json!({}));
        assert!(!pkt.id.is_empty());
        assert!(pkt.id.contains('-'));
    }

    #[test]
    fn packet_has_timestamp() {
        let pkt = Packet::new("heartbeat", serde_json::json!({}));
        assert!(pkt.timestamp > 0);
    }
}
