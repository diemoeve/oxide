use crate::commands::CommandHandler;
use oxide_shared::packet::Packet;
use std::collections::HashMap;

pub struct Dispatcher {
    handlers: HashMap<String, Box<dyn CommandHandler>>,
}

impl Dispatcher {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    pub fn register(&mut self, command_type: &str, handler: Box<dyn CommandHandler>) {
        self.handlers.insert(command_type.to_string(), handler);
    }

    pub fn dispatch(&self, packet: &Packet) -> Packet {
        let command_type = packet
            .data
            .get("command_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let args = packet.data.get("args").cloned().unwrap_or_default();

        match self.handlers.get(command_type) {
            Some(handler) => match handler.execute(args) {
                Ok(output) => Packet::new(
                    "response",
                    serde_json::json!({
                        "command_id": packet.id,
                        "status": "success",
                        "data": output,
                    }),
                ),
                Err(e) => Packet::new(
                    "response",
                    serde_json::json!({
                        "command_id": packet.id,
                        "status": "error",
                        "data": e.to_string(),
                    }),
                ),
            },
            None => Packet::new(
                "error",
                serde_json::json!({
                    "code": "unknown_command",
                    "message": format!("unknown command type: {command_type}"),
                }),
            ),
        }
    }
}
