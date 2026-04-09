use anyhow::Result;
use serde_json::Value;

pub mod shell;
pub mod file_list;
pub mod file_download;
pub mod screenshot;
pub mod process_list;

pub trait CommandHandler: Send + Sync {
    fn execute(&self, args: Value) -> Result<Value>;
}
