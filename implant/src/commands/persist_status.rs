use crate::commands::CommandHandler;
use crate::persistence;
use anyhow::Result;
use serde_json::Value;

pub struct PersistStatusHandler;

impl CommandHandler for PersistStatusHandler {
    fn execute(&self, _args: Value) -> Result<Value> {
        let statuses = persistence::get_chain().check_all();
        Ok(serde_json::json!({
            "methods": statuses.iter().map(|s| serde_json::json!({
                "name": s.name,
                "installed": s.installed,
            })).collect::<Vec<_>>(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persist_status_returns_methods_array() {
        let result = PersistStatusHandler.execute(Value::Null).unwrap();
        assert!(result["methods"].is_array());
    }
}
