use crate::commands::CommandHandler;
use crate::persistence;
use anyhow::Result;
use serde_json::Value;

pub struct PersistRemoveHandler;

impl CommandHandler for PersistRemoveHandler {
    fn execute(&self, _args: Value) -> Result<Value> {
        let results = persistence::get_chain().remove_all();
        Ok(serde_json::json!({
            "methods": results.iter().map(|r| serde_json::json!({
                "name": r.name,
                "removed": !r.installed,
                "error": r.error,
            })).collect::<Vec<_>>(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "invokes live systemctl disable; run manually to verify"]
    fn persist_remove_returns_methods_array() {
        let result = PersistRemoveHandler.execute(Value::Null).unwrap();
        assert!(result["methods"].is_array());
    }
}
