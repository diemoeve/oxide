use std::time::Duration;

#[derive(Debug, Clone)]
pub enum TransportMode { Tls, Http }

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub psk: String,
    pub salt: Vec<u8>,
    pub cert_hash: [u8; 32],
    pub transport: TransportMode,
    pub beacon_interval: Duration,
    pub beacon_jitter: f64,
    pub user_agent: String,
}

impl Config {
    pub fn lab_default() -> Self {
        let salt_bytes = hex::decode(
            std::fs::read_to_string("certs/salt.hex")
                .expect("run lab-setup/gen_certs.sh first").trim()
        ).expect("invalid salt hex");
        let hash_bytes = hex::decode(
            std::fs::read_to_string("certs/cert_hash.hex")
                .expect("run lab-setup/gen_certs.sh first").trim()
        ).expect("invalid cert hash hex");
        let mut cert_hash = [0u8; 32];
        cert_hash.copy_from_slice(&hash_bytes);

        let host = std::env::var("OXIDE_C2_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port = std::env::var("OXIDE_C2_PORT")
            .ok().and_then(|p| p.parse().ok()).unwrap_or(4444);

        #[cfg(feature = "http-transport")]
        let transport = TransportMode::Http;
        #[cfg(not(feature = "http-transport"))]
        let transport = TransportMode::Tls;

        Self {
            host,
            port,
            psk: "oxide-lab-psk".to_string(),
            salt: salt_bytes,
            cert_hash,
            transport,
            beacon_interval: Duration::from_secs(30),
            beacon_jitter: 0.25,
            user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                         (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36".to_string(),
        }
    }
}
