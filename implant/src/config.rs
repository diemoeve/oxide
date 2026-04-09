pub struct Config {
    pub host: String,
    pub port: u16,
    pub psk: String,
    pub salt: Vec<u8>,
    pub cert_hash: [u8; 32],
}

impl Config {
    pub fn lab_default() -> Self {
        let salt = std::fs::read_to_string("certs/salt.hex")
            .expect("run lab-setup/gen_certs.sh first")
            .trim()
            .to_string();
        let salt_bytes = hex::decode(&salt).expect("invalid salt hex");

        let hash_hex = std::fs::read_to_string("certs/cert_hash.hex")
            .expect("run lab-setup/gen_certs.sh first")
            .trim()
            .to_string();
        let hash_bytes = hex::decode(&hash_hex).expect("invalid cert hash hex");
        let mut cert_hash = [0u8; 32];
        cert_hash.copy_from_slice(&hash_bytes);

        Self {
            host: "127.0.0.1".to_string(),
            port: 4444,
            psk: "oxide-lab-psk".to_string(),
            salt: salt_bytes,
            cert_hash,
        }
    }
}
