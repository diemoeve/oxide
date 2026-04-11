use crate::constants::*;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("data too short for decryption")]
    TooShort,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("replay detected")]
    ReplayDetected,
}

pub struct CryptoContext {
    cipher: Aes256Gcm,
    send_counter: u64,
    last_recv_counter: Option<u64>,
    direction_prefix: [u8; 4],
}

impl CryptoContext {
    pub fn new(psk: &str, salt: &[u8], is_initiator: bool) -> Self {
        let key = derive_key(psk, salt);
        let cipher = Aes256Gcm::new_from_slice(&key).expect("valid key size");
        let direction_prefix = if is_initiator {
            [0x00, 0x00, 0x00, 0x00]
        } else {
            [0x01, 0x00, 0x00, 0x00]
        };
        Self {
            cipher,
            send_counter: 0,
            last_recv_counter: None,
            direction_prefix,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let nonce_bytes = self.make_nonce(self.send_counter);
        self.send_counter += 1;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .expect("encryption should not fail");
        let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < NONCE_SIZE + 16 {
            return Err(CryptoError::TooShort);
        }
        let nonce_bytes = &data[..NONCE_SIZE];
        let counter = u64::from_le_bytes(
            nonce_bytes[DIRECTION_PREFIX_SIZE..NONCE_SIZE]
                .try_into()
                .unwrap(),
        );
        if let Some(last) = self.last_recv_counter {
            if counter <= last {
                return Err(CryptoError::ReplayDetected);
            }
        }
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self
            .cipher
            .decrypt(nonce, &data[NONCE_SIZE..])
            .map_err(|_| CryptoError::DecryptFailed)?;
        self.last_recv_counter = Some(counter);
        Ok(plaintext)
    }

    fn make_nonce(&self, counter: u64) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..DIRECTION_PREFIX_SIZE].copy_from_slice(&self.direction_prefix);
        nonce[DIRECTION_PREFIX_SIZE..].copy_from_slice(&counter.to_le_bytes());
        nonce
    }
}

/// Derive a 32-byte AES-256 key from PSK + salt via PBKDF2-HMAC-SHA256.
pub fn derive_key(psk: &str, salt: &[u8]) -> [u8; AES_KEY_SIZE] {
    let mut key = [0u8; AES_KEY_SIZE];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(psk.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Encrypt with a fresh random 12-byte nonce. Output: `[nonce][ct+tag]`.
/// No counter — safe for stateless HTTP (TLS handles replay prevention).
pub fn encrypt_stateless(key: &[u8; AES_KEY_SIZE], plaintext: &[u8]) -> Vec<u8> {
    use rand::RngCore;
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, plaintext).expect("encrypt");
    let mut out = Vec::with_capacity(NONCE_SIZE + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

/// Decrypt output of `encrypt_stateless`. Input: `[12-byte nonce][ct+tag]`.
pub fn decrypt_stateless(key: &[u8; AES_KEY_SIZE], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < NONCE_SIZE + 16 {
        return Err(CryptoError::TooShort);
    }
    let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    cipher
        .decrypt(nonce, &data[NONCE_SIZE..])
        .map_err(|_| CryptoError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PSK: &str = "test-passphrase-oxide";
    const TEST_SALT: &[u8; 32] = b"test-salt-must-be-32-bytes-long!";

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut sender = CryptoContext::new(TEST_PSK, TEST_SALT, true);
        let mut receiver = CryptoContext::new(TEST_PSK, TEST_SALT, false);
        let plaintext = b"hello oxide";
        let encrypted = sender.encrypt(plaintext);
        let decrypted = receiver.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let mut sender = CryptoContext::new("correct-key", TEST_SALT, true);
        let mut receiver = CryptoContext::new("wrong-key", TEST_SALT, false);
        let encrypted = sender.encrypt(b"secret");
        assert!(receiver.decrypt(&encrypted).is_err());
    }

    #[test]
    fn nonces_differ_per_message() {
        let mut ctx = CryptoContext::new(TEST_PSK, TEST_SALT, true);
        let enc1 = ctx.encrypt(b"msg1");
        let enc2 = ctx.encrypt(b"msg2");
        assert_ne!(&enc1[..12], &enc2[..12]);
    }

    #[test]
    fn replay_detected() {
        let mut sender = CryptoContext::new(TEST_PSK, TEST_SALT, true);
        let mut receiver = CryptoContext::new(TEST_PSK, TEST_SALT, false);
        let encrypted = sender.encrypt(b"first");
        let _ = receiver.decrypt(&encrypted).unwrap();
        assert!(matches!(
            receiver.decrypt(&encrypted),
            Err(CryptoError::ReplayDetected)
        ));
    }

    #[test]
    fn data_too_short() {
        let mut ctx = CryptoContext::new(TEST_PSK, TEST_SALT, false);
        assert!(matches!(
            ctx.decrypt(&[0u8; 10]),
            Err(CryptoError::TooShort)
        ));
    }

    #[test]
    fn direction_prefix_prevents_self_decrypt() {
        let mut ctx = CryptoContext::new(TEST_PSK, TEST_SALT, true);
        let encrypted = ctx.encrypt(b"self-test");
        let nonce_prefix = &encrypted[..4];
        assert_eq!(nonce_prefix, &[0, 0, 0, 0]); // initiator prefix
    }

    #[test]
    fn stateless_encrypt_decrypt_roundtrip() {
        let key = derive_key("test-psk", b"test-salt-must-be-32-bytes-long!");
        let ct = encrypt_stateless(&key, b"hello oxide");
        assert_eq!(decrypt_stateless(&key, &ct).unwrap(), b"hello oxide");
    }

    #[test]
    fn stateless_nonces_differ_per_call() {
        let key = derive_key("test-psk", b"test-salt-must-be-32-bytes-long!");
        let c1 = encrypt_stateless(&key, b"same");
        let c2 = encrypt_stateless(&key, b"same");
        assert_ne!(&c1[..NONCE_SIZE], &c2[..NONCE_SIZE]);
    }

    #[test]
    fn stateless_wrong_key_fails() {
        let k1 = derive_key("key1", b"test-salt-must-be-32-bytes-long!");
        let k2 = derive_key("key2", b"test-salt-must-be-32-bytes-long!");
        let ct = encrypt_stateless(&k1, b"secret");
        assert!(decrypt_stateless(&k2, &ct).is_err());
    }

    #[test]
    fn stateless_too_short_fails() {
        let key = derive_key("k", b"test-salt-must-be-32-bytes-long!");
        assert!(matches!(
            decrypt_stateless(&key, &[0u8; 10]),
            Err(CryptoError::TooShort)
        ));
    }

    #[test]
    fn derive_key_is_stable() {
        let k1 = derive_key("psk", b"test-salt-must-be-32-bytes-long!");
        let k2 = derive_key("psk", b"test-salt-must-be-32-bytes-long!");
        assert_eq!(k1, k2);
    }
}
