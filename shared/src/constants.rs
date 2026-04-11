pub const MAX_MESSAGE_SIZE: u32 = 16_777_216; // 16 MB
pub const AES_KEY_SIZE: usize = 32; // AES-256
pub const NONCE_SIZE: usize = 12; // GCM standard
pub const DIRECTION_PREFIX_SIZE: usize = 4;
pub const PBKDF2_ITERATIONS: u32 = 600_000; // OWASP 2023
pub const PBKDF2_SALT_SIZE: usize = 32;
pub const LENGTH_PREFIX_SIZE: usize = 4;
pub const VERSION: &str = "0.1.0";
