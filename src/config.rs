use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionMode {
    ChaCha20Poly1305,
    Aes256Gcm,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub client_port: u16,
    pub stun_server: String,
    pub stun_verifier: String,
    pub web_port: u16,
    pub handshake_timeout_secs: u64,
    pub punch_hole_secs: u64,
    pub disconnect_timeout_ms: u64,
    pub encryption_mode: EncryptionMode,
}

impl Config {
    pub fn load() -> Self {
        Self {
            client_port: 0,
            stun_server: "stun.l.google.com:19302".to_string(),
            stun_verifier: "stun4.l.google.com:19302".to_string(),
            web_port: 8080,
            handshake_timeout_secs: 30,
            punch_hole_secs: 15,
            disconnect_timeout_ms: 500,
            encryption_mode: EncryptionMode::ChaCha20Poly1305,
        }
    }
}
