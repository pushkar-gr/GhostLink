#[derive(Debug, Clone)]
pub struct Config {
    pub client_port: u16,
    pub stun_server: String,
    pub stun_verifier: String,
    pub web_port: u16,
    pub handshake_timeout_secs: u64,
    pub punch_hole_secs: u64,
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
        }
    }
}
