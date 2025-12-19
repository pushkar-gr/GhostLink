#[derive(Debug, Clone)]
pub struct Config {
    pub stun_server: String,
}

impl Config {
    pub fn load() -> Self {
        Self {
            stun_server: "stun.l.google.com:19302".to_string(),
        }
    }
}
