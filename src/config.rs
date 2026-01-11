//! Configuration system for GhostLink.
//!
//! Supports three-tier configuration precedence:
//! 1. Built-in defaults (lowest priority)
//! 2. TOML configuration file (medium priority)
//! 3. Command-line arguments (highest priority)
//!
//! ## Example
//!
//! ```toml
//! # config.toml
//! web_port = 9000
//! encryption_mode = "aes256gcm"
//! ```
//!
//! ```bash
//! # CLI overrides config file
//! ghostlink --config config.toml --web-port 7777
//! ```

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

/// Default configuration file name.
const DEFAULT_CONFIG_FILE: &str = "config.toml";

/// Encryption algorithm for secure P2P communication.
///
/// Supports two AEAD ciphers:
/// - ChaCha20-Poly1305: Fast software implementation, default choice
/// - AES-256-GCM: Hardware-accelerated on most modern CPUs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionMode {
    /// ChaCha20-Poly1305 authenticated encryption.
    ChaCha20Poly1305,
    /// AES-256-GCM authenticated encryption.
    Aes256Gcm,
}

impl FromStr for EncryptionMode {
    type Err = anyhow::Error;

    /// Parses encryption mode from string (case-insensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    /// # use config::EncryptionMode;
    /// let mode = EncryptionMode::from_str("chacha20poly1305").unwrap();
    /// let mode_upper = EncryptionMode::from_str("AES256GCM").unwrap();
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "chacha20poly1305" => Ok(EncryptionMode::ChaCha20Poly1305),
            "aes256gcm" => Ok(EncryptionMode::Aes256Gcm),
            _ => anyhow::bail!(
                "Invalid encryption mode: '{}'. Valid options are 'chacha20poly1305' or 'aes256gcm'",
                s
            ),
        }
    }
}

/// Application configuration.
///
/// All fields have default values and can be overridden via:
/// - TOML configuration file
/// - Command-line arguments
///
/// Partial TOML files are supported; unspecified fields use defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// UDP port for client connections (0 = auto-assign).
    #[serde(default = "default_client_port")]
    pub client_port: u16,

    /// STUN server address for NAT traversal and public IP resolution.
    #[serde(default = "default_stun_server")]
    pub stun_server: String,

    /// STUN verifier address for NAT type detection.
    #[serde(default = "default_stun_verifier")]
    pub stun_verifier: String,

    /// HTTP web server port for the web interface.
    #[serde(default = "default_web_port")]
    pub web_port: u16,

    /// Handshake timeout in seconds.
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,

    /// NAT keep-alive interval in seconds.
    ///
    /// Periodic STUN requests maintain the NAT mapping.
    #[serde(default = "default_punch_hole_secs")]
    pub punch_hole_secs: u64,

    /// Disconnect timeout in milliseconds.
    ///
    /// Grace period before forced shutdown on disconnect.
    #[serde(default = "default_disconnect_timeout_ms")]
    pub disconnect_timeout_ms: u64,

    /// Encryption algorithm for secure communication.
    #[serde(default = "default_encryption_mode")]
    pub encryption_mode: EncryptionMode,
}

// Default value functions for serde deserialization.
// These provide fallback values when fields are missing from TOML files.

/// Default client port: 0 (auto-assign).
fn default_client_port() -> u16 {
    0
}

/// Default STUN server for NAT traversal.
fn default_stun_server() -> String {
    "stun.l.google.com:19302".to_string()
}

/// Default STUN verifier for NAT type detection.
fn default_stun_verifier() -> String {
    "stun4.l.google.com:19302".to_string()
}

/// Default web server port.
fn default_web_port() -> u16 {
    8080
}

/// Default handshake timeout: 30 seconds.
fn default_handshake_timeout_secs() -> u64 {
    30
}

/// Default NAT keep-alive interval: 15 seconds.
fn default_punch_hole_secs() -> u64 {
    15
}

/// Default disconnect timeout: 500 milliseconds.
fn default_disconnect_timeout_ms() -> u64 {
    500
}

/// Default encryption mode: ChaCha20-Poly1305.
fn default_encryption_mode() -> EncryptionMode {
    EncryptionMode::ChaCha20Poly1305
}

/// Command-line arguments parser.
///
/// All arguments are optional; unspecified values use config file or defaults.
#[derive(Parser, Debug)]
#[command(name = "GhostLink")]
#[command(author, version, about = "High-Performance Serverless P2P Messaging", long_about = None)]
pub struct CliArgs {
    /// Path to configuration file
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// UDP port for client connections (0 = auto-assign)
    #[arg(short = 'p', long)]
    pub client_port: Option<u16>,

    /// STUN server address for NAT traversal
    #[arg(short = 's', long)]
    pub stun_server: Option<String>,

    /// STUN verifier address for NAT type detection
    #[arg(short = 'v', long)]
    pub stun_verifier: Option<String>,

    /// HTTP web server port
    #[arg(short = 'w', long)]
    pub web_port: Option<u16>,

    /// Handshake timeout in seconds
    #[arg(short = 't', long)]
    pub handshake_timeout_secs: Option<u64>,

    /// NAT keep-alive interval in seconds
    #[arg(short = 'k', long)]
    pub punch_hole_secs: Option<u64>,

    /// Disconnect timeout in milliseconds
    #[arg(short = 'd', long)]
    pub disconnect_timeout_ms: Option<u64>,

    /// Encryption mode (chacha20poly1305 or aes256gcm)
    #[arg(short = 'e', long)]
    pub encryption_mode: Option<String>,
}

impl Config {
    /// Loads configuration with three-tier precedence.
    ///
    /// Priority (highest to lowest):
    /// 1. Command-line arguments
    /// 2. Configuration file (config.toml or --config path)
    /// 3. Built-in defaults
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use config::Config;
    /// let config = Config::load().unwrap();
    /// println!("Web server port: {}", config.web_port);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Config file exists but cannot be read
    /// - Config file has invalid TOML syntax
    /// - Encryption mode is invalid
    pub fn load() -> Result<Self> {
        let cli_args = CliArgs::parse();

        // Start with built-in defaults
        let mut config = Self::default_config();

        // Layer 2: Load from config file if it exists
        let config_path = cli_args
            .config
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_FILE));

        if config_path.exists() {
            let contents = fs::read_to_string(&config_path)
                .with_context(|| format!("Failed to read config file: {:?}", config_path))?;
            config = toml::from_str(&contents)
                .with_context(|| format!("Failed to parse config file: {:?}", config_path))?;
        }

        // Layer 3: Override with CLI arguments (highest priority)
        if let Some(port) = cli_args.client_port {
            config.client_port = port;
        }
        if let Some(stun) = cli_args.stun_server {
            config.stun_server = stun;
        }
        if let Some(verifier) = cli_args.stun_verifier {
            config.stun_verifier = verifier;
        }
        if let Some(web) = cli_args.web_port {
            config.web_port = web;
        }
        if let Some(timeout) = cli_args.handshake_timeout_secs {
            config.handshake_timeout_secs = timeout;
        }
        if let Some(punch) = cli_args.punch_hole_secs {
            config.punch_hole_secs = punch;
        }
        if let Some(disconnect) = cli_args.disconnect_timeout_ms {
            config.disconnect_timeout_ms = disconnect;
        }
        if let Some(mode_str) = cli_args.encryption_mode {
            config.encryption_mode = mode_str.parse()?;
        }

        Ok(config)
    }

    /// Creates configuration with all default values.
    fn default_config() -> Self {
        Self {
            client_port: default_client_port(),
            stun_server: default_stun_server(),
            stun_verifier: default_stun_verifier(),
            web_port: default_web_port(),
            handshake_timeout_secs: default_handshake_timeout_secs(),
            punch_hole_secs: default_punch_hole_secs(),
            disconnect_timeout_ms: default_disconnect_timeout_ms(),
            encryption_mode: default_encryption_mode(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default_config();
        assert_eq!(config.client_port, 0);
        assert_eq!(config.stun_server, "stun.l.google.com:19302");
        assert_eq!(config.stun_verifier, "stun4.l.google.com:19302");
        assert_eq!(config.web_port, 8080);
        assert_eq!(config.handshake_timeout_secs, 30);
        assert_eq!(config.punch_hole_secs, 15);
        assert_eq!(config.disconnect_timeout_ms, 500);
        assert_eq!(config.encryption_mode, EncryptionMode::ChaCha20Poly1305);
    }

    #[test]
    fn test_toml_deserialization() {
        let toml_str = r#"
            client_port = 3000
            stun_server = "stun.example.com:19302"
            web_port = 9090
            encryption_mode = "aes256gcm"
        "#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.client_port, 3000);
        assert_eq!(config.stun_server, "stun.example.com:19302");
        assert_eq!(config.web_port, 9090);
        assert_eq!(config.encryption_mode, EncryptionMode::Aes256Gcm);
        // Should have defaults for unspecified fields
        assert_eq!(config.stun_verifier, "stun4.l.google.com:19302");
    }

    #[test]
    fn test_encryption_mode_serialization() {
        let config = Config {
            client_port: 0,
            stun_server: "stun.example.com:19302".to_string(),
            stun_verifier: "stun.example.com:19303".to_string(),
            web_port: 8080,
            handshake_timeout_secs: 30,
            punch_hole_secs: 15,
            disconnect_timeout_ms: 500,
            encryption_mode: EncryptionMode::ChaCha20Poly1305,
        };

        let toml_str = toml::to_string(&config).unwrap();
        assert!(toml_str.contains("chacha20poly1305"));

        let config2 = Config {
            encryption_mode: EncryptionMode::Aes256Gcm,
            ..config
        };

        let toml_str2 = toml::to_string(&config2).unwrap();
        assert!(toml_str2.contains("aes256gcm"));
    }

    #[test]
    fn test_encryption_mode_from_str() {
        // Test valid values
        assert_eq!(
            "chacha20poly1305".parse::<EncryptionMode>().unwrap(),
            EncryptionMode::ChaCha20Poly1305
        );
        assert_eq!(
            "ChaCha20Poly1305".parse::<EncryptionMode>().unwrap(),
            EncryptionMode::ChaCha20Poly1305
        );
        assert_eq!(
            "aes256gcm".parse::<EncryptionMode>().unwrap(),
            EncryptionMode::Aes256Gcm
        );
        assert_eq!(
            "AES256GCM".parse::<EncryptionMode>().unwrap(),
            EncryptionMode::Aes256Gcm
        );

        // Test invalid value
        let result = "invalid_mode".parse::<EncryptionMode>();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid encryption mode")
        );
    }

    #[test]
    fn test_partial_toml_uses_defaults() {
        // Test that unspecified fields in TOML use default values
        let toml_str = r#"
            web_port = 9999
        "#;

        let config: Config = toml::from_str(toml_str).unwrap();

        // Specified field should use TOML value
        assert_eq!(config.web_port, 9999);

        // Unspecified fields should use defaults
        assert_eq!(config.client_port, 0);
        assert_eq!(config.stun_server, "stun.l.google.com:19302");
        assert_eq!(config.stun_verifier, "stun4.l.google.com:19302");
        assert_eq!(config.handshake_timeout_secs, 30);
        assert_eq!(config.punch_hole_secs, 15);
        assert_eq!(config.disconnect_timeout_ms, 500);
        assert_eq!(config.encryption_mode, EncryptionMode::ChaCha20Poly1305);
    }
}
