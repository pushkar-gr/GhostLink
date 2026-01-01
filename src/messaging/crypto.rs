//! Cryptographic primitives for GhostLink v1.1.
//!
//! Handles X25519 key exchange, HKDF key derivation, and
//! AEAD encryption/decryption (ChaCha20-Poly1305 / AES-256-GCM).

use crate::config::EncryptionMode;
use aes_gcm::{
    Aes256Gcm, Nonce as AesNonce,
    aead::{Aead, KeyInit},
};
use anyhow::Result;
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use std::fmt;
use x25519_dalek::{PublicKey, StaticSecret};

/// Represents an X25519 key pair used for Diffie-Hellman key exchange.
pub struct KeyPair {
    pub private: StaticSecret,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let private = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&private);
        Self { private, public }
    }
}

/// Enum representing the supported authenticated encryption algorithms.
pub enum CipherAlgo {
    ChaCha20(ChaCha20Poly1305),
    Aes256(Box<Aes256Gcm>),
}

impl fmt::Debug for CipherAlgo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChaCha20(_) => write!(f, "CipherAlgo::ChaCha20(opaque)"),
            Self::Aes256(_) => write!(f, "CipherAlgo::Aes256(opaque)"),
        }
    }
}

impl CipherAlgo {
    /// Encrypts the provided plaintext using the session's cipher.
    ///
    /// The nonce is constructed from the provided counter value to ensure uniqueness
    /// for every packet in the stream.
    ///
    /// # Arguments
    ///
    /// * `nonce_val` - A strictly increasing counter (sequence number).
    /// * `plaintext` - The raw data to encrypt.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The authenticated ciphertext (including tag).
    /// * `Err` - If the encryption operation fails.
    pub fn encrypt(&self, nonce_val: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        match self {
            CipherAlgo::ChaCha20(cipher) => {
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[4..].copy_from_slice(&nonce_val.to_be_bytes());
                let nonce = ChaChaNonce::from_slice(&nonce_bytes);
                cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|_| anyhow::anyhow!("Encryption failure"))
            }
            CipherAlgo::Aes256(cipher) => {
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[4..].copy_from_slice(&nonce_val.to_be_bytes());
                let nonce = AesNonce::from_slice(&nonce_bytes);
                cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|_| anyhow::anyhow!("Encryption failure"))
            }
        }
    }

    /// Decrypts the ciphertext using the session's cipher.
    ///
    /// # Arguments
    ///
    /// * `nonce_val` - The sequence number expected for this packet.
    /// * `ciphertext` - The encrypted data to authenticate and decrypt.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The decrypted plaintext.
    /// * `Err` - If the authentication tag is invalid or decryption fails.
    pub fn decrypt(&self, nonce_val: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
        match self {
            CipherAlgo::ChaCha20(cipher) => {
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[4..].copy_from_slice(&nonce_val.to_be_bytes());
                let nonce = ChaChaNonce::from_slice(&nonce_bytes);
                cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|_| anyhow::anyhow!("Decryption failure"))
            }
            CipherAlgo::Aes256(cipher) => {
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[4..].copy_from_slice(&nonce_val.to_be_bytes());
                let nonce = AesNonce::from_slice(&nonce_bytes);
                cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|_| anyhow::anyhow!("Decryption failure"))
            }
        }
    }
}

/// Holds all cryptographic state derived for a secure session.
#[derive(Debug)]
pub struct SessionData {
    pub cipher: CipherAlgo,
    pub fingerprint: String,
}

/// Derives session keys and authentication data from a secure key exchange.
///
/// This function performs the ECDH calculation using the local private key and
/// the remote peer's public key. It then uses HKDF to derive the symmetric
/// encryption keys and generates a SAS fingerprint for manual verification.
///
/// # Arguments
///
/// * `private_key` - The local ephemeral private key.
/// * `peer_public_bytes` - The remote peer's public key (raw bytes).
/// * `mode` - The negotiated encryption algorithm to initialize.
/// * `my_public_bytes` - The local public key (raw bytes) used for fingerprinting.
///
/// # Returns
///
/// * `Ok(SessionData)` - The initialized cipher and authentication fingerprint.
/// * `Err` - If key expansion or cipher initialization fails.
pub fn derive_session(
    private_key: StaticSecret,
    peer_public_bytes: [u8; 32],
    mode: EncryptionMode,
    my_public_bytes: [u8; 32],
) -> Result<SessionData> {
    let peer_public = PublicKey::from(peer_public_bytes);
    let shared_secret = private_key.diffie_hellman(&peer_public);

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut key_material = [0u8; 32];
    hkdf.expand(b"ghostlink_v1_session", &mut key_material)
        .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;

    let cipher = match mode {
        EncryptionMode::ChaCha20Poly1305 => {
            CipherAlgo::ChaCha20(ChaCha20Poly1305::new_from_slice(&key_material)?)
        }
        EncryptionMode::Aes256Gcm => {
            CipherAlgo::Aes256(Box::new(Aes256Gcm::new_from_slice(&key_material)?))
        }
    };

    let mut keys = [my_public_bytes, peer_public_bytes];
    keys.sort();

    let mut hasher = Sha256::new();
    use sha2::Digest;
    hasher.update(b"ghostlink_fingerprint");
    hasher.update(keys[0]);
    hasher.update(keys[1]);
    let hash = hasher.finalize();

    let fingerprint = format!("{:02X} {:02X} {:02X}", hash[0], hash[1], hash[2]);

    Ok(SessionData {
        cipher,
        fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keys = KeyPair::generate();
        assert_eq!(keys.public.to_bytes().len(), 32);
    }

    #[test]
    fn test_ecdh_shared_secret() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let alice_shared = alice.private.diffie_hellman(&bob.public);
        let bob_shared = bob.private.diffie_hellman(&alice.public);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_session_derivation_match() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let alice_pub = alice.public.to_bytes();
        let bob_pub = bob.public.to_bytes();

        let alice_session = derive_session(
            alice.private,
            bob_pub,
            EncryptionMode::ChaCha20Poly1305,
            alice_pub,
        )
        .unwrap();
        let bob_session = derive_session(
            bob.private,
            alice_pub,
            EncryptionMode::ChaCha20Poly1305,
            bob_pub,
        )
        .unwrap();

        assert_eq!(alice_session.fingerprint, bob_session.fingerprint);
    }

    #[test]
    fn test_chacha20_roundtrip() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let session = derive_session(
            alice.private,
            bob.public.to_bytes(),
            EncryptionMode::ChaCha20Poly1305,
            alice.public.to_bytes(),
        )
        .unwrap();

        let nonce = 12345u64;
        let plaintext = b"Hello GhostLink";

        let encrypted = session.cipher.encrypt(nonce, plaintext).unwrap();
        assert_ne!(encrypted, plaintext);

        let decrypted = session.cipher.decrypt(nonce, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
