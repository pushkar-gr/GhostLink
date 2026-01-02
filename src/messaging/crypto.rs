//! Cryptographic primitives for GhostLink.
//!
//! Provides X25519 key exchange, HKDF key derivation, and
//! AEAD encryption/decryption (ChaCha20-Poly1305 / AES-256-GCM).

use super::super::config::EncryptionMode;
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

/// X25519 key pair for Diffie-Hellman key exchange.
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

/// Supported authenticated encryption algorithms.
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
    /// Encrypts plaintext using session cipher.
    ///
    /// Nonce is constructed from counter value to ensure uniqueness
    /// for every packet in the stream.
    ///
    /// # Arguments
    ///
    /// * `nonce_val` - Strictly increasing counter (sequence number).
    /// * `plaintext` - Raw data to encrypt.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Authenticated ciphertext (including tag).
    /// * `Err` - Encryption operation failed.
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

    #[test]
    fn test_aes256_roundtrip() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let session = derive_session(
            alice.private,
            bob.public.to_bytes(),
            EncryptionMode::Aes256Gcm,
            alice.public.to_bytes(),
        )
        .unwrap();

        let nonce = 98765u64;
        let plaintext = b"Testing AES-256-GCM encryption";

        let encrypted = session.cipher.encrypt(nonce, plaintext).unwrap();
        assert_ne!(encrypted, plaintext);

        let decrypted = session.cipher.decrypt(nonce, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encryption_with_different_nonces() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let session = derive_session(
            alice.private,
            bob.public.to_bytes(),
            EncryptionMode::ChaCha20Poly1305,
            alice.public.to_bytes(),
        )
        .unwrap();

        let plaintext = b"Same message";
        let nonce1 = 1u64;
        let nonce2 = 2u64;

        let encrypted1 = session.cipher.encrypt(nonce1, plaintext).unwrap();
        let encrypted2 = session.cipher.encrypt(nonce2, plaintext).unwrap();

        // Same plaintext with different nonces should produce different ciphertexts
        assert_ne!(encrypted1, encrypted2);

        // Both should decrypt correctly
        let decrypted1 = session.cipher.decrypt(nonce1, &encrypted1).unwrap();
        let decrypted2 = session.cipher.decrypt(nonce2, &encrypted2).unwrap();
        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }

    #[test]
    fn test_decryption_with_wrong_nonce_fails() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let session = derive_session(
            alice.private,
            bob.public.to_bytes(),
            EncryptionMode::ChaCha20Poly1305,
            alice.public.to_bytes(),
        )
        .unwrap();

        let plaintext = b"Secret message";
        let nonce_encrypt = 100u64;
        let nonce_decrypt = 200u64;

        let encrypted = session.cipher.encrypt(nonce_encrypt, plaintext).unwrap();

        // Decrypting with wrong nonce should fail
        let result = session.cipher.decrypt(nonce_decrypt, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let session = derive_session(
            alice.private,
            bob.public.to_bytes(),
            EncryptionMode::ChaCha20Poly1305,
            alice.public.to_bytes(),
        )
        .unwrap();

        let plaintext = b"Important data";
        let nonce = 42u64;

        let mut encrypted = session.cipher.encrypt(nonce, plaintext).unwrap();

        // Tamper with ciphertext
        if !encrypted.is_empty() {
            encrypted[0] ^= 0xFF;
        }

        // Decryption should fail due to authentication tag mismatch
        let result = session.cipher.decrypt(nonce, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_large_message_encryption() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let session = derive_session(
            alice.private,
            bob.public.to_bytes(),
            EncryptionMode::ChaCha20Poly1305,
            alice.public.to_bytes(),
        )
        .unwrap();

        // Test with larger message (1KB)
        let plaintext = vec![0x42u8; 1024];
        let nonce = 999u64;

        let encrypted = session.cipher.encrypt(nonce, &plaintext).unwrap();
        let decrypted = session.cipher.decrypt(nonce, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_empty_message_encryption() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let session = derive_session(
            alice.private,
            bob.public.to_bytes(),
            EncryptionMode::ChaCha20Poly1305,
            alice.public.to_bytes(),
        )
        .unwrap();

        let plaintext = b"";
        let nonce = 1u64;

        let encrypted = session.cipher.encrypt(nonce, plaintext).unwrap();
        let decrypted = session.cipher.decrypt(nonce, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_fingerprint_generation() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let session = derive_session(
            alice.private,
            bob.public.to_bytes(),
            EncryptionMode::ChaCha20Poly1305,
            alice.public.to_bytes(),
        )
        .unwrap();

        // Fingerprint should be in format "XX XX XX" (8 chars with spaces)
        assert_eq!(session.fingerprint.len(), 8);

        // Should match pattern of two hex digits, space, two hex digits, space, two hex digits
        let parts: Vec<&str> = session.fingerprint.split(' ').collect();
        assert_eq!(parts.len(), 3);
        for part in parts {
            assert_eq!(part.len(), 2);
            assert!(part.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn test_same_keypair_same_mode_same_fingerprint() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let session1 = derive_session(
            alice.private.clone(),
            bob.public.to_bytes(),
            EncryptionMode::ChaCha20Poly1305,
            alice.public.to_bytes(),
        )
        .unwrap();

        let session2 = derive_session(
            alice.private,
            bob.public.to_bytes(),
            EncryptionMode::ChaCha20Poly1305,
            alice.public.to_bytes(),
        )
        .unwrap();

        // Same keys and mode should produce same fingerprint
        assert_eq!(session1.fingerprint, session2.fingerprint);
    }
}
