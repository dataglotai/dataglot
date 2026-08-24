//! Envelope encryption for secrets at rest.
//!
//! `CREATE SECRET` values are encrypted here before they reach the meta store,
//! and decrypted here when a catalog resolves a `*_secret` reference. The store
//! only ever holds ciphertext (rule 12); the key lives solely in this process,
//! sourced from an env var.
//!
//! # Construction
//!
//! [`XChaCha20Poly1305`] with a random **192-bit** nonce per encryption — a
//! random nonce is safe at this width (unlike a 96-bit nonce, where random
//! generation risks a birthday collision). The on-disk blob is
//! `nonce (24 bytes) ‖ ciphertext+tag`. Pure-Rust `RustCrypto` AEAD (rule 15 clean).
//!
//! The 256-bit key is a base64 env var (default `DATAGLOT_SECRET_KEY`). No key
//! ⇒ no cipher ⇒ secret DDL is refused with a clear error (wired in the server).

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, Generate, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

/// Env var holding the base64-encoded 256-bit envelope key.
pub const SECRET_KEY_ENV: &str = "DATAGLOT_SECRET_KEY";

/// Length of the XChaCha20-Poly1305 nonce, in bytes (192-bit).
const NONCE_LEN: usize = 24;

/// Something went wrong building the cipher or (de)crypting a secret. `Display`
/// is deliberately terse and value-free (rule 12) — it never echoes plaintext,
/// ciphertext, or the key.
#[derive(Debug, thiserror::Error)]
pub enum SecretCryptoError {
    /// The env var was set but not valid base64.
    #[error("secret key ({env}) is not valid base64")]
    KeyNotBase64 {
        /// The env var consulted.
        env: String,
    },
    /// The decoded key was not exactly 32 bytes.
    #[error("secret key ({env}) must decode to 32 bytes, got {got}")]
    KeyWrongLength {
        /// The env var consulted.
        env: String,
        /// The actual decoded length.
        got: usize,
    },
    /// The env var was set to non-UTF-8 bytes.
    #[error("secret key ({env}) is not valid UTF-8")]
    KeyNotUnicode {
        /// The env var consulted.
        env: String,
    },
    /// Encryption failed (should not happen for well-formed input).
    #[error("secret encryption failed")]
    Encrypt,
    /// The stored blob was too short to contain a nonce.
    #[error("stored secret is malformed")]
    Malformed,
    /// Decryption/authentication failed — wrong key or tampered ciphertext.
    #[error("secret decryption failed (wrong key or corrupt data)")]
    Decrypt,
}

/// An envelope cipher over a 256-bit key. Holds no plaintext; `Debug` is
/// intentionally not derived so the key can't be dumped.
pub struct SecretCipher {
    cipher: XChaCha20Poly1305,
}

impl SecretCipher {
    /// Build a cipher from raw 32-byte key material (e.g. from a KMS, or a
    /// test). [`Self::from_base64_key`] is the env-var path.
    #[must_use]
    pub fn from_key_bytes(key: &[u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(&Key::from(*key)),
        }
    }

    /// Build a cipher from a base64-encoded 32-byte key.
    ///
    /// # Errors
    /// [`SecretCryptoError::KeyNotBase64`] / [`SecretCryptoError::KeyWrongLength`].
    pub fn from_base64_key(env: &str, b64: &str) -> Result<Self, SecretCryptoError> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|_| SecretCryptoError::KeyNotBase64 {
                env: env.to_string(),
            })?;
        let key: [u8; 32] =
            raw.as_slice()
                .try_into()
                .map_err(|_| SecretCryptoError::KeyWrongLength {
                    env: env.to_string(),
                    got: raw.len(),
                })?;
        Ok(Self {
            cipher: XChaCha20Poly1305::new(&Key::from(key)),
        })
    }

    /// Build a cipher from the [`SECRET_KEY_ENV`] env var, or `None` if unset.
    ///
    /// # Errors
    /// A malformed key ([`SecretCryptoError`]); an unset var is `Ok(None)`.
    pub fn from_env() -> Result<Option<Self>, SecretCryptoError> {
        Self::from_env_var(SECRET_KEY_ENV)
    }

    /// [`Self::from_env`] against an arbitrary var name (for tests).
    ///
    /// # Errors
    /// A malformed key ([`SecretCryptoError`]).
    pub fn from_env_var(env: &str) -> Result<Option<Self>, SecretCryptoError> {
        match std::env::var(env) {
            Ok(b64) => Ok(Some(Self::from_base64_key(env, &b64)?)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(SecretCryptoError::KeyNotUnicode {
                env: env.to_string(),
            }),
        }
    }

    /// Encrypt `plaintext` into a `nonce ‖ ciphertext` blob.
    ///
    /// # Errors
    /// [`SecretCryptoError::Encrypt`] (not expected for well-formed input).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretCryptoError> {
        let nonce = XNonce::generate();
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| SecretCryptoError::Encrypt)?;
        let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(nonce.as_slice());
        blob.extend_from_slice(&ciphertext);
        Ok(blob)
    }

    /// Decrypt a `nonce ‖ ciphertext` blob produced by [`Self::encrypt`].
    ///
    /// # Errors
    /// [`SecretCryptoError::Malformed`] if too short, [`SecretCryptoError::Decrypt`]
    /// on a wrong key or tampered data.
    pub fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>, SecretCryptoError> {
        if blob.len() < NONCE_LEN {
            return Err(SecretCryptoError::Malformed);
        }
        let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
        let nonce = XNonce::try_from(nonce).map_err(|_| SecretCryptoError::Malformed)?;
        self.cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| SecretCryptoError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic base64 key (32 bytes of 0x2a) for tests.
    fn test_key_b64() -> String {
        base64::engine::general_purpose::STANDARD.encode([0x2a_u8; 32])
    }

    fn cipher() -> SecretCipher {
        SecretCipher::from_base64_key(SECRET_KEY_ENV, &test_key_b64()).expect("build cipher")
    }

    #[test]
    fn round_trip() {
        let c = cipher();
        let blob = c.encrypt(b"host=db password=hunter2").expect("encrypt");
        assert_eq!(
            c.decrypt(&blob).expect("decrypt"),
            b"host=db password=hunter2"
        );
    }

    #[test]
    fn ciphertext_hides_plaintext_and_is_nondeterministic() {
        let c = cipher();
        let a = c.encrypt(b"super-secret").expect("encrypt");
        let b = c.encrypt(b"super-secret").expect("encrypt");
        // Random nonce ⇒ two encryptions of the same value differ.
        assert_ne!(a, b, "nonce must randomize the ciphertext");
        // The plaintext must not appear in the blob.
        assert!(!a.windows(12).any(|w| w == b"super-secret"));
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let a = cipher();
        let blob = a.encrypt(b"v").expect("encrypt");
        let other_key = base64::engine::general_purpose::STANDARD.encode([0x01_u8; 32]);
        let b = SecretCipher::from_base64_key(SECRET_KEY_ENV, &other_key).expect("build");
        assert!(matches!(b.decrypt(&blob), Err(SecretCryptoError::Decrypt)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let c = cipher();
        let mut blob = c.encrypt(b"v").expect("encrypt");
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(matches!(c.decrypt(&blob), Err(SecretCryptoError::Decrypt)));
    }

    #[test]
    fn short_blob_is_malformed() {
        let c = cipher();
        assert!(matches!(
            c.decrypt(&[0u8; 4]),
            Err(SecretCryptoError::Malformed)
        ));
    }

    #[test]
    fn bad_key_rejected() {
        assert!(matches!(
            SecretCipher::from_base64_key(SECRET_KEY_ENV, "not base64!!!"),
            Err(SecretCryptoError::KeyNotBase64 { .. })
        ));
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(matches!(
            SecretCipher::from_base64_key(SECRET_KEY_ENV, &short),
            Err(SecretCryptoError::KeyWrongLength { got: 16, .. })
        ));
    }
}
