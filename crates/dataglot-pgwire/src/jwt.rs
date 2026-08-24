//! JWT verification for the `jwt` connection-auth mode.
//!
//! In `jwt` auth mode a client presents a **signed JWT as its password**.
//! [`JwtVerifier::verify`] is the security-critical primitive: it verifies
//! the token's **signature** against a configured key, checks the temporal
//! claims (`exp`, and `nbf`/`iat` when present), and — when configured —
//! the `iss` / `aud` claims, all **before** any claim is trusted. Only on a
//! fully-verified token does it extract the directory-group membership from
//! the configured `groups` claim.
//!
//! # Fail-closed
//!
//! Any verification failure — bad signature, expired/not-yet-valid,
//! wrong issuer/audience, malformed token — returns
//! [`JwtError::Verification`]. The caller (the pgwire startup handler)
//! maps that to a rejected connection. An unverified token is **never**
//! trusted for either authentication or group membership.
//!
//! # Credential isolation (hard rule 12)
//!
//! The token, its signature, and the signing key are secrets. They never
//! appear in a [`JwtError`]'s `Display` / `Debug` (the error is value-free
//! — "jwt verification failed", not the token), are never logged here, and
//! the [`JwtVerifier`]'s own `Debug` renders no key material.

use std::fmt;

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde_json::Value;

/// Signing algorithm the verifier is configured to accept. A token whose
/// header names a different algorithm is rejected — the classic JWT
/// "alg confusion" attack (e.g. an RS256 verifier tricked into treating an
/// attacker-chosen HMAC key) cannot happen because [`Validation`] pins the
/// accepted algorithm to exactly this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtAlgorithm {
    /// HMAC-SHA256 with a shared secret.
    Hs256,
    /// RSA PKCS#1 v1.5 SHA-256 with a PEM-encoded public key.
    Rs256,
    /// ECDSA P-256 SHA-256 with a PEM-encoded public key.
    Es256,
}

impl JwtAlgorithm {
    fn to_jsonwebtoken(self) -> Algorithm {
        match self {
            JwtAlgorithm::Hs256 => Algorithm::HS256,
            JwtAlgorithm::Rs256 => Algorithm::RS256,
            JwtAlgorithm::Es256 => Algorithm::ES256,
        }
    }
}

/// Error verifying a presented JWT. **Value-free** (hard rule 12): a
/// variant never carries the token, signature, key, or any claim value —
/// only the *kind* of failure, so it is safe to log / surface.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    /// The configured signing key could not be parsed (bad PEM, wrong key
    /// type for the algorithm). Raised at construction, so a misconfigured
    /// deployment fails fast at boot rather than per connection.
    #[error("jwt: invalid signing key configuration")]
    Key,
    /// The token failed verification: bad signature, expired / not-yet-valid,
    /// wrong issuer / audience, or malformed. Deliberately opaque — the
    /// underlying reason (and the token) is never surfaced.
    #[error("jwt verification failed")]
    Verification,
}

/// A verified JWT's extracted membership. Produced only after the token's
/// signature and temporal / issuer / audience claims have all passed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerifiedJwt {
    /// The directory groups named by the configured `groups` claim. Empty
    /// when the claim is absent or not an array of strings — the caller
    /// treats that as "authenticated, no memberships".
    pub groups: Vec<String>,
}

/// Verifies client-presented JWTs against a configured key and claim policy.
///
/// Cheap to share behind an `Arc` across connections — `verify` takes
/// `&self` and allocates only the extracted group vector.
pub struct JwtVerifier {
    key: DecodingKey,
    validation: Validation,
    groups_claim: String,
}

impl fmt::Debug for JwtVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the decoding key or the validation's configured
        // secrets (rule 12). The claim name is not a secret.
        f.debug_struct("JwtVerifier")
            .field("groups_claim", &self.groups_claim)
            .finish_non_exhaustive()
    }
}

impl JwtVerifier {
    /// Build a verifier.
    ///
    /// - `algorithm` pins the single accepted signing algorithm.
    /// - `key_material` is the HMAC **shared secret** bytes for
    ///   [`JwtAlgorithm::Hs256`], or the **PEM-encoded public key** bytes for
    ///   RS256 / ES256.
    /// - `groups_claim` names the claim carrying the group array (e.g.
    ///   `"groups"`).
    /// - `issuer` / `audience`, when `Some`, are additionally required to
    ///   match exactly. When `None`, that claim is not validated.
    /// - `leeway_secs` tolerates that much clock skew on `exp` / `nbf`.
    ///
    /// # Errors
    /// [`JwtError::Key`] if the PEM key material fails to parse.
    pub fn new(
        algorithm: JwtAlgorithm,
        key_material: &[u8],
        groups_claim: impl Into<String>,
        issuer: Option<String>,
        audience: Option<String>,
        leeway_secs: u64,
    ) -> Result<Self, JwtError> {
        let key = match algorithm {
            JwtAlgorithm::Hs256 => DecodingKey::from_secret(key_material),
            JwtAlgorithm::Rs256 => {
                DecodingKey::from_rsa_pem(key_material).map_err(|_| JwtError::Key)?
            }
            JwtAlgorithm::Es256 => {
                DecodingKey::from_ec_pem(key_material).map_err(|_| JwtError::Key)?
            }
        };

        let mut validation = Validation::new(algorithm.to_jsonwebtoken());
        validation.leeway = leeway_secs;
        // Always enforce expiry, and reject not-yet-valid tokens when they
        // carry an `nbf`. `exp` is required (a token with no expiry is
        // rejected) — a governance engine must not honour a non-expiring
        // credential.
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_required_spec_claims(&["exp"]);
        if let Some(iss) = issuer {
            validation.set_issuer(&[iss]);
        }
        match audience {
            Some(aud) => validation.set_audience(&[aud]),
            // Without a configured audience, do not reject tokens that happen
            // to carry an `aud` claim (jsonwebtoken validates `aud` by
            // default). Issuer/expiry still apply.
            None => validation.validate_aud = false,
        }

        Ok(Self {
            key,
            validation,
            groups_claim: groups_claim.into(),
        })
    }

    /// Verify `token` end-to-end and extract its group membership.
    ///
    /// Returns [`VerifiedJwt`] **only** when the signature and every
    /// configured claim check pass. Any failure yields
    /// [`JwtError::Verification`] with no detail (rule 12).
    ///
    /// # Errors
    /// [`JwtError::Verification`] on any signature / claim / format failure.
    pub fn verify(&self, token: &str) -> Result<VerifiedJwt, JwtError> {
        // `decode` verifies the signature with `self.key` AND applies
        // `self.validation` (algorithm pin, exp, nbf, iss, aud) in one shot.
        // The error is discarded so nothing about the token leaks (rule 12).
        let data = decode::<Value>(token, &self.key, &self.validation)
            .map_err(|_| JwtError::Verification)?;
        Ok(VerifiedJwt {
            groups: extract_groups(&data.claims, &self.groups_claim),
        })
    }
}

/// Extract a `Vec<String>` from `claims[claim]` when it is a JSON array of
/// strings. Any other shape (absent, null, scalar, non-string elements)
/// yields an empty vector — "authenticated, no memberships". Non-string
/// array elements are skipped rather than failing the whole login.
fn extract_groups(claims: &Value, claim: &str) -> Vec<String> {
    match claims.get(claim) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    const SECRET: &[u8] = b"test-shared-secret-value";

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Sign an HS256 token with the given claims JSON.
    fn sign_hs256(claims: &Value) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            claims,
            &EncodingKey::from_secret(SECRET),
        )
        .expect("sign token")
    }

    fn hs256_verifier(iss: Option<&str>, aud: Option<&str>) -> JwtVerifier {
        JwtVerifier::new(
            JwtAlgorithm::Hs256,
            SECRET,
            "groups",
            iss.map(str::to_string),
            aud.map(str::to_string),
            60,
        )
        .expect("build verifier")
    }

    #[test]
    fn valid_token_extracts_groups() {
        let token = sign_hs256(&json!({
            "sub": "alice",
            "exp": now() + 3600,
            "groups": ["QC-Finance", "QC-Ops"],
        }));
        let verified = hs256_verifier(None, None).verify(&token).expect("verifies");
        assert_eq!(verified.groups, vec!["QC-Finance", "QC-Ops"]);
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let token = sign_hs256(&json!({ "sub": "alice", "exp": now() + 3600 }));
        // Flip the last character of the signature segment.
        let mut parts: Vec<&str> = token.split('.').collect();
        let sig = parts[2].to_string();
        let last = sig.chars().last().unwrap();
        let swapped = if last == 'A' { 'B' } else { 'A' };
        let tampered_sig = format!("{}{}", &sig[..sig.len() - 1], swapped);
        parts[2] = &tampered_sig;
        let tampered = parts.join(".");

        let err = hs256_verifier(None, None)
            .verify(&tampered)
            .expect_err("tampered signature must be rejected");
        assert!(matches!(err, JwtError::Verification));
    }

    #[test]
    fn wrong_key_is_rejected() {
        // A token signed with a different secret must not verify — the
        // signature is the authentication.
        let token = encode(
            &Header::new(Algorithm::HS256),
            &json!({ "sub": "mallory", "exp": now() + 3600, "groups": ["admin"] }),
            &EncodingKey::from_secret(b"attacker-secret"),
        )
        .unwrap();
        let err = hs256_verifier(None, None)
            .verify(&token)
            .expect_err("wrong-key token must be rejected");
        assert!(matches!(err, JwtError::Verification));
    }

    #[test]
    fn expired_token_is_rejected() {
        // exp well in the past, beyond the 60s leeway.
        let token = sign_hs256(&json!({ "sub": "alice", "exp": now() - 3600 }));
        let err = hs256_verifier(None, None)
            .verify(&token)
            .expect_err("expired token must be rejected");
        assert!(matches!(err, JwtError::Verification));
    }

    #[test]
    fn not_yet_valid_token_is_rejected() {
        let token = sign_hs256(&json!({
            "sub": "alice",
            "exp": now() + 7200,
            "nbf": now() + 3600, // not valid for another hour
        }));
        let err = hs256_verifier(None, None)
            .verify(&token)
            .expect_err("nbf-in-future token must be rejected");
        assert!(matches!(err, JwtError::Verification));
    }

    #[test]
    fn missing_exp_is_rejected() {
        // No exp at all — a non-expiring credential must not be honoured.
        let token = sign_hs256(&json!({ "sub": "alice", "groups": ["x"] }));
        let err = hs256_verifier(None, None)
            .verify(&token)
            .expect_err("token without exp must be rejected");
        assert!(matches!(err, JwtError::Verification));
    }

    #[test]
    fn correct_issuer_and_audience_verify() {
        let token = sign_hs256(&json!({
            "sub": "alice",
            "exp": now() + 3600,
            "iss": "https://idp.example",
            "aud": "dataglot",
            "groups": ["QC-Finance"],
        }));
        let verified = hs256_verifier(Some("https://idp.example"), Some("dataglot"))
            .verify(&token)
            .expect("matching iss+aud verifies");
        assert_eq!(verified.groups, vec!["QC-Finance"]);
    }

    #[test]
    fn wrong_issuer_is_rejected() {
        let token = sign_hs256(&json!({
            "sub": "alice",
            "exp": now() + 3600,
            "iss": "https://evil.example",
            "aud": "dataglot",
        }));
        let err = hs256_verifier(Some("https://idp.example"), Some("dataglot"))
            .verify(&token)
            .expect_err("wrong issuer must be rejected");
        assert!(matches!(err, JwtError::Verification));
    }

    #[test]
    fn wrong_audience_is_rejected() {
        let token = sign_hs256(&json!({
            "sub": "alice",
            "exp": now() + 3600,
            "iss": "https://idp.example",
            "aud": "some-other-service",
        }));
        let err = hs256_verifier(Some("https://idp.example"), Some("dataglot"))
            .verify(&token)
            .expect_err("wrong audience must be rejected");
        assert!(matches!(err, JwtError::Verification));
    }

    #[test]
    fn missing_groups_claim_yields_empty() {
        // Authenticated, but no groups claim → empty (caller = NoGroups).
        let token = sign_hs256(&json!({ "sub": "alice", "exp": now() + 3600 }));
        let verified = hs256_verifier(None, None).verify(&token).expect("verifies");
        assert!(verified.groups.is_empty());
    }

    #[test]
    fn non_array_groups_claim_yields_empty() {
        let token = sign_hs256(&json!({
            "sub": "alice",
            "exp": now() + 3600,
            "groups": "QC-Finance", // a scalar, not an array
        }));
        let verified = hs256_verifier(None, None).verify(&token).expect("verifies");
        assert!(verified.groups.is_empty());
    }

    #[test]
    fn algorithm_confusion_is_rejected() {
        // A verifier configured for RS256 must reject an HS256-signed token
        // (alg pinned by Validation) — no downgrade to a symmetric key.
        // Build an RS256 verifier from a throwaway public key is heavy;
        // instead assert the reverse is impossible: an HS256 verifier rejects
        // a token whose header claims a different algorithm.
        let token = encode(
            &Header::new(Algorithm::HS384),
            &json!({ "sub": "alice", "exp": now() + 3600 }),
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap();
        let err = hs256_verifier(None, None)
            .verify(&token)
            .expect_err("HS384 token must be rejected by an HS256 verifier");
        assert!(matches!(err, JwtError::Verification));
    }

    #[test]
    fn malformed_token_is_rejected() {
        let err = hs256_verifier(None, None)
            .verify("not-a-jwt")
            .expect_err("garbage must be rejected");
        assert!(matches!(err, JwtError::Verification));
    }

    #[test]
    fn error_and_verifier_debug_are_value_free() {
        // rule 12: neither the error nor the verifier's Debug may leak the
        // token or the key.
        let token = sign_hs256(&json!({ "sub": "alice", "exp": now() - 3600 }));
        let err = hs256_verifier(None, None).verify(&token).unwrap_err();
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains(&token), "error must not contain the token");
        assert!(shown.contains("verification failed"));

        let verifier = hs256_verifier(None, None);
        let dbg = format!("{verifier:?}");
        assert!(
            !dbg.contains("test-shared-secret"),
            "must not render the key"
        );
        assert!(dbg.contains("groups_claim"));
    }
}
