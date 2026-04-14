// rust_core/src/security.rs
//! HMAC-SHA256 ticket auth, anti-replay, and ECDSA-P256 manifest verification.

use crate::config::Config;
use crate::error::AetherError;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ring::signature::{self, UnparsedPublicKey};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::error;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── SecureKey ─────────────────────────────────────────────────────────────────

/// A shared secret that is zeroed from RAM on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureKey(pub Vec<u8>);

type HmacSha256 = Hmac<Sha256>;

// ── SecurityManager ───────────────────────────────────────────────────────────

pub struct SecurityManager;

impl SecurityManager {
    // ── Ticket verification ───────────────────────────────────────────────────

    /// Verify an HMAC-SHA256 ticket and its timestamp window.
    ///
    /// Ticket format: `<model_id>|<version>|<unix_timestamp>.<base64-HMAC>`
    pub fn verify_ticket(ticket: &str, secret: &SecureKey) -> Result<(), AetherError> {
        let (payload, signature_b64) = ticket.rsplit_once('.').ok_or(AetherError::InvalidTicket)?;
        if payload.is_empty() || signature_b64.is_empty() {
            return Err(AetherError::InvalidTicket);
        }
        let signature = BASE64
            .decode(signature_b64)
            .map_err(|_| AetherError::InvalidTicket)?;

        // Constant-time HMAC comparison (prevents timing side-channel).
        let mut mac = HmacSha256::new_from_slice(&secret.0)
            .map_err(|_| AetherError::InternalError("HMAC init failed".into()))?;
        mac.update(payload.as_bytes());
        mac.verify_slice(&signature).map_err(|_| {
            error!("HMAC mismatch for payload: {}", payload);
            AetherError::SecurityError("Invalid signature".into())
        })?;

        // Timestamp window (anti-replay).
        let fields: Vec<&str> = payload.split('|').collect();
        if fields.len() < 3 {
            return Err(AetherError::InvalidTicket);
        }
        let ts: u64 = fields[2].parse().map_err(|_| AetherError::InvalidTicket)?;
        let now = Self::now_secs();
        let w = Config::TICKET_WINDOW_SECS;
        if now > ts + w || now < ts.saturating_sub(w) {
            return Err(AetherError::SecurityError("Ticket expired".into()));
        }

        Ok(())
    }

    /// Generate a signed ticket for outbound requests.
    pub fn generate_ticket(
        model_id: &str,
        version: &str,
        issuer_peer_id: &str,
        secret: &SecureKey,
    ) -> Result<String, AetherError> {
        let payload = format!(
            "{}|{}|{}|{}",
            model_id,
            version,
            Self::now_secs(),
            issuer_peer_id
        );
        let mut mac = HmacSha256::new_from_slice(&secret.0)
            .map_err(|_| AetherError::InternalError("HMAC init failed".into()))?;
        mac.update(payload.as_bytes());
        let sig = BASE64.encode(mac.finalize().into_bytes());
        Ok(format!("{}.{}", payload, sig))
    }

    // ── Manifest ECDSA verification ───────────────────────────────────────────

    /// Verify that a manifest's ECDSA-P256-SHA256 signature is valid.
    ///
    /// # Arguments
    /// * `canonical_json`  – The canonical (sorted-keys, no extra whitespace) JSON payload string.
    /// * `sig_hex`         – Hex-encoded DER ECDSA signature produced by `forge.py`.
    /// * `public_key_der`  – DER-encoded X.509 SubjectPublicKeyInfo EC public key
    ///   (the `app_public.pem` content, decoded from PEM).
    pub fn verify_manifest(
        canonical_json: &str,
        sig_hex: &str,
        public_key_der: &[u8],
    ) -> Result<(), AetherError> {
        let sig_bytes =
            hex::decode(sig_hex).map_err(|_| AetherError::SignatureVerificationFailed)?;

        let peer_public_key =
            UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key_der);

        peer_public_key
            .verify(canonical_json.as_bytes(), &sig_bytes)
            .map_err(|_| {
                error!("Manifest ECDSA signature invalid");
                AetherError::SignatureVerificationFailed
            })
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Current Unix timestamp in seconds.
    ///
    /// Uses `unwrap_or(Duration::ZERO)` instead of `unwrap()` so a device with
    /// a clock set before the Unix epoch (rooted device, firmware bug) returns 0
    /// rather than panicking inside ticket verification.
    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }

    /// Derive a 32-byte HMAC key from a raw ECDH shared secret using HKDF-SHA256.
    ///
    /// Raw ECDH output is not uniformly random (it is the x-coordinate of an
    /// EC point) and should not be used directly as a symmetric key. HKDF
    /// extracts entropy and expands it to a full-length key with a domain-
    /// separation label, preventing key-reuse issues if the same ECDH output
    /// is ever used for multiple purposes.
    ///
    /// Context label `b"aether-hmac-v1"` ensures keys derived for different
    /// purposes are independent even if the IKM (input key material) is reused.
    pub fn derive_hmac_key(raw_ecdh_secret: &[u8]) -> Result<[u8; 32], AetherError> {
        Self::derive_labeled_key(raw_ecdh_secret, b"aether-hmac-v1")
    }

    pub fn derive_transport_key(raw_ecdh_secret: &[u8]) -> Result<[u8; 32], AetherError> {
        Self::derive_labeled_key(raw_ecdh_secret, b"aether-transport-v1")
    }

    pub fn derive_session_stream_key(
        transport_key: &SecureKey,
        ticket: &str,
    ) -> Result<[u8; 32], AetherError> {
        let hk = Hkdf::<Sha256>::new(Some(ticket.as_bytes()), &transport_key.0);
        let mut output = [0u8; 32];
        hk.expand(b"aether-stream-session-v1", &mut output)
            .map_err(|_| AetherError::InternalError("HKDF stream expand failed".into()))?;
        Ok(output)
    }

    pub fn derive_session_nonce(ticket: &str) -> [u8; 12] {
        let mut hasher = Sha256::new();
        hasher.update(b"aether-stream-nonce-v1");
        hasher.update(ticket.as_bytes());
        let digest = hasher.finalize();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&digest[..12]);
        nonce
    }

    fn derive_labeled_key(raw_ecdh_secret: &[u8], label: &[u8]) -> Result<[u8; 32], AetherError> {
        let hk = Hkdf::<Sha256>::new(None, raw_ecdh_secret);
        let mut output = [0u8; 32];
        hk.expand(label, &mut output)
            .map_err(|_| AetherError::InternalError("HKDF expand failed".into()))?;
        Ok(output)
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(bytes: &[u8]) -> SecureKey {
        SecureKey(bytes.to_vec())
    }

    #[test]
    fn ticket_roundtrip() {
        let secret = make_key(&[0xAB; 32]);
        let ticket =
            SecurityManager::generate_ticket("model-x", "1.0", "peer-seeder", &secret).unwrap();
        assert!(SecurityManager::verify_ticket(&ticket, &secret).is_ok());
    }

    #[test]
    fn ticket_wrong_key_fails() {
        let secret1 = make_key(&[0xAB; 32]);
        let secret2 = make_key(&[0xCD; 32]);
        let ticket =
            SecurityManager::generate_ticket("model-x", "1.0", "peer-seeder", &secret1).unwrap();
        assert!(SecurityManager::verify_ticket(&ticket, &secret2).is_err());
    }

    #[test]
    fn ticket_tampered_payload_fails() {
        let secret = make_key(&[0xAB; 32]);
        let ticket =
            SecurityManager::generate_ticket("model-x", "1.0", "peer-seeder", &secret).unwrap();
        // Corrupt the payload portion
        let bad_ticket = ticket.replace("model-x", "evil-model");
        assert!(SecurityManager::verify_ticket(&bad_ticket, &secret).is_err());
    }

    #[test]
    fn ticket_malformed_rejected() {
        let secret = make_key(&[0xAB; 32]);
        assert!(SecurityManager::verify_ticket("nodot", &secret).is_err());
        assert!(SecurityManager::verify_ticket("", &secret).is_err());
    }

    #[test]
    fn now_secs_returns_reasonable_timestamp() {
        // generate_ticket uses now_secs internally; if it panics, the test fails.
        let secret = make_key(&[0xAB; 32]);
        let ticket = SecurityManager::generate_ticket("m", "1", "peer-seeder", &secret).unwrap();
        let parts: Vec<&str> = ticket.splitn(2, '.').collect();
        let fields: Vec<&str> = parts[0].split('|').collect();
        let ts: u64 = fields[2].parse().expect("Timestamp must parse as u64");
        // Sanity check: timestamp is after 2020-01-01 (1577836800) and before 2100
        assert!(ts > 1_577_836_800, "Timestamp too small: {ts}");
        assert!(ts < 4_102_444_800, "Timestamp too large: {ts}");
    }

    #[test]
    fn derive_hmac_key_all_zeros_input_not_trivial() {
        // Even with a weak ECDH input (all zeros), HKDF must produce a non-zero key
        let raw = vec![0u8; 32];
        let derived = SecurityManager::derive_hmac_key(&raw).unwrap();
        assert_ne!(derived, [0u8; 32], "HKDF of zero input must not be zero");
    }

    #[test]
    fn derive_hmac_key_output_is_32_bytes() {
        let raw = vec![0xFFu8; 32];
        let derived = SecurityManager::derive_hmac_key(&raw).unwrap();
        assert_eq!(derived.len(), 32);
    }

    #[test]
    fn derive_transport_key_output_is_32_bytes() {
        let raw = vec![0x44u8; 32];
        let derived = SecurityManager::derive_transport_key(&raw).unwrap();
        assert_eq!(derived.len(), 32);
    }
}
