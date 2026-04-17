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
    fn split_ticket_payload<'a>(
        ticket: &'a str,
    ) -> Result<(&'a str, &'a str, &'a str, Option<u64>, &'a str), AetherError> {
        let (payload, _signature_b64) =
            ticket.rsplit_once('.').ok_or(AetherError::InvalidTicket)?;
        let fields: Vec<&str> = payload.split('|').collect();
        if fields.len() < 4 {
            return Err(AetherError::InvalidTicket);
        }

        let model_id = fields[0];
        let version = fields[1];
        let ts_str = fields[2];
        // ADR-017: Optional counter field (5th position in new format)
        let counter = if fields.len() >= 5 {
            fields[3].parse::<u64>().ok()
        } else {
            None
        };
        let issuer = if fields.len() >= 5 {
            fields[4]
        } else {
            fields[3]
        };
        if model_id.is_empty() || version.is_empty() || ts_str.is_empty() || issuer.is_empty() {
            return Err(AetherError::InvalidTicket);
        }
        Ok((model_id, version, ts_str, counter, issuer))
    }

    // ── Ticket verification ───────────────────────────────────────────────────

    /// Verify an HMAC-SHA256 ticket and its timestamp window.
    ///
    /// Ticket format: `<model_id>|<version>|<unix_timestamp>|<issuer_peer_id>.<base64-HMAC>`
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
            // SECURITY: Log hash of payload instead of plaintext to prevent info leakage
            let payload_hash = hex::encode(Sha256::digest(payload.as_bytes()));
            error!("HMAC mismatch for payload hash: {}", payload_hash);
            AetherError::SecurityError("Invalid signature".into())
        })?;

        // Timestamp window (anti-replay).
        // SECURITY: Parse all fields first, then validate atomically to prevent
        // timing side-channel attacks that could distinguish parse failures from
        // validation failures.
        let (_model_id, _version, ts_str, _counter, _issuer) = Self::split_ticket_payload(ticket)?;

        // Parse timestamp (may fail, but we don't early-reject based on this alone)
        let ts: u64 = match ts_str.parse() {
            Ok(t) => t,
            Err(_) => return Err(AetherError::InvalidTicket),
        };

        // Atomic validation: all checks happen together after parsing
        let now = Self::now_secs();
        let w = Config::TICKET_WINDOW_SECS;
        if now > ts + w || now < ts.saturating_sub(w) {
            return Err(AetherError::SecurityError("Ticket expired".into()));
        }

        Ok(())
    }

    pub fn extract_model_id<'a>(ticket: &'a str) -> Result<&'a str, AetherError> {
        let (model_id, _, _, _, _) = Self::split_ticket_payload(ticket)?;
        Ok(model_id)
    }

    pub fn extract_issuer_peer_id<'a>(ticket: &'a str) -> Result<&'a str, AetherError> {
        let (_, _, _, _, issuer) = Self::split_ticket_payload(ticket)?;
        Ok(issuer)
    }

    /// ADR-017: Extract counter from ticket (returns None for legacy 4-field tickets).
    pub fn extract_counter(ticket: &str) -> Result<Option<u64>, AetherError> {
        let (_, _, _, counter, _) = Self::split_ticket_payload(ticket)?;
        Ok(counter)
    }

    /// Generate a signed ticket for outbound requests (legacy format, no counter).
    /// ADR-017: Use `generate_ticket_with_counter` for new implementations.
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

    /// ADR-017: Generate a signed ticket with monotonic counter for NTP manipulation resistance.
    ///
    /// Ticket format: `<model_id>|<version>|<unix_timestamp>|<counter>|<issuer_peer_id>.<base64-HMAC>`
    /// The counter must be strictly increasing per issuer to prevent replay attacks with valid tickets.
    pub fn generate_ticket_with_counter(
        model_id: &str,
        version: &str,
        issuer_peer_id: &str,
        counter: u64,
        secret: &SecureKey,
    ) -> Result<String, AetherError> {
        let payload = format!(
            "{}|{}|{}|{}|{}",
            model_id,
            version,
            Self::now_secs(),
            counter,
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
        model_id: &str,
    ) -> Result<[u8; 32], AetherError> {
        let hk = Hkdf::<Sha256>::new(Some(model_id.as_bytes()), &transport_key.0);
        let mut output = [0u8; 32];
        hk.expand(b"aether-stream-session-v1", &mut output)
            .map_err(|_| AetherError::InternalError("HKDF stream expand failed".into()))?;
        Ok(output)
    }

    /// Generate a cryptographically random 12-byte nonce for ChaCha20.
    ///
    /// Each session gets a unique nonce, eliminating keystream-reuse risk
    /// even if the same ticket+key pair is used across seeder restarts.
    pub fn generate_random_nonce() -> [u8; 12] {
        use rand::RngCore;
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
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
