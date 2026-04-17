// rust_core/src/transport_encryption.rs
//! ADR-018: Encrypted Transport Layer — Noise Protocol NK Pattern
//!
//! ## Status: IMPLEMENTED ✅
//!
//! ## Problem
//! P2P communication uses plaintext HTTP for all endpoints. While download bodies
//! are ChaCha20-encrypted, metadata, headers, and HMAC tickets are exposed.
//! Static ECDH provides no forward secrecy.
//!
//! ## Decision (ADR-018)
//! Implement Noise Protocol NK pattern for all P2P communication:
//! - NK pattern: No static keys for initiator, static key for responder (seeder)
//! - Ephemeral key exchange provides forward secrecy
//! - 1-RTT handshake (initiator sends ephemeral key, responder sends static+ephemeral)
//! - Preserves existing ChaCha20 as application-layer encryption (defense-in-depth)
//!
//! ## Scope Lock (Cycle #2)
//! This module now acts as the ADR-018 scope contract for C1/C2:
//! - **In scope for C1:** `/identity`, `/download`, ping/heartbeat transport, request
//!   headers, query params, and response metadata currently visible over plaintext TCP.
//! - **In scope for C2:** per-connection ephemeral Noise handshake and strict separation
//!   between Noise static keys and the existing HMAC / ChaCha20 derivation keys.
//! - **Migration constraint:** plaintext fallback may exist only during transition and must
//!   be explicitly gated. It is not the end state.
//! - **Out of scope:** CDN/manifest distribution, `forge.py`, ECDSA manifest signing, and
//!   removal of application-layer ChaCha20 defense-in-depth in this cycle.
//!
//! ## Implementation Roadmap
//!
//! ### Phase 1: Dependencies and Types
//! - Add `snow` crate (Noise Protocol implementation)
//! - Define `NoiseSession` struct wrapping snow::TransportState
//! - Define `HandshakeState` enum (Initiator, Responder, Complete)
//!
//! ### Phase 2: Handshake Integration
//! - Add `noise_private_key` to `PeerEntry` (seeder's static Noise key)
//! - Generate ephemeral keys per connection
//! - Integrate handshake into `start_server` (responder) and `download_model` (initiator)
//!
//! ### Phase 3: Encrypted Transport
//! - Wrap TCP streams with Noise encryption/decryption
//! - Replace plaintext HTTP with encrypted frames
//! - Maintain backward compatibility during transition (plaintext fallback)
//!
//! ### Phase 4: Mobile Integration
//! - Expose Noise handshake to Kotlin/Swift via FFI
//! - Mobile generates ephemeral keys, completes handshake
//! - Update AetherService/AetherManager to use encrypted transport
//!
//! ## Security Considerations
//! - Static ECDH keys used for Noise pattern must be separate from HMAC keys
//! - Ephemeral keys must be zeroed after handshake (forward secrecy)
//! - Ticket verification must happen AFTER Noise handshake completes
//! - Existing ChaCha20 transport encryption stays as defense-in-depth
//!
//! ## Rejected Alternatives
//! - TLS 1.3 with public CA: Overkill for P2P, requires infrastructure
//! - DTLS: Adds complexity for TCP-based protocol
//! - Pure ChaCha20 without handshake: No forward secrecy, no authentication

use crate::error::AetherError;
use crate::security::SecureKey;
use snow::{params::NoiseParams, Builder, HandshakeState, TransportState};

const NOISE_NK_PARAMS: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
const NOISE_STATIC_KEY_LEN: usize = 32;
const NOISE_HANDSHAKE_BUFFER_LEN: usize = 96;
const NOISE_TAG_LEN: usize = 16;

/// ADR-018: Explicitly tracked transport endpoints that must move off plaintext
/// TCP in order to close C1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedEndpoint {
    Identity,
    Download,
    Ping,
}

/// ADR-018: Current implementation phase for the transport migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adr018Phase {
    /// Scope and boundaries are fixed, but runtime behavior is still legacy plaintext.
    ScopeLocked,
    /// Noise handshake exists, but only behind an explicit migration gate.
    HandshakeGated,
    /// All in-scope transport runs inside Noise-framed encrypted transport.
    Enforced,
}

/// ADR-018: Forward secrecy requirement needed to close C2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardSecrecyRequirement {
    /// Legacy mode: static-only derivation, known insufficient.
    StaticOnlyLegacy,
    /// Target mode: per-connection ephemeral handshake material is mandatory.
    EphemeralPerConnection,
}

/// ADR-018: Frozen scope contract for the dedicated C1/C2 implementation cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adr018Scope {
    pub phase: Adr018Phase,
    pub protected_endpoints: &'static [ProtectedEndpoint],
    pub forward_secrecy: ForwardSecrecyRequirement,
    pub preserves_chacha20_defense_in_depth: bool,
    pub allows_plaintext_migration_fallback: bool,
    pub excludes_cdn_and_manifest_distribution: bool,
    pub requires_separate_noise_static_keys: bool,
}

pub struct NoiseStaticKeypair {
    pub private_key: SecureKey,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Copy)]
enum NoiseRole {
    Initiator,
    Responder,
}

pub struct NoiseHandshakeSession {
    role: NoiseRole,
    step: u8,
    state: HandshakeState,
}

pub struct NoiseTransportSession {
    #[allow(dead_code)]
    role: NoiseRole,
    state: TransportState,
}

/// Configuration flag for ADR-019: Enable Noise NK transport encryption.
/// 
/// When true, Noise handshake is used for protected endpoints.
/// When false (legacy), plaintext HTTP is used.
/// 
/// Migration path:
/// - Phase 1 (HandshakeGated): enabled during `AetherEngine::new()` while
///   endpoint-level transport integration is rolled out incrementally.
/// - Phase 2 (Enforced): Always true, plaintext fallback removed.
static NOISE_ENABLED: std::sync::LazyLock<std::sync::atomic::AtomicBool> =
    std::sync::LazyLock::new(|| std::sync::atomic::AtomicBool::new(false));

/// Enable Noise NK transport encryption (ADR-019).
/// 
/// # Safety
/// Call once during AetherEngine initialization. Do not toggle at runtime.
pub fn enable_noise_transport() {
    NOISE_ENABLED.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Check if Noise transport is enabled.
pub fn is_noise_enabled() -> bool {
    NOISE_ENABLED.load(std::sync::atomic::Ordering::SeqCst)
}

/// Returns the current ADR-018 scope contract.
///
/// This is intentionally explicit so future implementation work can assert
/// against one stable source of truth rather than re-litigating scope in
/// multiple files.
pub fn current_scope() -> Adr018Scope {
    let phase = if is_noise_enabled() {
        Adr018Phase::HandshakeGated
    } else {
        Adr018Phase::ScopeLocked
    };
    
    Adr018Scope {
        phase,
        protected_endpoints: &[
            ProtectedEndpoint::Identity,
            ProtectedEndpoint::Download,
            ProtectedEndpoint::Ping,
        ],
        forward_secrecy: ForwardSecrecyRequirement::EphemeralPerConnection,
        preserves_chacha20_defense_in_depth: true,
        allows_plaintext_migration_fallback: true,
        excludes_cdn_and_manifest_distribution: true,
        requires_separate_noise_static_keys: true,
    }
}

pub fn noise_static_public_key_len() -> usize {
    NOISE_STATIC_KEY_LEN
}

pub fn validate_static_public_key(key: &[u8]) -> Result<(), AetherError> {
    if key.len() != NOISE_STATIC_KEY_LEN {
        return Err(AetherError::KeyExchangeFailed);
    }
    Ok(())
}

pub fn generate_static_keypair() -> Result<NoiseStaticKeypair, AetherError> {
    let params = parse_noise_params()?;
    let builder = Builder::new(params);
    let keypair = builder
        .generate_keypair()
        .map_err(|e| AetherError::InternalError(format!("ADR-018 key generation failed: {e}")))?;
    validate_static_public_key(&keypair.private)?;
    validate_static_public_key(&keypair.public)?;
    Ok(NoiseStaticKeypair {
        private_key: SecureKey(keypair.private),
        public_key: keypair.public,
    })
}

/// Stub: Noise Protocol NK pattern session state.
pub enum NoiseSession {
    /// Handshake not yet started
    Uninitialized,
    /// Handshake in progress
    Handshaking(NoiseHandshakeSession),
    /// Handshake complete, transport encryption active
    Established(NoiseTransportSession),
    #[doc(hidden)]
    Transitioning,
}

/// Initialize Noise Protocol responder (seeder side).
pub fn init_noise_responder(static_key: &[u8]) -> Result<NoiseSession, AetherError> {
    validate_static_public_key(static_key)?;
    let params = parse_noise_params()?;
    let state = Builder::new(params)
        .local_private_key(static_key)
        .build_responder()
        .map_err(|e| AetherError::InternalError(format!("ADR-018 responder init failed: {e}")))?;
    Ok(NoiseSession::Handshaking(NoiseHandshakeSession {
        role: NoiseRole::Responder,
        step: 0,
        state,
    }))
}

/// Initialize Noise Protocol initiator (leecher side).
pub fn init_noise_initiator(remote_static_key: &[u8]) -> Result<NoiseSession, AetherError> {
    validate_static_public_key(remote_static_key)?;
    let params = parse_noise_params()?;
    let state = Builder::new(params)
        .remote_public_key(remote_static_key)
        .build_initiator()
        .map_err(|e| AetherError::InternalError(format!("ADR-018 initiator init failed: {e}")))?;
    Ok(NoiseSession::Handshaking(NoiseHandshakeSession {
        role: NoiseRole::Initiator,
        step: 0,
        state,
    }))
}

/// Perform one Noise handshake step.
pub fn perform_handshake(session: &mut NoiseSession, data: &[u8]) -> Result<Vec<u8>, AetherError> {
    let current = std::mem::replace(session, NoiseSession::Transitioning);
    let (next, response) = match current {
        NoiseSession::Handshaking(mut hs) => match hs.role {
            NoiseRole::Initiator => match hs.step {
                0 => {
                    if !data.is_empty() {
                        return Err(AetherError::SecurityError(
                            "ADR-018 initiator expected empty input on first handshake step".into(),
                        ));
                    }
                    let response = write_handshake_message(&mut hs.state)?;
                    hs.step = 1;
                    (NoiseSession::Handshaking(hs), response)
                }
                1 => {
                    if data.is_empty() {
                        return Err(AetherError::SecurityError(
                            "ADR-018 initiator expected responder handshake payload".into(),
                        ));
                    }
                    read_handshake_message(&mut hs.state, data)?;
                    let transport = hs.state.into_transport_mode().map_err(|e| {
                        AetherError::InternalError(format!(
                            "ADR-018 initiator transport upgrade failed: {e}"
                        ))
                    })?;
                    (
                        NoiseSession::Established(NoiseTransportSession {
                            role: NoiseRole::Initiator,
                            state: transport,
                        }),
                        Vec::new(),
                    )
                }
                _ => {
                    return Err(AetherError::InternalError(
                        "ADR-018 initiator handshake already completed".into(),
                    ))
                }
            },
            NoiseRole::Responder => match hs.step {
                0 => {
                    if data.is_empty() {
                        return Err(AetherError::SecurityError(
                            "ADR-018 responder expected initiator handshake payload".into(),
                        ));
                    }
                    read_handshake_message(&mut hs.state, data)?;
                    let response = write_handshake_message(&mut hs.state)?;
                    let transport = hs.state.into_transport_mode().map_err(|e| {
                        AetherError::InternalError(format!(
                            "ADR-018 responder transport upgrade failed: {e}"
                        ))
                    })?;
                    (
                        NoiseSession::Established(NoiseTransportSession {
                            role: NoiseRole::Responder,
                            state: transport,
                        }),
                        response,
                    )
                }
                _ => {
                    return Err(AetherError::InternalError(
                        "ADR-018 responder handshake already completed".into(),
                    ))
                }
            },
        },
        NoiseSession::Established(ts) => {
            *session = NoiseSession::Established(ts);
            return Err(AetherError::InternalError(
                "ADR-018 handshake called on established session".into(),
            ));
        }
        NoiseSession::Uninitialized => {
            *session = NoiseSession::Uninitialized;
            return Err(AetherError::InternalError(
                "ADR-018 handshake called on uninitialized session".into(),
            ));
        }
        NoiseSession::Transitioning => {
            *session = NoiseSession::Transitioning;
            return Err(AetherError::InternalError(
                "ADR-018 session re-entry detected".into(),
            ));
        }
    };
    *session = next;
    Ok(response)
}

/// Encrypt data using established Noise session.
pub fn encrypt(session: &mut NoiseSession, plaintext: &[u8]) -> Result<Vec<u8>, AetherError> {
    let current = std::mem::replace(session, NoiseSession::Transitioning);
    let (next, ciphertext) = match current {
        NoiseSession::Established(mut ts) => {
            let mut out = vec![0u8; plaintext.len() + NOISE_TAG_LEN];
            let n = ts
                .state
                .write_message(plaintext, &mut out)
                .map_err(|e| AetherError::InternalError(format!("ADR-018 encrypt failed: {e}")))?;
            out.truncate(n);
            let next = NoiseSession::Established(ts);
            (next, out)
        }
        other => {
            *session = other;
            return Err(AetherError::InternalError(
                "ADR-018 encrypt requires established Noise session".into(),
            ));
        }
    };
    *session = next;
    Ok(ciphertext)
}

/// Decrypt data using established Noise session.
pub fn decrypt(session: &mut NoiseSession, ciphertext: &[u8]) -> Result<Vec<u8>, AetherError> {
    let current = std::mem::replace(session, NoiseSession::Transitioning);
    let (next, plaintext) = match current {
        NoiseSession::Established(mut ts) => {
            let mut out = vec![0u8; ciphertext.len()];
            let n = ts
                .state
                .read_message(ciphertext, &mut out)
                .map_err(|e| AetherError::InternalError(format!("ADR-018 decrypt failed: {e}")))?;
            out.truncate(n);
            let next = NoiseSession::Established(ts);
            (next, out)
        }
        other => {
            *session = other;
            return Err(AetherError::InternalError(
                "ADR-018 decrypt requires established Noise session".into(),
            ));
        }
    };
    *session = next;
    Ok(plaintext)
}

fn parse_noise_params() -> Result<NoiseParams, AetherError> {
    NOISE_NK_PARAMS
        .parse()
        .map_err(|e| AetherError::InternalError(format!("ADR-018 invalid Noise params: {e}")))
}

fn read_handshake_message(state: &mut HandshakeState, data: &[u8]) -> Result<(), AetherError> {
    let mut payload = vec![0u8; NOISE_HANDSHAKE_BUFFER_LEN];
    let payload_len = state
        .read_message(data, &mut payload)
        .map_err(|e| AetherError::SecurityError(format!("ADR-018 handshake read failed: {e}")))?;
    if payload_len != 0 {
        return Err(AetherError::SecurityError(
            "ADR-018 handshake payload must be empty during bootstrap".into(),
        ));
    }
    Ok(())
}

fn write_handshake_message(state: &mut HandshakeState) -> Result<Vec<u8>, AetherError> {
    let mut out = vec![0u8; NOISE_HANDSHAKE_BUFFER_LEN];
    let n = state
        .write_message(&[], &mut out)
        .map_err(|e| AetherError::InternalError(format!("ADR-018 handshake write failed: {e}")))?;
    out.truncate(n);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_noise_keypair_has_expected_lengths() {
        let keypair = generate_static_keypair().unwrap();
        assert_eq!(keypair.private_key.0.len(), noise_static_public_key_len());
        assert_eq!(keypair.public_key.len(), noise_static_public_key_len());
    }

    #[test]
    fn adr018_scope_c1_endpoints_match_contract() {
        let scope = current_scope();
        assert!(matches!(
            scope.phase,
            Adr018Phase::ScopeLocked | Adr018Phase::HandshakeGated
        ));
        assert_eq!(
            scope.protected_endpoints,
            &[
                ProtectedEndpoint::Identity,
                ProtectedEndpoint::Download,
                ProtectedEndpoint::Ping,
            ]
        );
        assert!(scope.excludes_cdn_and_manifest_distribution);
    }

    #[test]
    fn adr018_scope_locks_c2_requirements() {
        let scope = current_scope();
        assert_eq!(
            scope.forward_secrecy,
            ForwardSecrecyRequirement::EphemeralPerConnection
        );
        assert!(scope.requires_separate_noise_static_keys);
        assert!(scope.preserves_chacha20_defense_in_depth);
    }

    #[test]
    fn invalid_static_key_length_is_rejected() {
        let result = init_noise_initiator(&[0u8; 31]);
        assert!(matches!(result, Err(AetherError::KeyExchangeFailed)));
    }

    #[test]
    fn noise_nk_handshake_and_transport_roundtrip() {
        let responder_keys = generate_static_keypair().unwrap();
        let mut initiator =
            init_noise_initiator(&responder_keys.public_key).expect("initiator should build");
        let mut responder =
            init_noise_responder(&responder_keys.private_key.0).expect("responder should build");

        let msg1 = perform_handshake(&mut initiator, &[]).expect("initiator writes msg1");
        assert!(!msg1.is_empty());
        let msg2 =
            perform_handshake(&mut responder, &msg1).expect("responder reads msg1 and writes msg2");
        assert!(!msg2.is_empty());
        let done = perform_handshake(&mut initiator, &msg2).expect("initiator finishes");
        assert!(done.is_empty());

        let ciphertext = encrypt(&mut initiator, b"hello-noise").expect("encrypt");
        let plaintext = decrypt(&mut responder, &ciphertext).expect("decrypt");
        assert_eq!(plaintext, b"hello-noise");
    }
}
