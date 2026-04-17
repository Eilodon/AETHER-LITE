// rust_core/src/lib.rs
//! AetherEngine – central orchestrator (v2.3.2)
//!
//! Upgrades vs v2.3.1:
//!   • Seeder role implemented: `register_file_for_serving` + streaming `download_handler`
//!     with Content-Length, Range (206 Partial Content), and graceful 416 errors.
//!   • `heartbeat()` now probes the TCP server (127.0.0.1:<bound_port>) instead of
//!     logging a string — detects silent Tokio task crashes.
//!   • HKDF-SHA256 applied in `register_peer_key` before using ECDH output as HMAC key.
//!   • `now_secs()` unwrap removed — no panic on pre-epoch device clocks.
//!   • `Arc<Runtime>` so runtime outlives engine drop on Android main thread.
#![allow(clippy::empty_line_after_doc_comments)]

mod canonical_json;
mod config;
pub mod decompressor;
pub mod error;
mod network;
pub mod patcher;
pub mod security;
pub mod transport_encryption; // ADR-018: Noise Protocol stub (roadmap)

use crate::canonical_json::canonicalize_json;
use crate::config::Config;
use crate::error::AetherError;
use crate::network::{download_file_to_fd, ping_peer, ping_peer_secure};
use crate::security::{SecureKey, SecurityManager};
use async_stream::try_stream;
use serde::Serialize;

use axum::{
    body::{Body, Bytes},
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use dashmap::DashMap;
use futures_util::stream::{self, BoxStream};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::runtime::Runtime;
use tokio::sync::{Mutex, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::info;

uniffi::include_scaffolding!("aether");

// ── Shared server state ───────────────────────────────────────────────────────

struct AppState {
    // ADR-012: Unified peer map — single DashMap entry per peer for atomic revocation.
    // Replaces the previous separate peer_keys + peer_permissions + peer_limiters maps,
    // which required 3 non-atomic remove() calls in revoke_peer().
    peers: DashMap<String, PeerEntry>,
    /// Per-peer limiter state for unknown / unauthenticated peers.
    /// Keeps pre-auth rate limiting separate from authenticated peer state.
    unauth_limiters: DashMap<String, PeerLimiterEntry>,
    seen_tickets: DashMap<String, u64>,
    /// ADR-007: CancellationToken replaces Arc&lt;Notify&gt; for graceful shutdown.
    /// Per-session token created by start_server(), cancelled by stop_server().
    /// No stored-permit issue — cancellation is purely cooperative.
    shutdown_token: RwLock<CancellationToken>,
    /// Limits concurrent download sessions to prevent resource exhaustion.
    download_limiter: Arc<Semaphore>,
    /// Files registered for serving by model_id → absolute path on disk.
    /// Populated by `register_file_for_serving` before a peer connects.
    serve_files: DashMap<String, PathBuf>,
    /// ADR-015: Per-peer consecutive ticket verification failure counter.
    /// After MAX_TICKET_VERIFY_FAILURES consecutive failures, the peer is
    /// temporarily blocked from attempting further verifications until TTL expiry.
    ticket_verify_failures: DashMap<String, TicketVerifyFailureEntry>,
    /// ADR-016: Last accepted manifest sequence per model_id.
    /// Rejects manifests with sequence <= stored value (rollback protection).
    manifest_sequences: DashMap<String, u64>,
    /// ADR-017: Last accepted ticket counter per issuer peer_id.
    /// Rejects tickets with counter <= stored value (NTP manipulation resistance).
    ticket_counters: DashMap<String, u64>,
    /// ADR-027: Established Noise transport session per peer.
    /// Stored separately from peer metadata so session state can be rotated
    /// without mutating the peer registry entry.
    noise_sessions: DashMap<String, NoiseSessionEntry>,
}

/// ADR-012: All per-peer state in a single struct stored under one DashMap key.
/// Removing this entry is atomic — no window between key/permission/limiter removal.
struct PeerEntry {
    keys: PeerKeys,
    permissions: HashSet<String>,
    limiter: PeerLimiterEntry,
}

#[derive(Clone)]
struct PeerKeys {
    auth_key: SecureKey,
    transport_key: SecureKey,
    noise_remote_static_key: Option<Vec<u8>>,
}

struct PeerLimiterEntry {
    semaphore: Arc<Semaphore>,
    last_seen_unix_secs: AtomicU64,
}

struct TicketVerifyFailureEntry {
    count: u32,
    last_failure_unix_secs: u64,
}

struct NoiseSessionEntry {
    session: Arc<Mutex<transport_encryption::NoiseSession>>,
    last_used_unix_secs: AtomicU64,
}

impl PeerLimiterEntry {
    fn new(now: u64) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(Config::MAX_DOWNLOADS_PER_PEER)),
            last_seen_unix_secs: AtomicU64::new(now),
        }
    }

    fn touch(&self, now: u64) {
        self.last_seen_unix_secs.store(now, Ordering::Relaxed);
    }

    fn is_idle_expired(&self, now: u64) -> bool {
        let last_seen = self.last_seen_unix_secs.load(Ordering::Relaxed);
        now.saturating_sub(last_seen) > Config::PEER_LIMITER_IDLE_TTL_SECS
            && self.semaphore.available_permits() == Config::MAX_DOWNLOADS_PER_PEER
    }
}

impl NoiseSessionEntry {
    fn new(session: transport_encryption::NoiseSession, now: u64) -> Self {
        Self {
            session: Arc::new(Mutex::new(session)),
            last_used_unix_secs: AtomicU64::new(now),
        }
    }

    fn touch(&self, now: u64) {
        self.last_used_unix_secs.store(now, Ordering::Relaxed);
    }

    fn is_idle_expired(&self, now: u64) -> bool {
        let last_seen = self.last_used_unix_secs.load(Ordering::Relaxed);
        now.saturating_sub(last_seen) > Config::NOISE_SESSION_IDLE_TTL_SECS
    }
}

#[derive(Clone, Serialize)]
struct IdentityState {
    peer_id: String,
    public_key_hex: String,
    noise_static_public_key_hex: String,
    protocol_version: String,
}

#[derive(Clone)]
struct ServerState {
    app: Arc<AppState>,
    identity: Arc<IdentityState>,
    noise_static_private_key: Arc<RwLock<SecureKey>>,
}

// ── Engine ────────────────────────────────────────────────────────────────────

pub struct AetherEngine {
    state: Arc<AppState>,
    /// Shared runtime — `Arc` ensures it outlives the engine if the engine is
    /// dropped on the Android main thread inside a coroutine.
    rt: Arc<Runtime>,
    /// Fix v2.3: node's own UUID; sent as `?pid=` in outbound requests.
    self_peer_id: Arc<RwLock<String>>,
    self_public_key_x962: Arc<RwLock<Vec<u8>>>,
    /// ADR-020: Responder static key persists for the lifetime of the engine.
    /// Reusing it across `stop_server()` / `start_server()` is intentional so
    /// existing peer registrations do not lose the seeder's advertised key.
    #[allow(dead_code)]
    noise_static_private_key: Arc<RwLock<SecureKey>>,
    noise_static_public_key: Arc<RwLock<Vec<u8>>>,
    /// Port assigned by the OS when `start_server()` is called.
    /// Used by `heartbeat()` to probe the actual TCP server.
    bound_port: Arc<RwLock<Option<u16>>>,
}

impl Default for AetherEngine {
    fn default() -> Self {
        Self::new().expect("ADR-001: AetherEngine::default() — init failed")
    }
}

impl AetherEngine {
    pub fn new() -> Result<Self, AetherError> {
        #[cfg(target_os = "android")]
        tracing_android::init_logging("aether_core", tracing::Level::INFO);

        #[cfg(not(target_os = "android"))]
        {
            use tracing_subscriber::fmt;
            let _ = fmt::try_init();
        }

        let default_id = uuid::Uuid::new_v4().to_string();
        // ADR-001: propagate error instead of expect()/panic
        let noise_static = transport_encryption::generate_static_keypair()
            .map_err(|e| AetherError::InternalError(format!("Noise static key init failed: {}", e)))?;
        // ADR-023: engine construction is the only reliable production call site
        // for this global scope flag; mobile clients should not have to remember
        // to toggle transport policy after every instantiation.
        transport_encryption::enable_noise_transport();

        let rt = Runtime::new()
            .map_err(|e| AetherError::InternalError(format!("Tokio runtime init failed: {}", e)))?;

        Ok(Self {
            state: Arc::new(AppState {
                peers: DashMap::new(),
                unauth_limiters: DashMap::new(),
                seen_tickets: DashMap::new(),
                shutdown_token: RwLock::new(CancellationToken::new()),
                download_limiter: Arc::new(Semaphore::new(Config::MAX_CONCURRENT_DOWNLOADS)),
                serve_files: DashMap::new(),
                ticket_verify_failures: DashMap::new(),
                manifest_sequences: DashMap::new(),
                ticket_counters: DashMap::new(),
                noise_sessions: DashMap::new(),
            }),
            rt: Arc::new(rt),
            self_peer_id: Arc::new(RwLock::new(default_id)),
            self_public_key_x962: Arc::new(RwLock::new(Vec::new())),
            noise_static_private_key: Arc::new(RwLock::new(noise_static.private_key)),
            noise_static_public_key: Arc::new(RwLock::new(noise_static.public_key)),
            bound_port: Arc::new(RwLock::new(None)),
        })
    }

    // ── Identity ──────────────────────────────────────────────────────────────

    pub fn set_self_peer_id(&self, peer_id: String) {
        // ADR-001: void return — expect() with clear message instead of bare unwrap()
        *self.self_peer_id.write().expect("ADR-001: self_peer_id write lock poisoned — unrecoverable") = peer_id;
    }

    pub fn set_self_identity_public_key(
        &self,
        public_key_x962: Vec<u8>,
    ) -> Result<(), AetherError> {
        if public_key_x962.len() != 65 || public_key_x962.first().copied() != Some(0x04) {
            return Err(AetherError::KeyExchangeFailed);
        }
        // ADR-001: propagate poison as InternalError instead of unwrap()
        let mut pk_guard = self.self_public_key_x962.write()
            .map_err(|_| AetherError::InternalError("RwLock poisoned".into()))?;
        *pk_guard = public_key_x962;
        Ok(())
    }

    fn get_self_peer_id(&self) -> String {
        // ADR-001: private void-return — expect() with clear message
        self.self_peer_id.read().expect("ADR-001: self_peer_id read lock poisoned — unrecoverable").clone()
    }

    // ── Server lifecycle ──────────────────────────────────────────────────────

    pub fn start_server(&self) -> Result<u16, AetherError> {
        // ── Invariant: identity public key must be set before serving ────────
        // Prevents serving an identity document with an empty public_key_hex
        // which would break ECDH handshake for any peer that trusts this node.
        // ADR-001: propagate poison as InternalError instead of unwrap()
        if self.self_public_key_x962.read().map_err(|_| AetherError::InternalError("RwLock poisoned".into()))?.is_empty() {
            return Err(AetherError::InternalError(
                "set_self_identity_public_key must be called before start_server".into(),
            ));
        }

        // ADR-007: create a fresh CancellationToken for this server session.
        // Replaces the old Arc&lt;Notify&gt; pattern — no permit accumulation risk.
        let token = CancellationToken::new();
        // ADR-001: propagate poison as InternalError instead of unwrap()
        let mut shutdown_guard = self.state.shutdown_token.write()
            .map_err(|_| AetherError::InternalError("RwLock poisoned".into()))?;
        *shutdown_guard = token.clone();
        let child = token.child_token();
        let app_state = self.state.clone();
        let bound_port = self.bound_port.clone();
        let self_peer_id = self.self_peer_id.clone();
        let self_public_key_x962 = self.self_public_key_x962.clone();
        let noise_static_public_key = self.noise_static_public_key.clone();
        let noise_static_private_key = self.noise_static_private_key.clone();
        let (tx, rx) = std::sync::mpsc::channel::<Result<u16, AetherError>>();

        self.rt.spawn(async move {
            let state = ServerState {
                app: app_state,
                identity: Arc::new(IdentityState {
                    // ADR-001: inside spawned task — expect() with clear message
                    peer_id: self_peer_id.read().expect("ADR-001: self_peer_id read lock poisoned in spawn").clone(),
                    public_key_hex: hex::encode(self_public_key_x962.read().expect("ADR-001: self_public_key_x962 read lock poisoned in spawn").clone()),
                    noise_static_public_key_hex: hex::encode(noise_static_public_key.read().expect("ADR-001: noise_static_public_key read lock poisoned in spawn").clone()),
                    protocol_version: Config::get_protocol_version().to_string(),
                }),
                noise_static_private_key,
            };
            let app = Router::new()
                .route("/download", get(download_handler))
                .route("/ping", get(ping_handler))
                .route("/identity", get(identity_handler))
                .route("/noise-handshake", post(noise_handshake_handler))
                .with_state(state);

            match tokio::net::TcpListener::bind(Config::BIND_ADDRESS).await {
                Ok(l) => {
                    // ADR-001: explicit match instead of unwrap() — async block returns ()
                    let port = match l.local_addr() {
                        Ok(addr) => addr.port(),
                        Err(e) => {
                            tracing::error!("ADR-001: Failed to get bound address: {}", e);
                            tx.send(Err(AetherError::ServerStartupError(
                                format!("Failed to get bound address: {}", e)
                            ))).ok();
                            return;
                        }
                    };
                    // ADR-001: inside spawned task — expect() with clear message
                    *bound_port.write().expect("ADR-001: bound_port write lock poisoned in spawn") = Some(port);
                    tx.send(Ok(port)).ok();
                    info!("Aether server listening on :{}", port);
                    axum::serve(l, app)
                        .with_graceful_shutdown(async move { child.cancelled().await })
                        .await
                        .unwrap_or_else(|e| tracing::error!("Server error: {}", e));
                }
                Err(e) => {
                    tx.send(Err(AetherError::ServerStartupError(e.to_string())))
                        .ok();
                }
            }
        });

        // ── Periodic background eviction of expired seen-ticket entries ────────
        // ADR-005: moved out of the per-request hot path. Runs every 30s,
        // co-shutdown with the Axum server via the same Notify.
        let eviction_state = self.state.clone();
        let eviction_child = token.child_token();
        self.rt.spawn(async move {
            loop {
                tokio::select! {
                    _ = eviction_child.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(Config::BACKGROUND_CLEANUP_INTERVAL_SECS)) => {
                        let now = current_unix_secs();
                        let ttl = Config::TICKET_REPLAY_TTL_SECS;
                        eviction_state.seen_tickets
                            .retain(|_, seen_at| now.saturating_sub(*seen_at) <= ttl);
                        eviction_state
                            .peers
                            .retain(|_, entry| !entry.limiter.is_idle_expired(now));
                        eviction_state
                            .unauth_limiters
                            .retain(|_, entry| !entry.is_idle_expired(now));
                        eviction_state
                            .ticket_verify_failures
                            .retain(|_, entry| {
                                now.saturating_sub(entry.last_failure_unix_secs)
                                    < Config::MAX_TICKET_VERIFY_FAILURE_TTL_SECS
                            });
                        eviction_state
                            .noise_sessions
                            .retain(|_, entry| !entry.is_idle_expired(now));
                    }
                }
            }
        });

        rx.recv()
            .map_err(|_| AetherError::InternalError("Startup channel closed".into()))?
    }

    pub fn stop_server(&self) {
        // ADR-007: cancel the current session's token — all child tokens
        // (Axum server, eviction task) observe cancellation and exit.
        // ADR-001: void return — expect() with clear messages instead of bare unwrap()
        self.state.shutdown_token.read().expect("ADR-001: shutdown_token read lock poisoned").cancel();
        *self.bound_port.write().expect("ADR-001: bound_port write lock poisoned") = None;
        // ADR-019: Clear all Noise sessions on server stop to prevent session/auth divergence
        self.state.noise_sessions.clear();
    }

    /// Returns `true` if the server is currently bound to a port.
    /// Cheap O(1) check — reads in-memory state only, no network probe.
    pub fn is_server_running(&self) -> bool {
        // ADR-001: graceful fallback instead of unwrap() — if lock is poisoned, server is not running
        self.bound_port.read().map(|g| g.is_some()).unwrap_or(false)
    }

    /// Returns the protocol version string from Rust config.
    /// Single source of truth — mobile should query this instead of hardcoding.
    pub fn get_protocol_version(&self) -> String {
        Config::get_protocol_version().to_string()
    }

    /// Validates that a peer's protocol version is compatible with ours.
    /// Rejects if the peer doesn't advertise a version or if the major version
    /// differs. Minor/patch differences are allowed.
    pub fn validate_peer_protocol(&self, peer_version: String) -> Result<(), AetherError> {
        let local = Config::get_protocol_version();
        let local_major = local.split('.').next().unwrap_or("");
        let peer_major = peer_version.split('.').next().unwrap_or("");
        if peer_major.is_empty() {
            return Err(AetherError::SecurityError(
                "Peer does not advertise protocol version".into(),
            ));
        }
        if local_major != peer_major {
            return Err(AetherError::SecurityError(format!(
                "Incompatible protocol version: local={} peer={}",
                local, peer_version
            )));
        }
        Ok(())
    }

    pub fn canonicalize_json(&self, json: String) -> Result<String, AetherError> {
        canonicalize_json(&json)
    }

    // ── Peer management ───────────────────────────────────────────────────────

    /// Register a 32-byte raw ECDH shared secret for a peer.
    ///
    /// HKDF-SHA256 is applied before storage so the key material used for
    /// HMAC-SHA256 ticket authentication is uniformly random, not a raw EC
    /// x-coordinate. Label `b"aether-hmac-v1"` provides domain separation.
    pub fn register_peer_key(
        &self,
        peer_id: String,
        shared_secret: Vec<u8>,
    ) -> Result<(), AetherError> {
        if shared_secret.len() != 32 {
            return Err(AetherError::KeyExchangeFailed);
        }
        let auth_key = SecurityManager::derive_hmac_key(&shared_secret)?;
        let transport_key = SecurityManager::derive_transport_key(&shared_secret)?;
        let now = current_unix_secs();
        // ADR-012: Insert into unified peer map. If peer already exists,
        // update keys but preserve permissions and limiter.
        match self.state.peers.entry(peer_id.clone()) {
            dashmap::mapref::entry::Entry::Occupied(mut e) => {
                let existing_noise_key = e.get().keys.noise_remote_static_key.clone();
                e.get_mut().keys = PeerKeys {
                    auth_key: SecureKey(auth_key.to_vec()),
                    transport_key: SecureKey(transport_key.to_vec()),
                    noise_remote_static_key: existing_noise_key,
                };
            }
            dashmap::mapref::entry::Entry::Vacant(e) => {
                e.insert(PeerEntry {
                    keys: PeerKeys {
                        auth_key: SecureKey(auth_key.to_vec()),
                        transport_key: SecureKey(transport_key.to_vec()),
                        noise_remote_static_key: None,
                    },
                    permissions: HashSet::new(),
                    limiter: PeerLimiterEntry::new(now),
                });
            }
        }
        Ok(())
    }

    /// ADR-018: Store a peer's Noise static public key separately from the
    /// existing HMAC/ChaCha20 key material. This keeps the migration path for
    /// C1/C2 explicit without reusing legacy transport secrets.
    pub fn register_peer_noise_static_key(
        &self,
        peer_id: String,
        remote_static_key: Vec<u8>,
    ) -> Result<(), AetherError> {
        transport_encryption::validate_static_public_key(&remote_static_key)?;
        let mut entry = match self.state.peers.get_mut(&peer_id) {
            Some(e) => e,
            None => return Err(AetherError::PeerNotFound),
        };
        entry.keys.noise_remote_static_key = Some(remote_static_key);
        Ok(())
    }

    // ADR-021: Noise Protocol NK pattern handshake methods
    
    /// Initiate a Noise NK handshake as the initiator (leecher side).
    /// 
    /// Returns the first handshake message to send to the responder.
    /// The peer must have a registered Noise static public key.
    pub fn initiate_noise_handshake(&self, peer_id: String) -> Result<Vec<u8>, AetherError> {
        let entry = match self.state.peers.get(&peer_id) {
            Some(e) => e,
            None => return Err(AetherError::PeerNotFound),
        };
        
        let remote_static_key = match &entry.keys.noise_remote_static_key {
            Some(key) => key.clone(),
            None => return Err(AetherError::KeyExchangeFailed),
        };
        
        // Create a new Noise session for this peer (stored in session cache)
        let mut session = transport_encryption::init_noise_initiator(&remote_static_key)?;
        
        // First handshake step: initiator sends ephemeral key
        let msg = transport_encryption::perform_handshake(&mut session, &[])?;
        self.state
            .noise_sessions
            .insert(peer_id, NoiseSessionEntry::new(session, current_unix_secs()));

        Ok(msg)
    }

    /// Complete a Noise NK handshake as the initiator.
    /// 
    /// Processes the responder's handshake reply and establishes the transport session.
    pub fn complete_noise_handshake(
        &self,
        peer_id: String,
        response: Vec<u8>,
    ) -> Result<(), AetherError> {
        self.rt
            .block_on(complete_noise_handshake_on_state(&self.state, &peer_id, response))
    }

    /// Establish a Noise session with a remote peer over the `/noise-handshake`
    /// endpoint and cache the established transport state for future requests.
    pub fn establish_noise_session(
        &self,
        peer_ip: String,
        peer_port: u16,
        peer_id: String,
    ) -> Result<(), AetherError> {
        self.rt.block_on(establish_noise_session_on_state(
            &self.state,
            &peer_ip,
            peer_port,
            &self.get_self_peer_id(),
            &peer_id,
        ))
    }

    // ADR-019: Enable Noise transport encryption
    
    /// Enable Noise NK transport encryption globally.
    /// 
    /// Call once during AetherEngine initialization. Once enabled, protected
    /// endpoints (identity, download, ping) will use Noise encryption.
    pub fn enable_noise_transport(&self) {
        transport_encryption::enable_noise_transport();
    }

    /// Grant a peer access to a specific model ID.
    pub fn grant_peer_model_access(
        &self,
        peer_id: String,
        model_id: String,
    ) -> Result<(), AetherError> {
        let mut entry = match self.state.peers.get_mut(&peer_id) {
            Some(e) => e,
            None => return Err(AetherError::PeerNotFound),
        };
        entry.permissions.insert(model_id);
        Ok(())
    }

    /// Revoke all access for a peer: removes keys and permissions from the
    /// in-memory engine state. ADR-011: mobile `removePinnedPeer()` must call
    /// this in addition to clearing persistent storage, so that a revoked peer
    /// cannot continue downloading in the current session.
    ///
    /// ADR-012: Single atomic DashMap::remove() — no window between key and
    /// permission removal. All peer state lives under one key.
    pub fn revoke_peer(&self, peer_id: String) -> Result<(), AetherError> {
        if self.state.peers.remove(&peer_id).is_none() {
            return Err(AetherError::PeerNotFound);
        }
        // ADR-019: Invalidate Noise session to prevent stale session semantics after revoke
        self.state.noise_sessions.remove(&peer_id);
        info!("Revoked peer: {peer_id}");
        Ok(())
    }

    /// ADR-016: Verify manifest signature AND enforce monotonic sequence number.
    ///
    /// Rejects manifests with sequence <= last accepted sequence for the same model_id.
    /// This prevents rollback attacks where an old valid signed manifest is replayed
    /// to force a version downgrade.
    ///
    /// # Arguments
    /// * `model_id` – The model identifier from the manifest payload.
    /// * `sequence` – The monotonic sequence number from the manifest payload.
    /// * `canonical_json` – The canonical JSON string of the manifest payload.
    /// * `signature_hex` – The hex-encoded ECDSA signature.
    /// * `public_key_der` – The DER-encoded public key for verification.
    pub fn verify_manifest_with_sequence(
        &self,
        model_id: String,
        sequence: u64,
        canonical_json: String,
        signature_hex: String,
        public_key_der: Vec<u8>,
    ) -> Result<(), AetherError> {
        // First: verify ECDSA signature
        SecurityManager::verify_manifest(&canonical_json, &signature_hex, &public_key_der)?;

        // Second: check monotonic sequence
        let last_accepted = self
            .state
            .manifest_sequences
            .get(&model_id)
            .map(|v| *v)
            .unwrap_or(0);
        if sequence <= last_accepted {
            return Err(AetherError::SecurityError(format!(
                "Manifest sequence {} is not greater than last accepted {} (ADR-016)",
                sequence, last_accepted
            )));
        }

        // Update stored sequence atomically
        self.state.manifest_sequences.insert(model_id, sequence);
        Ok(())
    }

    /// Seed ADR-016 manifest sequence state from platform-persisted storage.
    ///
    /// Mobile clients persist the last accepted sequence across app restarts,
    /// while the Rust engine only keeps in-memory state for the current
    /// process. This method hydrates that persisted value into the engine
    /// without allowing a lower value to overwrite a newer in-memory one.
    pub fn seed_manifest_sequence(
        &self,
        model_id: String,
        sequence: u64,
    ) -> Result<(), AetherError> {
        if sequence == 0 {
            return Err(AetherError::SecurityError(
                "Manifest sequence must be > 0 (ADR-016)".into(),
            ));
        }

        let current = self
            .state
            .manifest_sequences
            .get(&model_id)
            .map(|v| *v)
            .unwrap_or(0);
        if sequence > current {
            self.state.manifest_sequences.insert(model_id, sequence);
        }
        Ok(())
    }

    // ── Seeder role ───────────────────────────────────────────────────────────

    /// Register a local file to be served to authenticated peers.
    ///
    /// After calling this, any peer that presents a valid HMAC ticket with
    /// `model_id` in the payload can download the file via `GET /download?pid=`.
    ///
    /// # Arguments
    /// * `model_id` – Identifier that must match the ticket payload (e.g. `"llm-mini"`).
    /// * `file_path` – Absolute path on disk to the file to serve.
    pub fn register_file_for_serving(
        &self,
        model_id: String,
        file_path: String,
    ) -> Result<(), AetherError> {
        let path = PathBuf::from(&file_path);
        if !path.exists() {
            return Err(AetherError::InternalError(format!(
                "File not found: {}",
                file_path
            )));
        }
        self.state.serve_files.insert(model_id, path);
        Ok(())
    }

    /// ADR-017: Verify ticket with monotonic counter check for NTP manipulation resistance.
    ///
    /// Rejects tickets with counter <= last accepted counter for the same issuer.
    /// Falls back to standard verification for legacy 4-field tickets (counter = None).
    ///
    /// # Arguments
    /// * `ticket` – The ticket string to verify.
    /// * `secret` – The HMAC secret key.
    /// * `issuer_peer_id` – The expected issuer peer ID (extracted from ticket and verified).
    pub fn verify_ticket_with_counter(
        &self,
        ticket: &str,
        secret: &SecureKey,
        issuer_peer_id: &str,
    ) -> Result<(), AetherError> {
        // First: standard HMAC and timestamp verification
        SecurityManager::verify_ticket(ticket, secret)?;

        // Second: check monotonic counter if present (ADR-017)
        let counter = SecurityManager::extract_counter(ticket)?;
        if let Some(cnt) = counter {
            match self.state.ticket_counters.entry(issuer_peer_id.to_string()) {
                dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                    let last_accepted = *entry.get();
                    if cnt <= last_accepted {
                        return Err(AetherError::SecurityError(format!(
                            "Ticket counter {} is not greater than last accepted {} (ADR-017)",
                            cnt, last_accepted
                        )));
                    }
                    entry.insert(cnt);
                }
                dashmap::mapref::entry::Entry::Vacant(entry) => {
                    entry.insert(cnt);
                }
            }
        }
        // If counter is None (legacy ticket), allow it (backward compatibility)
        Ok(())
    }

    // ── Zero-copy download ────────────────────────────────────────────────────

    pub fn download_model(
        &self,
        peer_ip: String,
        peer_port: u16,
        seeder_peer_id: String,
        ticket: String,
        expected_sha256: String,
        resume_from: u64,
        fd: i32,
    ) -> Result<(), AetherError> {
        if expected_sha256.trim().is_empty() {
            return Err(AetherError::SecurityError(
                "expected_sha256 is required for downloads".into(),
            ));
        }

        // ── Verify HMAC BEFORE reading any field from the ticket payload ──
        // The caller provides `seeder_peer_id` (known from the handshake)
        // so we look up the auth key without trusting the ticket contents.
        let peer_entry = self
            .state
            .peers
            .get(&seeder_peer_id)
            .ok_or(AetherError::PeerNotFound)?;

        SecurityManager::verify_ticket(&ticket, &peer_entry.keys.auth_key)?;

        // Only AFTER HMAC verification is it safe to parse the ticket.
        // Validate that the issuer in the ticket matches the expected seeder.
        let issuer_peer_id = SecurityManager::extract_issuer_peer_id(&ticket)?.to_string();
        if issuer_peer_id != seeder_peer_id {
            return Err(AetherError::SecurityError(
                "Ticket issuer does not match expected seeder peer ID".into(),
            ));
        }
        self.verify_ticket_with_counter(&ticket, &peer_entry.keys.auth_key, &issuer_peer_id)?;

        let transport_key = peer_entry.keys.transport_key.clone();
        let has_noise_key = peer_entry.keys.noise_remote_static_key.is_some();
        let self_id = self.get_self_peer_id();
        drop(peer_entry); // release DashMap reference

        if transport_encryption::is_noise_enabled() && has_noise_key {
            self.rt.block_on(establish_noise_session_on_state(
                &self.state,
                &peer_ip,
                peer_port,
                &self_id,
                &seeder_peer_id,
            ))?;
        }
        let noise_session = if transport_encryption::is_noise_enabled() && has_noise_key {
            get_noise_session_handle(&self.state, &seeder_peer_id)
        } else {
            None
        };

        self.rt.block_on(download_file_to_fd(
            peer_ip,
            peer_port,
            ticket,
            self_id,
            seeder_peer_id,
            noise_session,
            transport_key,
            expected_sha256,
            resume_from,
            fd,
        ))
    }

    // ── Surgical patching ─────────────────────────────────────────────────────

    /// ADR-003: Check available RAM before patching to prevent OOM.
    /// Returns Ok(()) if the device has enough RAM, Err otherwise.
    /// `old_file_size` and `patch_file_size` are the sizes of the input files.
    pub fn check_patch_ram_feasibility(
        &self,
        old_file_size: u64,
        patch_file_size: u64,
    ) -> Result<(), AetherError> {
        let total_needed = old_file_size.saturating_add(patch_file_size);
        // With mmap (ADR-006), physical RAM pressure is much lower, but we still
        // need a safety margin for the bspatch output buffer and OS overhead.
        // Require at least 50% of available RAM as headroom.
        let available_ram = get_available_ram();
        let threshold = (available_ram as f64 * 0.5) as u64;
        if total_needed > threshold {
            return Err(AetherError::PatchError(format!(
                "ADR-003: Insufficient RAM for patching. Need {} bytes, available threshold is {} bytes (50% of {} bytes available)",
                total_needed, threshold, available_ram
            )));
        }
        info!(
            "ADR-003: RAM check passed — need {} bytes, threshold {} bytes",
            total_needed, threshold
        );
        Ok(())
    }

    pub fn apply_patch(
        &self,
        old_fd: i32,
        patch_fd: i32,
        new_fd: i32,
        expected_patch_sha256: String,
        expected_output_sha256: String,
    ) -> Result<(), AetherError> {
        if expected_patch_sha256.trim().is_empty() || expected_output_sha256.trim().is_empty() {
            return Err(AetherError::SecurityError(
                "expected patch and output SHA-256 values are required".into(),
            ));
        }
        let handle = std::thread::spawn(move || {
            patcher::apply_patch_fds(
                old_fd,
                patch_fd,
                new_fd,
                &expected_patch_sha256,
                &expected_output_sha256,
            )
        });
        handle
            .join()
            .map_err(|_| AetherError::PatchError("Patch thread panicked".into()))?
    }

    // ── Decompression ─────────────────────────────────────────────────────────

    pub fn decompress_file(&self, compressed_fd: i32, output_fd: i32) -> Result<u64, AetherError> {
        std::thread::spawn(move || decompressor::decompress_zstd_fds(compressed_fd, output_fd))
            .join()
            .map_err(|_| AetherError::DecompressError("Decompress thread panicked".into()))?
    }

    // ── Manifest verification ─────────────────────────────────────────────────

    pub fn verify_manifest(
        &self,
        canonical_json: String,
        sig_hex: String,
        public_key_der: Vec<u8>,
    ) -> Result<bool, AetherError> {
        SecurityManager::verify_manifest(&canonical_json, &sig_hex, &public_key_der)?;
        Ok(true)
    }

    // ── Diagnostics ───────────────────────────────────────────────────────────

    /// Probe the TCP server on loopback to verify it is truly alive.
    ///
    /// Simply logging a string (as in v2.3.0) would return `Ok(())` even when
    /// the Tokio server task has silently crashed. Probing `127.0.0.1:<port>`
    /// exercises the actual server socket.
    pub fn heartbeat(&self) -> Result<(), AetherError> {
        // ADR-001: propagate poison as InternalError instead of unwrap()
        let port = self
            .bound_port
            .read()
            .map_err(|_| AetherError::InternalError("RwLock poisoned".into()))?
            .ok_or_else(|| AetherError::InternalError("Server not started".into()))?;

        let alive = self.rt.block_on(ping_peer("127.0.0.1", port));

        if alive {
            info!("Aether heartbeat ✓ (server alive on :{port})");
            Ok(())
        } else {
            tracing::error!("Aether heartbeat ✗ — server on :{port} not responding");
            Err(AetherError::NetworkError(format!(
                "Heartbeat failed: server on :{port} not responding"
            )))
        }
    }

    pub fn ping_peer(&self, peer_ip: String, peer_port: u16) -> Result<bool, AetherError> {
        Ok(self.rt.block_on(ping_peer(&peer_ip, peer_port)))
    }

    pub fn ping_peer_secure(
        &self,
        peer_ip: String,
        peer_port: u16,
        peer_id: String,
    ) -> Result<bool, AetherError> {
        let self_id = self.get_self_peer_id();
        self.rt.block_on(establish_noise_session_on_state(
            &self.state,
            &peer_ip,
            peer_port,
            &self_id,
            &peer_id,
        ))?;
        let session = get_noise_session_handle(&self.state, &peer_id)
            .ok_or_else(|| AetherError::SecurityError("Noise session unavailable".into()))?;
        Ok(self
            .rt
            .block_on(ping_peer_secure(&peer_ip, peer_port, &self_id, session)))
    }

    #[doc(hidden)]
    pub fn get_self_peer_id_for_test(&self) -> String {
        self.get_self_peer_id()
    }

    #[doc(hidden)]
    pub fn get_noise_static_public_key_for_test(&self) -> Vec<u8> {
        // ADR-001: test-only helper — expect() with clear message
        self.noise_static_public_key.read().expect("ADR-001: noise key read lock poisoned (test)").clone()
    }

    #[doc(hidden)]
    pub fn get_bound_port_for_test(&self) -> Option<u16> {
        // ADR-001: test-only helper — expect() with clear message
        *self.bound_port.read().expect("ADR-001: bound_port read lock poisoned (test)")
    }

    #[cfg(test)]
    fn has_file_registered_for_test(&self, model_id: &str) -> bool {
        self.state.serve_files.contains_key(model_id)
    }
}

fn get_noise_session_handle(
    state: &AppState,
    peer_id: &str,
) -> Option<Arc<Mutex<transport_encryption::NoiseSession>>> {
    let now = current_unix_secs();
    state.noise_sessions.get(peer_id).map(|entry| {
        entry.touch(now);
        entry.session.clone()
    })
}

async fn complete_noise_handshake_on_state(
    state: &AppState,
    peer_id: &str,
    response: Vec<u8>,
) -> Result<(), AetherError> {
    if response.is_empty() {
        return Err(AetherError::KeyExchangeFailed);
    }

    let session = get_noise_session_handle(state, peer_id).ok_or(AetherError::PeerNotFound)?;
    let mut guard = session.lock().await;
    transport_encryption::perform_handshake(&mut guard, &response)?;
    Ok(())
}

async fn establish_noise_session_on_state(
    state: &AppState,
    peer_ip: &str,
    peer_port: u16,
    self_peer_id: &str,
    peer_id: &str,
) -> Result<(), AetherError> {
    if let Some(session) = get_noise_session_handle(state, peer_id) {
        let guard = session.lock().await;
        if matches!(&*guard, transport_encryption::NoiseSession::Established(_)) {
            return Ok(());
        }
    }

    let remote_static_key = {
        let entry = state.peers.get(peer_id).ok_or(AetherError::PeerNotFound)?;
        entry
            .keys
            .noise_remote_static_key
            .clone()
            .ok_or(AetherError::KeyExchangeFailed)?
    };

    let mut session = transport_encryption::init_noise_initiator(&remote_static_key)?;
    let request = transport_encryption::perform_handshake(&mut session, &[])?;
    state
        .noise_sessions
        .insert(peer_id.to_string(), NoiseSessionEntry::new(session, current_unix_secs()));
    let response = network::perform_noise_handshake(
        peer_ip,
        peer_port,
        self_peer_id,
        request,
        Config::get_protocol_version(),
    )
    .await?;
    complete_noise_handshake_on_state(state, peer_id, response).await
}

// ── Axum handlers ─────────────────────────────────────────────────────────────

async fn download_handler(
    State(state): State<ServerState>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    // ── Rate limit ────────────────────────────────────────────────────────────
    let _permit = match state.app.download_limiter.try_acquire() {
        Ok(p) => p,
        Err(_) => return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response(),
    };

    // ── Auth ──────────────────────────────────────────────────────────────────
    let peer_id = match params.get("pid") {
        Some(id) => id.clone(),
        None => return (StatusCode::BAD_REQUEST, "Missing pid").into_response(),
    };

    // ── Per-peer rate limit ─────────────────────────────────────────────────
    // SECURITY: Prevent a single peer from exhausting all global download slots
    let now = current_unix_secs();
    let peer_limiter = if let Some(peer_ref) = state.app.peers.get(&peer_id) {
        peer_ref.value().limiter.touch(now);
        peer_ref.value().limiter.semaphore.clone()
    } else {
        let entry = state
            .app
            .unauth_limiters
            .entry(peer_id.clone())
            .or_insert_with(|| PeerLimiterEntry::new(now));
        entry.touch(now);
        entry.semaphore.clone()
    };
    let _peer_permit = match peer_limiter.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "Per-peer rate limit exceeded",
            )
                .into_response()
        }
    };

    let ticket_str = {
        let primary = headers.get(Config::get_header_key());
        let fallback = headers.get("X-Aether-Ticket");
        match primary.or(fallback) {
            Some(v) => v.to_str().unwrap_or("").to_owned(),
            None => return (StatusCode::BAD_REQUEST, "Missing auth ticket").into_response(),
        }
    };

    // ── Protocol version check (defense-in-depth) ───────────────────────────
    // Leecher sends X-Aether-Protocol header — reject if major version differs.
    if let Some(proto) = headers.get("X-Aether-Protocol") {
        if let Ok(peer_ver) = proto.to_str() {
            let local = Config::get_protocol_version();
            let local_major = local.split('.').next().unwrap_or("");
            let peer_major = peer_ver.split('.').next().unwrap_or("");
            if !peer_major.is_empty() && local_major != peer_major {
                tracing::warn!(
                    "Protocol mismatch from peer {}: local={} peer={}",
                    peer_id,
                    local,
                    peer_ver
                );
                return (StatusCode::BAD_REQUEST, "Incompatible protocol version").into_response();
            }
        }
    }

    let peer_ref = match state.app.peers.get(&peer_id) {
        Some(k) => k,
        None => return (StatusCode::FORBIDDEN, "Unknown peer identity").into_response(),
    };

    // ADR-015: Block peers with too many consecutive ticket verification failures.
    if let Some(failures) = state.app.ticket_verify_failures.get(&peer_id) {
        if failures.count >= Config::MAX_TICKET_VERIFY_FAILURES {
            tracing::warn!(
                "Peer {} blocked: {} consecutive ticket verify failures",
                peer_id,
                failures.count
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many authentication failures",
            )
                .into_response();
        }
    }

    if SecurityManager::verify_ticket(&ticket_str, &peer_ref.value().keys.auth_key).is_err() {
        record_ticket_verify_failure(&state.app, &peer_id);
        return (StatusCode::FORBIDDEN, "Invalid ticket").into_response();
    }

    let issuer_peer_id = match SecurityManager::extract_issuer_peer_id(&ticket_str) {
        Ok(issuer) => issuer.to_string(),
        Err(_) => return (StatusCode::BAD_REQUEST, "Malformed ticket payload").into_response(),
    };
    if let Err(_) = verify_ticket_with_counter_on_state(
        &state.app,
        &ticket_str,
        &peer_ref.value().keys.auth_key,
        &issuer_peer_id,
    ) {
        record_ticket_verify_failure(&state.app, &peer_id);
        return (StatusCode::FORBIDDEN, "Invalid ticket").into_response();
    }

    // ADR-015: Reset failure counter on successful verification
    state.app.ticket_verify_failures.remove(&peer_id);

    if let Err(e) = reject_replayed_ticket(&state.app.seen_tickets, &ticket_str) {
        tracing::warn!("Replay rejected for peer {}: {}", peer_id, e);
        return (StatusCode::FORBIDDEN, "Replay detected").into_response();
    }

    // Extract model_id only after the ticket has been authenticated.
    let model_id = match SecurityManager::extract_model_id(&ticket_str) {
        Ok(model_id) => model_id.to_string(),
        Err(_) => return (StatusCode::BAD_REQUEST, "Malformed ticket payload").into_response(),
    };

    // ADR-012: permissions are inside the unified PeerEntry
    let allowed = peer_ref.value().permissions.contains(&model_id);
    if !allowed {
        return (
            StatusCode::FORBIDDEN,
            "Peer is not authorized for this model",
        )
            .into_response();
    }

    // ── Resolve file ──────────────────────────────────────────────────────────
    let file_path = match state.app.serve_files.get(&model_id) {
        Some(p) => p.clone(),
        None => {
            return (StatusCode::NOT_FOUND, "No file registered for this model").into_response()
        }
    };

    // ── Open + stat ───────────────────────────────────────────────────────────
    let file_size = match std::fs::metadata(&file_path) {
        Ok(m) => m.len(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Cannot stat file").into_response(),
    };

    let file = match tokio::fs::File::open(&file_path).await {
        Ok(f) => f,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Cannot open file").into_response(),
    };
    let transport_key = peer_ref.value().keys.transport_key.clone();
    let noise_session = if transport_encryption::is_noise_enabled() {
        get_noise_session_handle(&state.app, &peer_id)
    } else {
        None
    };
    let chacha_nonce = if noise_session.is_none() {
        Some(SecurityManager::generate_random_nonce())
    } else {
        None
    };

    // ── Range header handling ─────────────────────────────────────────────────
    let range_header = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("bytes="))
        .and_then(|v| v.strip_suffix('-'))
        .and_then(|v| v.parse::<u64>().ok());

    if let Some(start) = range_header {
        if start >= file_size {
            // RFC 7233 §4.4 — 416 Range Not Satisfiable
            // ADR-001: unwrap_or_else with 500 fallback instead of bare unwrap()
            return axum::http::Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header("Content-Range", format!("bytes */{}", file_size))
                .body(Body::empty())
                .unwrap_or_else(|e| {
                    tracing::error!("ADR-001: Failed to build 416 response: {:?}", e);
                    let mut fb = axum::http::Response::new(Body::from("Internal response error"));
                    *fb.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    fb
                });
        }

        let content_len = file_size - start;
        let stream = encrypted_file_stream(
            file,
            start,
            content_len,
            &ticket_str,
            &transport_key,
            chacha_nonce.as_ref(),
            noise_session.clone(),
        );

        // ADR-001: unwrap_or_else with 500 fallback instead of bare unwrap()
        let mut builder = axum::http::Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(
                "Content-Range",
                format!("bytes {}-{}/{}", start, file_size - 1, file_size),
            );
        let encoded_len = if noise_session.is_some() {
            framed_noise_content_length(content_len)
        } else {
            content_len
        };
        builder = builder.header(header::CONTENT_LENGTH, encoded_len.to_string());
        let mut response = builder.body(Body::from_stream(stream)).unwrap_or_else(|e| {
            tracing::error!("ADR-001: Failed to build 206 response: {:?}", e);
            let mut fb = axum::http::Response::new(Body::from("Internal response error"));
            *fb.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            fb
        });
        if noise_session.is_some() {
            response.headers_mut().insert(
                header::HeaderName::from_static("x-aether-encrypted"),
                header::HeaderValue::from_static("noise-nk"),
            );
        } else {
            let nonce_hex = hex::encode(chacha_nonce.expect("nonce must exist for chacha20 fallback"));
            response.headers_mut().insert(
                header::HeaderName::from_static("x-aether-encrypted"),
                header::HeaderValue::from_static("chacha20"),
            );
            if let Ok(value) = header::HeaderValue::from_str(&nonce_hex) {
                response.headers_mut().insert(
                    header::HeaderName::from_static("x-aether-nonce"),
                    value,
                );
            }
        }
        return response;
    }

    // ── Full file response ────────────────────────────────────────────────────
    let stream = encrypted_file_stream(
        file,
        0,
        file_size,
        &ticket_str,
        &transport_key,
        chacha_nonce.as_ref(),
        noise_session.clone(),
    );
    // ADR-001: unwrap_or_else with 500 fallback instead of bare unwrap()
    let mut builder = axum::http::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream");
    let encoded_len = if noise_session.is_some() {
        framed_noise_content_length(file_size)
    } else {
        file_size
    };
    builder = builder.header(header::CONTENT_LENGTH, encoded_len.to_string());
    let mut response = builder.body(Body::from_stream(stream)).unwrap_or_else(|e| {
        tracing::error!("ADR-001: Failed to build 200 response: {:?}", e);
        let mut fb = axum::http::Response::new(Body::from("Internal response error"));
        *fb.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        fb
    });
    if noise_session.is_some() {
        response.headers_mut().insert(
            header::HeaderName::from_static("x-aether-encrypted"),
            header::HeaderValue::from_static("noise-nk"),
        );
    } else {
        let nonce_hex = hex::encode(chacha_nonce.expect("nonce must exist for chacha20 fallback"));
        response.headers_mut().insert(
            header::HeaderName::from_static("x-aether-encrypted"),
            header::HeaderValue::from_static("chacha20"),
        );
        if let Ok(value) = header::HeaderValue::from_str(&nonce_hex) {
            response.headers_mut().insert(
                header::HeaderName::from_static("x-aether-nonce"),
                value,
            );
        }
    }
    response
}

async fn ping_handler(
    State(state): State<ServerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Some(peer_id) = params.get("pid") {
        // ADR-020: Secure ping requires peer to remain in live authorization graph
        if !state.app.peers.contains_key(peer_id) {
            return (StatusCode::FORBIDDEN, "Unknown peer identity").into_response();
        }
        if let Some(session) = get_noise_session_handle(&state.app, peer_id) {
            let mut guard = session.lock().await;
            match transport_encryption::encrypt(
                &mut guard,
                Config::get_protocol_version().as_bytes(),
            ) {
                Ok(ciphertext) => {
                    let mut response = axum::http::Response::new(Body::from(ciphertext));
                    *response.status_mut() = StatusCode::OK;
                    response.headers_mut().insert(
                        header::CONTENT_TYPE,
                        header::HeaderValue::from_static("application/octet-stream"),
                    );
                    response.headers_mut().insert(
                        header::HeaderName::from_static("x-aether-encrypted"),
                        header::HeaderValue::from_static("noise-nk"),
                    );
                    return response;
                }
                Err(e) => {
                    tracing::warn!("Noise ping encryption failed for peer {}: {}", peer_id, e);
                }
            }
        }
    }

    (StatusCode::OK, Config::get_protocol_version()).into_response()
}

async fn identity_handler(State(state): State<ServerState>) -> impl IntoResponse {
    axum::Json((*state.identity).clone())
}

async fn noise_handshake_handler(
    State(state): State<ServerState>,
    Query(params): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    let peer_id = match params.get("pid") {
        Some(id) => id.clone(),
        None => return (StatusCode::BAD_REQUEST, "Missing pid").into_response(),
    };
    if !state.app.peers.contains_key(&peer_id) {
        return (StatusCode::FORBIDDEN, "Unknown peer identity").into_response();
    }

    let private_key = match state.noise_static_private_key.read() {
        Ok(g) => g.0.clone(),
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Noise key unavailable").into_response()
        }
    };

    let mut session = match transport_encryption::init_noise_responder(&private_key) {
        Ok(session) => session,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Noise init failed").into_response(),
    };

    let response = match transport_encryption::perform_handshake(&mut session, &body) {
        Ok(response) => response,
        Err(_) => return (StatusCode::FORBIDDEN, "Invalid handshake").into_response(),
    };

    state
        .app
        .noise_sessions
        .insert(peer_id, NoiseSessionEntry::new(session, current_unix_secs()));

    let mut handshake_response = axum::http::Response::new(Body::from(response));
    *handshake_response.status_mut() = StatusCode::OK;
    handshake_response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/octet-stream"),
    );
    handshake_response
}

fn reject_replayed_ticket(
    seen_tickets: &DashMap<String, u64>,
    ticket: &str,
) -> Result<(), AetherError> {
    let now = current_unix_secs();
    let ttl = Config::TICKET_REPLAY_TTL_SECS;

    let digest = hex::encode(Sha256::digest(ticket.as_bytes()));
    match seen_tickets.entry(digest) {
        dashmap::mapref::entry::Entry::Occupied(mut e) => {
            // Entry may be expired but not yet evicted by the background task.
            // Atomic update: holds shard write lock throughout.
            if now.saturating_sub(*e.get()) > ttl {
                e.insert(now);
                Ok(())
            } else {
                Err(AetherError::SecurityError("Ticket replay detected".into()))
            }
        }
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(now);
            Ok(())
        }
    }
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn verify_ticket_with_counter_on_state(
    state: &AppState,
    ticket: &str,
    secret: &SecureKey,
    issuer_peer_id: &str,
) -> Result<(), AetherError> {
    SecurityManager::verify_ticket(ticket, secret)?;
    if let Some(counter) = SecurityManager::extract_counter(ticket)? {
        match state.ticket_counters.entry(issuer_peer_id.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                let last_accepted = *entry.get();
                if counter <= last_accepted {
                    return Err(AetherError::SecurityError(format!(
                        "Ticket counter {} is not greater than last accepted {} (ADR-017)",
                        counter, last_accepted
                    )));
                }
                entry.insert(counter);
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(counter);
            }
        }
    }
    Ok(())
}

fn record_ticket_verify_failure(state: &AppState, peer_id: &str) {
    let now = current_unix_secs();
    state
        .ticket_verify_failures
        .entry(peer_id.to_string())
        .and_modify(|entry| {
            entry.count = entry.count.saturating_add(1);
            entry.last_failure_unix_secs = now;
        })
        .or_insert(TicketVerifyFailureEntry {
            count: 1,
            last_failure_unix_secs: now,
        });
}

fn framed_noise_content_length(plaintext_len: u64) -> u64 {
    let chunk_size = 64 * 1024u64;
    let frame_overhead = (4 + 16) as u64;
    let frames = if plaintext_len == 0 {
        0
    } else {
        (plaintext_len + chunk_size - 1) / chunk_size
    };
    plaintext_len + frames * frame_overhead
}

fn encrypted_file_stream(
    mut file: tokio::fs::File,
    start: u64,
    remaining_len: u64,
    ticket: &str,
    transport_key: &SecureKey,
    chacha_nonce: Option<&[u8; 12]>,
    noise_session: Option<Arc<Mutex<transport_encryption::NoiseSession>>>,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static {
    // Extract model_id from ticket for HKDF salt (not the ticket itself).
    let model_id = match SecurityManager::extract_model_id(ticket) {
        Ok(model_id) => model_id.to_string(),
        Err(e) => {
            let err = std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string());
            return stream::once(async move { Err(err) }).boxed();
        }
    };
    let transport_key = transport_key.clone();
    let chacha_nonce = chacha_nonce.copied();
    let stream: BoxStream<'static, Result<Bytes, std::io::Error>> = try_stream! {
        file.seek(std::io::SeekFrom::Start(start)).await?;
        let mut sent = 0u64;
        let mut buf = vec![0u8; 64 * 1024];
        let mut cipher = match chacha_nonce {
            Some(nonce) => {
                let session_key = SecurityManager::derive_session_stream_key(&transport_key, &model_id)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                let mut cipher = ChaCha20::new((&session_key).into(), (&nonce).into());
                cipher.seek(start);
                Some(cipher)
            }
            None => None,
        };
        while sent < remaining_len {
            // ADR-001: safe fallback instead of bare unwrap() — value is clamped by .min(buf.len())
            // so it always fits in usize, but use unwrap_or for explicit safety
            let want = usize::try_from((remaining_len - sent).min(buf.len() as u64)).unwrap_or(buf.len());
            let n = file.read(&mut buf[..want]).await?;
            if n == 0 {
                break;
            }
            let mut chunk = buf[..n].to_vec();
            if let Some(ref mut cipher) = cipher {
                cipher.apply_keystream(&mut chunk);
            } else if let Some(ref session) = noise_session {
                let mut guard = session.lock().await;
                let ciphertext = transport_encryption::encrypt(&mut guard, &chunk)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                let mut framed = Vec::with_capacity(4 + ciphertext.len());
                framed.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
                framed.extend_from_slice(&ciphertext);
                chunk = framed;
            }
            sent += n as u64;
            yield Bytes::from(chunk);
        }
    }
    .boxed();
    stream
}

/// ADR-003: Query available physical RAM in bytes.
/// Uses `/proc/meminfo` on Linux/Android and `sysctl` on macOS/iOS.
fn get_available_ram() -> u64 {
    #[cfg(target_os = "linux")]
    {
        // Parse MemAvailable from /proc/meminfo (kB → bytes)
        if let Ok(data) = std::fs::read_to_string("/proc/meminfo") {
            for line in data.lines() {
                if line.starts_with("MemAvailable:") {
                    let kb: u64 = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    return kb * 1024;
                }
            }
        }
        // Fallback: assume 2GB if we can't read meminfo
        2 * 1024 * 1024 * 1024
    }

    #[cfg(all(
        not(target_os = "linux"),
        not(any(target_os = "ios", target_os = "macos"))
    ))]
    {
        // macOS/iOS: use sysctl hw.memsize as rough total, assume 50% available
        // This is conservative; on iOS the actual free memory is lower but
        // the OS will jetsam before we hit this threshold anyway.
        let mut size: libc::size_t = 0;
        let mut len = std::mem::size_of::<libc::size_t>();
        let mib = [libc::CTL_HW, libc::HW_MEMSIZE];
        let result = unsafe {
            libc::sysctl(
                mib.as_ptr() as *mut libc::c_int,
                2,
                &mut size as *mut _ as *mut libc::c_void,
                &mut len as *mut _ as *mut libc::c_void,
                std::ptr::null_mut(),
                0,
            )
        };
        if result == 0 {
            // Assume 50% of total RAM is available as a conservative estimate
            (size as u64 * 50) / 100
        } else {
            // Fallback: assume 2GB
            2 * 1024 * 1024 * 1024
        }
    }

    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        let host = unsafe { libc::mach_host_self() };
        let mut page_size: libc::vm_size_t = 0;
        let page_size_result = unsafe { libc::host_page_size(host, &mut page_size) };
        if page_size_result == libc::KERN_SUCCESS {
            let mut stats = std::mem::MaybeUninit::<libc::vm_statistics64_data_t>::zeroed();
            let mut count = libc::HOST_VM_INFO64_COUNT;
            let stats_result = unsafe {
                libc::host_statistics64(
                    host,
                    libc::HOST_VM_INFO64,
                    stats.as_mut_ptr() as libc::host_info64_t,
                    &mut count,
                )
            };
            if stats_result == libc::KERN_SUCCESS {
                let stats = unsafe { stats.assume_init() };
                let available_pages = stats
                    .free_count
                    .saturating_add(stats.inactive_count)
                    .saturating_add(stats.speculative_count);
                return u64::from(available_pages).saturating_mul(u64::from(page_size));
            }
        }

        // Fallback: use a more conservative fraction of total RAM when Mach APIs fail.
        let mut size: libc::size_t = 0;
        let mut len = std::mem::size_of::<libc::size_t>();
        let mib = [libc::CTL_HW, libc::HW_MEMSIZE];
        let result = unsafe {
            libc::sysctl(
                mib.as_ptr() as *mut libc::c_int,
                2,
                &mut size as *mut _ as *mut libc::c_void,
                &mut len as *mut _ as *mut libc::c_void,
                std::ptr::null_mut(),
                0,
            )
        };
        if result == 0 {
            (size as u64 / 4).max(256 * 1024 * 1024)
        } else {
            512 * 1024 * 1024
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;

    #[test]
    fn engine_creates_unique_default_peer_id() {
        let e1 = AetherEngine::new().unwrap();
        let e2 = AetherEngine::new().unwrap();
        assert_ne!(e1.get_self_peer_id(), e2.get_self_peer_id());
    }

    #[test]
    fn set_self_peer_id_persists() {
        let engine = AetherEngine::new().unwrap();
        engine.set_self_peer_id("my-node-uuid".into());
        assert_eq!(engine.get_self_peer_id(), "my-node-uuid");
    }

    #[test]
    fn canonicalize_json_is_sorted_and_stable() {
        let engine = AetherEngine::new().unwrap();
        let canonical = engine
            .canonicalize_json(r#"{"z":"last","a":"first","full":{"url":"x","size":1}}"#.into())
            .unwrap();
        assert_eq!(
            canonical,
            r#"{"a":"first","full":{"size":1,"url":"x"},"z":"last"}"#
        );
    }

    #[test]
    fn register_peer_key_wrong_length_fails() {
        let engine = AetherEngine::new().unwrap();
        let result = engine.register_peer_key("peer-1".into(), vec![0u8; 16]);
        assert!(matches!(result, Err(AetherError::KeyExchangeFailed)));
    }

    #[test]
    fn register_peer_key_correct_length_ok() {
        let engine = AetherEngine::new().unwrap();
        assert!(engine
            .register_peer_key("peer-1".into(), vec![0u8; 32])
            .is_ok());
    }

    #[test]
    fn engine_generates_noise_static_keypair() {
        let engine = AetherEngine::new().unwrap();
        let public = engine.get_noise_static_public_key_for_test();
        assert_eq!(
            public.len(),
            transport_encryption::noise_static_public_key_len()
        );
        assert_eq!(
            engine.noise_static_private_key.read().unwrap().0.len(),
            transport_encryption::noise_static_public_key_len()
        );
    }

    #[test]
    fn register_peer_noise_static_key_requires_known_peer() {
        let engine = AetherEngine::new().unwrap();
        let result = engine.register_peer_noise_static_key("missing".into(), vec![7u8; 32]);
        assert!(matches!(result, Err(AetherError::PeerNotFound)));
    }

    #[test]
    fn register_peer_key_preserves_noise_static_key() {
        let engine = AetherEngine::new().unwrap();
        engine
            .register_peer_key("peer-a".into(), vec![0xAAu8; 32])
            .unwrap();
        engine
            .register_peer_noise_static_key("peer-a".into(), vec![0x11u8; 32])
            .unwrap();

        engine
            .register_peer_key("peer-a".into(), vec![0xBBu8; 32])
            .unwrap();

        let peer = engine.state.peers.get("peer-a").unwrap();
        assert_eq!(
            peer.keys.noise_remote_static_key.as_deref(),
            Some([0x11u8; 32].as_slice())
        );
    }

    #[test]
    fn hkdf_produces_different_key_than_raw_input() {
        // The derived key must differ from the raw ECDH secret.
        let raw = vec![0xABu8; 32];
        let derived = SecurityManager::derive_hmac_key(&raw).unwrap();
        assert_ne!(derived.as_ref(), raw.as_slice());
    }

    #[test]
    fn hkdf_is_deterministic() {
        let raw = vec![0x42u8; 32];
        let d1 = SecurityManager::derive_hmac_key(&raw).unwrap();
        let d2 = SecurityManager::derive_hmac_key(&raw).unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn verify_manifest_invalid_sig_fails() {
        let engine = AetherEngine::new().unwrap();
        let result =
            engine.verify_manifest(r#"{"id":"test"}"#.into(), "deadbeef".into(), vec![0u8; 65]);
        assert!(result.is_err());
    }

    #[test]
    fn seed_manifest_sequence_rejects_zero() {
        let engine = AetherEngine::new().unwrap();
        let result = engine.seed_manifest_sequence("model-a".into(), 0);
        assert!(matches!(result, Err(AetherError::SecurityError(_))));
    }

    #[test]
    fn seed_manifest_sequence_keeps_highest_value() {
        let engine = AetherEngine::new().unwrap();
        engine.seed_manifest_sequence("model-a".into(), 5).unwrap();
        engine.seed_manifest_sequence("model-a".into(), 3).unwrap();
        let stored = engine.state.manifest_sequences.get("model-a").map(|v| *v);
        assert_eq!(stored, Some(5));
    }

    #[test]
    fn verify_ticket_with_counter_rejects_reused_counter() {
        let engine = AetherEngine::new().unwrap();
        let raw = vec![0x44u8; 32];
        let derived = SecurityManager::derive_hmac_key(&raw).unwrap();
        let secret = SecureKey(derived.to_vec());
        let ticket =
            SecurityManager::generate_ticket_with_counter("m", "1", "peer-a", 7, &secret).unwrap();

        engine
            .verify_ticket_with_counter(&ticket, &secret, "peer-a")
            .unwrap();
        let reused = engine.verify_ticket_with_counter(&ticket, &secret, "peer-a");
        assert!(matches!(reused, Err(AetherError::SecurityError(_))));
    }

    #[test]
    fn ticket_verify_failure_entry_tracks_count_and_timestamp() {
        let engine = AetherEngine::new().unwrap();
        record_ticket_verify_failure(&engine.state, "peer-a");
        record_ticket_verify_failure(&engine.state, "peer-a");

        let failure = engine.state.ticket_verify_failures.get("peer-a").unwrap();
        assert_eq!(failure.count, 2);
        assert!(failure.last_failure_unix_secs <= current_unix_secs());
    }

    #[test]
    fn heartbeat_fails_before_server_starts() {
        let engine = AetherEngine::new().unwrap();
        // bound_port is None → heartbeat returns InternalError
        assert!(engine.heartbeat().is_err());
    }

    #[test]
    fn heartbeat_ok_after_server_starts() {
        let engine = AetherEngine::new().unwrap();
        engine
            .set_self_identity_public_key(vec![0x04u8; 65])
            .unwrap();
        engine.start_server().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(engine.heartbeat().is_ok());
        engine.stop_server();
    }

    #[test]
    fn heartbeat_fails_after_server_stops() {
        let engine = AetherEngine::new().unwrap();
        engine
            .set_self_identity_public_key(vec![0x04u8; 65])
            .unwrap();
        engine.start_server().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        engine.stop_server();
        std::thread::sleep(std::time::Duration::from_millis(50));
        // bound_port is reset to None on stop
        assert!(engine.heartbeat().is_err());
    }

    #[test]
    fn replayed_ticket_is_rejected() {
        let raw = vec![0x11u8; 32];
        let derived = SecurityManager::derive_hmac_key(&raw).unwrap();
        let ticket =
            SecurityManager::generate_ticket("m", "1", "seeder-1", &SecureKey(derived.to_vec()))
                .unwrap();
        let seen = DashMap::new();

        assert!(reject_replayed_ticket(&seen, &ticket).is_ok());
        assert!(reject_replayed_ticket(&seen, &ticket).is_err());
    }

    #[test]
    fn expired_occupied_entry_allows_reuse() {
        // ADR-005: expired entries are no longer evicted inline.
        // The Occupied branch checks TTL and allows re-use if expired.
        let seen = DashMap::new();
        let ticket = "test-ticket-expired";
        let digest = hex::encode(Sha256::digest(ticket.as_bytes()));

        // Insert with expired timestamp
        seen.insert(
            digest.clone(),
            current_unix_secs() - Config::TICKET_REPLAY_TTL_SECS - 1,
        );

        // Same ticket should be allowed (expired → treated as fresh)
        assert!(reject_replayed_ticket(&seen, ticket).is_ok());

        // Timestamp should be updated to a recent value
        let updated_ts = seen.get(&digest).unwrap();
        assert!(*updated_ts > current_unix_secs() - 5);
    }

    #[test]
    fn fresh_occupied_entry_still_rejected() {
        // Immediate replay of a fresh ticket must still be rejected.
        let seen = DashMap::new();
        let ticket = "test-ticket-fresh";

        // First use: OK
        assert!(reject_replayed_ticket(&seen, ticket).is_ok());
        // Immediate replay: rejected
        assert!(reject_replayed_ticket(&seen, ticket).is_err());
    }

    #[test]
    fn expired_entry_remains_until_background_eviction() {
        // ADR-005: without inline retain(), expired entries stay in the map
        // until the background eviction task cleans them up.
        let seen = DashMap::new();
        seen.insert(
            "old-key".into(),
            current_unix_secs() - Config::TICKET_REPLAY_TTL_SECS - 1,
        );

        // A fresh ticket (different digest) should succeed
        assert!(reject_replayed_ticket(&seen, "fresh-ticket").is_ok());

        // The expired "old-key" still exists — will be cleaned by background task
        assert!(seen.contains_key("old-key"));
    }

    #[test]
    fn download_requires_expected_sha256() {
        use std::os::unix::io::IntoRawFd;
        use tempfile::NamedTempFile;

        let engine = AetherEngine::new().unwrap();
        let file = NamedTempFile::new().unwrap();
        let fd = std::fs::OpenOptions::new()
            .write(true)
            .open(file.path())
            .unwrap()
            .into_raw_fd();

        let result = engine.download_model(
            "127.0.0.1".into(),
            1,
            "unknown-seeder".into(),
            "ticket".into(),
            "".into(),
            0,
            fd,
        );
        let _ = unsafe { std::fs::File::from_raw_fd(fd) };
        assert!(matches!(result, Err(AetherError::SecurityError(_))));
    }

    /// ADR-011: revoke_peer removes peer keys and permissions.
    #[test]
    fn revoke_peer_removes_keys_and_permissions() {
        let engine = AetherEngine::new().unwrap();
        let secret = vec![0xAAu8; 32];
        engine
            .register_peer_key("peer-a".into(), secret.clone())
            .unwrap();
        engine
            .grant_peer_model_access("peer-a".into(), "model-x".into())
            .unwrap();

        // Peer exists before revocation
        assert!(engine.state.peers.contains_key("peer-a"));

        engine.revoke_peer("peer-a".into()).unwrap();

        // Peer gone after revocation (ADR-012: single atomic remove)
        assert!(!engine.state.peers.contains_key("peer-a"));
    }

    /// ADR-011: revoke_peer returns PeerNotFound for unknown peer.
    #[test]
    fn revoke_peer_unknown_returns_error() {
        let engine = AetherEngine::new().unwrap();
        let result = engine.revoke_peer("nonexistent".into());
        assert!(matches!(result, Err(AetherError::PeerNotFound)));
    }

    /// is_server_running returns false on fresh engine, true after start.
    #[test]
    fn is_server_running_reflects_bound_port() {
        let engine = AetherEngine::new().unwrap();
        engine
            .set_self_identity_public_key(vec![0x04u8; 65])
            .unwrap();
        assert!(!engine.is_server_running());
        let _port = engine.start_server().unwrap();
        assert!(engine.is_server_running());
        engine.stop_server();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!engine.is_server_running());
    }

    /// get_protocol_version returns the config value.
    #[test]
    fn get_protocol_version_returns_config_value() {
        let engine = AetherEngine::new().unwrap();
        assert_eq!(
            engine.get_protocol_version(),
            Config::get_protocol_version()
        );
    }

    /// validate_peer_protocol accepts same major, rejects different major and blank.
    #[test]
    fn validate_peer_protocol_accepts_same_major() {
        let engine = AetherEngine::new().unwrap();
        // Same version → OK
        assert!(engine
            .validate_peer_protocol("v2.3-swarm-fixed".into())
            .is_ok());
        // Same major, different minor → OK
        assert!(engine.validate_peer_protocol("v2.4-beta".into()).is_ok());
    }

    #[test]
    fn validate_peer_protocol_rejects_different_major() {
        let engine = AetherEngine::new().unwrap();
        let result = engine.validate_peer_protocol("v3.0-swarm-fixed".into());
        assert!(matches!(result, Err(AetherError::SecurityError(_))));
    }

    #[test]
    fn validate_peer_protocol_rejects_blank() {
        let engine = AetherEngine::new().unwrap();
        let result = engine.validate_peer_protocol("".into());
        assert!(matches!(result, Err(AetherError::SecurityError(_))));
    }

    #[test]
    fn register_file_nonexistent_returns_error() {
        let engine = AetherEngine::new().unwrap();
        let result =
            engine.register_file_for_serving("model-x".into(), "/nonexistent/path/file.zst".into());
        assert!(result.is_err());
    }

    /// H-05 regression: stop_server() on a fresh engine must NOT poison
    /// the next start_server(). With notify_waiters() (ADR-005 Cycle #2),
    /// calling stop_server() before start_server() stores no permit.
    #[test]
    fn stop_server_on_fresh_engine_does_not_poison_start() {
        let engine = AetherEngine::new().unwrap();
        engine
            .set_self_identity_public_key(vec![0x04u8; 65])
            .unwrap();

        // Call stop_server() on a fresh engine (no server running).
        // This used to poison Notify with notify_one(), causing the next
        // start_server() to shut down immediately.
        engine.stop_server();

        // Now start the server — it must succeed and stay alive.
        let port = engine
            .start_server()
            .expect("start_server must succeed after stop_server on fresh engine");
        assert_ne!(port, 0);

        std::thread::sleep(std::time::Duration::from_millis(100));

        // Heartbeat must pass — server is alive.
        assert!(
            engine.heartbeat().is_ok(),
            "server must be alive after start_server following stop_server on fresh engine"
        );

        engine.stop_server();
    }

    #[test]
    fn register_and_serve_file_roundtrip() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut tmp = NamedTempFile::new().unwrap();
        let content = b"aether seeder payload for testing";
        tmp.write_all(content).unwrap();
        tmp.flush().unwrap();

        let engine = AetherEngine::new().unwrap();
        engine
            .register_file_for_serving("test-model".into(), tmp.path().to_str().unwrap().into())
            .unwrap();

        // Verify it was stored
        assert!(engine.has_file_registered_for_test("test-model"));
    }

    #[test]
    fn establish_noise_session_enables_secure_ping() {
        let seeder = AetherEngine::new().unwrap();
        let leecher = AetherEngine::new().unwrap();

        seeder.set_self_peer_id("seeder".into());
        leecher.set_self_peer_id("leecher".into());
        seeder
            .set_self_identity_public_key(vec![0x04u8; 65])
            .unwrap();

        let shared_secret = vec![0x33u8; 32];
        seeder
            .register_peer_key("leecher".into(), shared_secret.clone())
            .unwrap();
        leecher
            .register_peer_key("seeder".into(), shared_secret)
            .unwrap();
        leecher
            .register_peer_noise_static_key(
                "seeder".into(),
                seeder.get_noise_static_public_key_for_test(),
            )
            .unwrap();

        let port = seeder.start_server().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        leecher
            .establish_noise_session("127.0.0.1".into(), port, "seeder".into())
            .unwrap();
        assert!(leecher
            .ping_peer_secure("127.0.0.1".into(), port, "seeder".into())
            .unwrap());

        seeder.stop_server();
    }

    #[test]
    fn download_model_uses_noise_session_when_available() {
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::os::fd::IntoRawFd;
        use tempfile::NamedTempFile;

        let seeder = AetherEngine::new().unwrap();
        let leecher = AetherEngine::new().unwrap();

        seeder.set_self_peer_id("seeder".into());
        leecher.set_self_peer_id("leecher".into());
        seeder
            .set_self_identity_public_key(vec![0x04u8; 65])
            .unwrap();

        let shared_secret = vec![0x55u8; 32];
        seeder
            .register_peer_key("leecher".into(), shared_secret.clone())
            .unwrap();
        seeder
            .grant_peer_model_access("leecher".into(), "model-a".into())
            .unwrap();
        leecher
            .register_peer_key("seeder".into(), shared_secret.clone())
            .unwrap();
        leecher
            .register_peer_noise_static_key(
                "seeder".into(),
                seeder.get_noise_static_public_key_for_test(),
            )
            .unwrap();

        let mut src = NamedTempFile::new().unwrap();
        let payload = b"noise-backed download payload";
        src.write_all(payload).unwrap();
        src.flush().unwrap();
        seeder
            .register_file_for_serving("model-a".into(), src.path().to_str().unwrap().into())
            .unwrap();

        let port = seeder.start_server().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        let derived = SecurityManager::derive_hmac_key(&shared_secret).unwrap();
        let ticket = SecurityManager::generate_ticket(
            "model-a",
            "1",
            "seeder",
            &SecureKey(derived.to_vec()),
        )
        .unwrap();
        let expected_sha = {
            let mut hasher = Sha256::new();
            hasher.update(payload);
            hex::encode(hasher.finalize())
        };

        let out = NamedTempFile::new().unwrap();
        let fd = std::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .open(out.path())
            .unwrap()
            .into_raw_fd();

        leecher
            .download_model(
                "127.0.0.1".into(),
                port,
                "seeder".into(),
                ticket,
                expected_sha,
                0,
                fd,
            )
            .unwrap();

        let mut out_file = std::fs::OpenOptions::new()
            .read(true)
            .open(out.path())
            .unwrap();
        out_file.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = Vec::new();
        out_file.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, payload);
        assert!(leecher.state.noise_sessions.contains_key("seeder"));

        seeder.stop_server();
    }
}
