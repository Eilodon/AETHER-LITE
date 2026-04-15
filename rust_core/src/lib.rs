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

use crate::canonical_json::canonicalize_json;
use crate::config::Config;
use crate::error::AetherError;
use crate::network::{download_file_to_fd, ping_peer};
use crate::security::{SecureKey, SecurityManager};
use async_stream::try_stream;
use serde::Serialize;

use axum::{
    body::{Body, Bytes},
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::info;

uniffi::include_scaffolding!("aether");

// ── Shared server state ───────────────────────────────────────────────────────

struct AppState {
    peer_keys: DashMap<String, PeerKeys>,
    peer_permissions: DashMap<String, HashSet<String>>,
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
}

#[derive(Clone)]
struct PeerKeys {
    auth_key: SecureKey,
    transport_key: SecureKey,
}

#[derive(Clone, Serialize)]
struct IdentityState {
    peer_id: String,
    public_key_hex: String,
    protocol_version: String,
}

#[derive(Clone)]
struct ServerState {
    app: Arc<AppState>,
    identity: Arc<IdentityState>,
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
    /// Port assigned by the OS when `start_server()` is called.
    /// Used by `heartbeat()` to probe the actual TCP server.
    bound_port: Arc<RwLock<Option<u16>>>,
}

impl Default for AetherEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AetherEngine {
    pub fn new() -> Self {
        #[cfg(target_os = "android")]
        tracing_android::init_logging("aether_core", tracing::Level::INFO);

        #[cfg(not(target_os = "android"))]
        {
            use tracing_subscriber::fmt;
            let _ = fmt::try_init();
        }

        let default_id = uuid::Uuid::new_v4().to_string();

        Self {
            state: Arc::new(AppState {
                peer_keys: DashMap::new(),
                peer_permissions: DashMap::new(),
                seen_tickets: DashMap::new(),
                shutdown_token: RwLock::new(CancellationToken::new()),
                download_limiter: Arc::new(Semaphore::new(Config::MAX_CONCURRENT_DOWNLOADS)),
                serve_files: DashMap::new(),
            }),
            rt: Arc::new(Runtime::new().expect("Tokio runtime init failed")),
            self_peer_id: Arc::new(RwLock::new(default_id)),
            self_public_key_x962: Arc::new(RwLock::new(Vec::new())),
            bound_port: Arc::new(RwLock::new(None)),
        }
    }

    // ── Identity ──────────────────────────────────────────────────────────────

    pub fn set_self_peer_id(&self, peer_id: String) {
        *self.self_peer_id.write().unwrap() = peer_id;
    }

    pub fn set_self_identity_public_key(&self, public_key_x962: Vec<u8>) -> Result<(), AetherError> {
        if public_key_x962.len() != 65 || public_key_x962.first().copied() != Some(0x04) {
            return Err(AetherError::KeyExchangeFailed);
        }
        *self.self_public_key_x962.write().unwrap() = public_key_x962;
        Ok(())
    }

    fn get_self_peer_id(&self) -> String {
        self.self_peer_id.read().unwrap().clone()
    }

    // ── Server lifecycle ──────────────────────────────────────────────────────

    pub fn start_server(&self) -> Result<u16, AetherError> {
        // ── Invariant: identity public key must be set before serving ────────
        // Prevents serving an identity document with an empty public_key_hex
        // which would break ECDH handshake for any peer that trusts this node.
        if self.self_public_key_x962.read().unwrap().is_empty() {
            return Err(AetherError::InternalError(
                "set_self_identity_public_key must be called before start_server".into(),
            ));
        }

        // ADR-007: create a fresh CancellationToken for this server session.
        // Replaces the old Arc&lt;Notify&gt; pattern — no permit accumulation risk.
        let token = CancellationToken::new();
        *self.state.shutdown_token.write().unwrap() = token.clone();
        let child = token.child_token();
        let app_state = self.state.clone();
        let bound_port = self.bound_port.clone();
        let self_peer_id = self.self_peer_id.clone();
        let self_public_key_x962 = self.self_public_key_x962.clone();
        let (tx, rx) = std::sync::mpsc::channel::<Result<u16, AetherError>>();

        self.rt.spawn(async move {
            let state = ServerState {
                app: app_state,
                identity: Arc::new(IdentityState {
                peer_id: self_peer_id.read().unwrap().clone(),
                public_key_hex: hex::encode(self_public_key_x962.read().unwrap().clone()),
                protocol_version: Config::get_protocol_version().to_string(),
                }),
            };
            let app = Router::new()
                .route("/download", get(download_handler))
                .route("/ping", get(ping_handler))
                .route("/identity", get(identity_handler))
                .with_state(state);

            match tokio::net::TcpListener::bind(Config::BIND_ADDRESS).await {
                Ok(l) => {
                    let port = l.local_addr().unwrap().port();
                    *bound_port.write().unwrap() = Some(port);
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
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {
                        let now = current_unix_secs();
                        let ttl = Config::TICKET_REPLAY_TTL_SECS;
                        eviction_state.seen_tickets
                            .retain(|_, seen_at| now.saturating_sub(*seen_at) <= ttl);
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
        self.state.shutdown_token.read().unwrap().cancel();
        *self.bound_port.write().unwrap() = None;
    }

    /// Returns `true` if the server is currently bound to a port.
    /// Cheap O(1) check — reads in-memory state only, no network probe.
    pub fn is_server_running(&self) -> bool {
        self.bound_port.read().unwrap().is_some()
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
        self.state.peer_keys.insert(
            peer_id,
            PeerKeys {
                auth_key: SecureKey(auth_key.to_vec()),
                transport_key: SecureKey(transport_key.to_vec()),
            },
        );
        Ok(())
    }

    /// Grant a peer access to a specific model ID.
    pub fn grant_peer_model_access(
        &self,
        peer_id: String,
        model_id: String,
    ) -> Result<(), AetherError> {
        if !self.state.peer_keys.contains_key(&peer_id) {
            return Err(AetherError::PeerNotFound);
        }
        self.state
            .peer_permissions
            .entry(peer_id)
            .or_default()
            .insert(model_id);
        Ok(())
    }

    /// Revoke all access for a peer: removes keys and permissions from the
    /// in-memory engine state. ADR-011: mobile `removePinnedPeer()` must call
    /// this in addition to clearing persistent storage, so that a revoked peer
    /// cannot continue downloading in the current session.
    pub fn revoke_peer(&self, peer_id: String) -> Result<(), AetherError> {
        let had_keys = self.state.peer_keys.remove(&peer_id).is_some();
        let had_perms = self.state.peer_permissions.remove(&peer_id).is_some();
        if !had_keys && !had_perms {
            return Err(AetherError::PeerNotFound);
        }
        info!("Revoked peer: {peer_id}");
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
        let peer_keys = self
            .state
            .peer_keys
            .get(&seeder_peer_id)
            .ok_or(AetherError::PeerNotFound)?;

        SecurityManager::verify_ticket(&ticket, &peer_keys.auth_key)?;

        // Only AFTER HMAC verification is it safe to parse the ticket.
        // Validate that the issuer in the ticket matches the expected seeder.
        let issuer_peer_id = ticket
            .rsplit_once('.')
            .map(|(payload, _)| payload)
            .and_then(|payload| payload.split('|').nth(3))
            .ok_or(AetherError::InvalidTicket)?
            .to_string();
        if issuer_peer_id != seeder_peer_id {
            return Err(AetherError::SecurityError(
                "Ticket issuer does not match expected seeder peer ID".into(),
            ));
        }

        let transport_key = peer_keys.transport_key.clone();
        drop(peer_keys); // release DashMap reference

        let self_id = self.get_self_peer_id();
        self.rt.block_on(download_file_to_fd(
            peer_ip,
            peer_port,
            ticket,
            self_id,
            transport_key,
            expected_sha256,
            resume_from,
            fd,
        ))
    }

    // ── Surgical patching ─────────────────────────────────────────────────────

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
        let port = self
            .bound_port
            .read()
            .unwrap()
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

    #[doc(hidden)]
    pub fn get_self_peer_id_for_test(&self) -> String {
        self.get_self_peer_id()
    }

    #[doc(hidden)]
    pub fn get_bound_port_for_test(&self) -> Option<u16> {
        *self.bound_port.read().unwrap()
    }

    #[cfg(test)]
    fn has_file_registered_for_test(&self, model_id: &str) -> bool {
        self.state.serve_files.contains_key(model_id)
    }
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
                    peer_id, local, peer_ver
                );
                return (StatusCode::BAD_REQUEST, "Incompatible protocol version").into_response();
            }
        }
    }

    let key_ref = match state.app.peer_keys.get(&peer_id) {
        Some(k) => k,
        None => return (StatusCode::FORBIDDEN, "Unknown peer identity").into_response(),
    };

    if SecurityManager::verify_ticket(&ticket_str, &key_ref.value().auth_key).is_err() {
        return (StatusCode::FORBIDDEN, "Invalid ticket").into_response();
    }

    if let Err(e) = reject_replayed_ticket(&state.app.seen_tickets, &ticket_str) {
        tracing::warn!("Replay rejected for peer {}: {}", peer_id, e);
        return (StatusCode::FORBIDDEN, "Replay detected").into_response();
    }

    // Extract model_id only after the ticket has been authenticated.
    let model_id = match ticket_str
        .rsplit_once('.')
        .map(|(payload, _)| payload)
        .and_then(|payload| payload.split('|').next())
    {
        Some(model_id) if !model_id.is_empty() => model_id.to_string(),
        _ => return (StatusCode::BAD_REQUEST, "Malformed ticket payload").into_response(),
    };

    let allowed = match state.app.peer_permissions.get(&peer_id) {
        Some(models) => models.contains(&model_id),
        None => false,
    };
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
    let transport_key = key_ref.value().transport_key.clone();

    // ── Random nonce for this session (prevents keystream reuse across restarts)
    let nonce = SecurityManager::generate_random_nonce();
    let nonce_hex = hex::encode(nonce);

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
            return axum::http::Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header("Content-Range", format!("bytes */{}", file_size))
                .body(Body::empty())
                .unwrap();
        }

        let content_len = file_size - start;
        let stream = encrypted_file_stream(
            file,
            start,
            content_len,
            &ticket_str,
            &transport_key,
            &nonce,
        );

        return axum::http::Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header("X-Aether-Encrypted", "chacha20")
            .header("X-Aether-Nonce", &nonce_hex)
            .header(header::CONTENT_LENGTH, content_len.to_string())
            .header(
                "Content-Range",
                format!("bytes {}-{}/{}", start, file_size - 1, file_size),
            )
            .body(Body::from_stream(stream))
            .unwrap();
    }

    // ── Full file response ────────────────────────────────────────────────────
    let stream = encrypted_file_stream(file, 0, file_size, &ticket_str, &transport_key, &nonce);
    axum::http::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header("X-Aether-Encrypted", "chacha20")
        .header("X-Aether-Nonce", &nonce_hex)
        .header(header::CONTENT_LENGTH, file_size.to_string())
        .body(Body::from_stream(stream))
        .unwrap()
}

async fn ping_handler() -> impl IntoResponse {
    (StatusCode::OK, Config::get_protocol_version())
}

async fn identity_handler(State(state): State<ServerState>) -> impl IntoResponse {
    axum::Json((*state.identity).clone())
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

fn encrypted_file_stream(
    mut file: tokio::fs::File,
    start: u64,
    remaining_len: u64,
    ticket: &str,
    transport_key: &SecureKey,
    nonce: &[u8; 12],
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static {
    let ticket = ticket.to_string();
    let transport_key = transport_key.clone();
    let nonce = *nonce;
    try_stream! {
        let session_key = SecurityManager::derive_session_stream_key(&transport_key, &ticket)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let mut cipher = ChaCha20::new((&session_key).into(), (&nonce).into());
        file.seek(std::io::SeekFrom::Start(start)).await?;
        cipher.seek(start);

        let mut sent = 0u64;
        let mut buf = vec![0u8; 64 * 1024];
        while sent < remaining_len {
            let want = usize::try_from((remaining_len - sent).min(buf.len() as u64)).unwrap();
            let n = file.read(&mut buf[..want]).await?;
            if n == 0 {
                break;
            }
            let mut chunk = buf[..n].to_vec();
            cipher.apply_keystream(&mut chunk);
            sent += n as u64;
            yield Bytes::from(chunk);
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
        let e1 = AetherEngine::new();
        let e2 = AetherEngine::new();
        assert_ne!(e1.get_self_peer_id(), e2.get_self_peer_id());
    }

    #[test]
    fn set_self_peer_id_persists() {
        let engine = AetherEngine::new();
        engine.set_self_peer_id("my-node-uuid".into());
        assert_eq!(engine.get_self_peer_id(), "my-node-uuid");
    }

    #[test]
    fn canonicalize_json_is_sorted_and_stable() {
        let engine = AetherEngine::new();
        let canonical = engine
            .canonicalize_json(r#"{"z":"last","a":"first","full":{"url":"x","size":1}}"#.into())
            .unwrap();
        assert_eq!(canonical, r#"{"a":"first","full":{"size":1,"url":"x"},"z":"last"}"#);
    }

    #[test]
    fn register_peer_key_wrong_length_fails() {
        let engine = AetherEngine::new();
        let result = engine.register_peer_key("peer-1".into(), vec![0u8; 16]);
        assert!(matches!(result, Err(AetherError::KeyExchangeFailed)));
    }

    #[test]
    fn register_peer_key_correct_length_ok() {
        let engine = AetherEngine::new();
        assert!(engine
            .register_peer_key("peer-1".into(), vec![0u8; 32])
            .is_ok());
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
        let engine = AetherEngine::new();
        let result =
            engine.verify_manifest(r#"{"id":"test"}"#.into(), "deadbeef".into(), vec![0u8; 65]);
        assert!(result.is_err());
    }

    #[test]
    fn heartbeat_fails_before_server_starts() {
        let engine = AetherEngine::new();
        // bound_port is None → heartbeat returns InternalError
        assert!(engine.heartbeat().is_err());
    }

    #[test]
    fn heartbeat_ok_after_server_starts() {
        let engine = AetherEngine::new();
        engine.set_self_identity_public_key(vec![0x04u8; 65]).unwrap();
        engine.start_server().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(engine.heartbeat().is_ok());
        engine.stop_server();
    }

    #[test]
    fn heartbeat_fails_after_server_stops() {
        let engine = AetherEngine::new();
        engine.set_self_identity_public_key(vec![0x04u8; 65]).unwrap();
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
        seen.insert(digest.clone(), current_unix_secs() - Config::TICKET_REPLAY_TTL_SECS - 1);

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

        let engine = AetherEngine::new();
        let file = NamedTempFile::new().unwrap();
        let fd = std::fs::OpenOptions::new()
            .write(true)
            .open(file.path())
            .unwrap()
            .into_raw_fd();

        let result =
            engine.download_model("127.0.0.1".into(), 1, "unknown-seeder".into(), "ticket".into(), "".into(), 0, fd);
        let _ = unsafe { std::fs::File::from_raw_fd(fd) };
        assert!(matches!(result, Err(AetherError::SecurityError(_))));
    }

    /// ADR-011: revoke_peer removes peer keys and permissions.
    #[test]
    fn revoke_peer_removes_keys_and_permissions() {
        let engine = AetherEngine::new();
        let secret = vec![0xAAu8; 32];
        engine.register_peer_key("peer-a".into(), secret.clone()).unwrap();
        engine.grant_peer_model_access("peer-a".into(), "model-x".into()).unwrap();

        // Peer exists before revocation
        assert!(engine.state.peer_keys.contains_key("peer-a"));
        assert!(engine.state.peer_permissions.contains_key("peer-a"));

        engine.revoke_peer("peer-a".into()).unwrap();

        // Peer gone after revocation
        assert!(!engine.state.peer_keys.contains_key("peer-a"));
        assert!(!engine.state.peer_permissions.contains_key("peer-a"));
    }

    /// ADR-011: revoke_peer returns PeerNotFound for unknown peer.
    #[test]
    fn revoke_peer_unknown_returns_error() {
        let engine = AetherEngine::new();
        let result = engine.revoke_peer("nonexistent".into());
        assert!(matches!(result, Err(AetherError::PeerNotFound)));
    }

    /// is_server_running returns false on fresh engine, true after start.
    #[test]
    fn is_server_running_reflects_bound_port() {
        let engine = AetherEngine::new();
        engine.set_self_identity_public_key(vec![0x04u8; 65]).unwrap();
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
        let engine = AetherEngine::new();
        assert_eq!(engine.get_protocol_version(), Config::get_protocol_version());
    }

    /// validate_peer_protocol accepts same major, rejects different major and blank.
    #[test]
    fn validate_peer_protocol_accepts_same_major() {
        let engine = AetherEngine::new();
        // Same version → OK
        assert!(engine.validate_peer_protocol("v2.3-swarm-fixed".into()).is_ok());
        // Same major, different minor → OK
        assert!(engine.validate_peer_protocol("v2.4-beta".into()).is_ok());
    }

    #[test]
    fn validate_peer_protocol_rejects_different_major() {
        let engine = AetherEngine::new();
        let result = engine.validate_peer_protocol("v3.0-swarm-fixed".into());
        assert!(matches!(result, Err(AetherError::SecurityError(_))));
    }

    #[test]
    fn validate_peer_protocol_rejects_blank() {
        let engine = AetherEngine::new();
        let result = engine.validate_peer_protocol("".into());
        assert!(matches!(result, Err(AetherError::SecurityError(_))));
    }

    #[test]
    fn register_file_nonexistent_returns_error() {
        let engine = AetherEngine::new();
        let result =
            engine.register_file_for_serving("model-x".into(), "/nonexistent/path/file.zst".into());
        assert!(result.is_err());
    }

    /// H-05 regression: stop_server() on a fresh engine must NOT poison
    /// the next start_server(). With notify_waiters() (ADR-005 Cycle #2),
    /// calling stop_server() before start_server() stores no permit.
    #[test]
    fn stop_server_on_fresh_engine_does_not_poison_start() {
        let engine = AetherEngine::new();
        engine.set_self_identity_public_key(vec![0x04u8; 65]).unwrap();

        // Call stop_server() on a fresh engine (no server running).
        // This used to poison Notify with notify_one(), causing the next
        // start_server() to shut down immediately.
        engine.stop_server();

        // Now start the server — it must succeed and stay alive.
        let port = engine.start_server().expect("start_server must succeed after stop_server on fresh engine");
        assert_ne!(port, 0);

        std::thread::sleep(std::time::Duration::from_millis(100));

        // Heartbeat must pass — server is alive.
        assert!(engine.heartbeat().is_ok(), "server must be alive after start_server following stop_server on fresh engine");

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

        let engine = AetherEngine::new();
        engine
            .register_file_for_serving("test-model".into(), tmp.path().to_str().unwrap().into())
            .unwrap();

        // Verify it was stored
        assert!(engine.has_file_registered_for_test("test-model"));
    }
}
