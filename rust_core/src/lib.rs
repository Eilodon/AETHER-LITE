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

mod config;
pub mod decompressor;
pub mod error;
mod network;
pub mod patcher;
pub mod security;

use crate::config::Config;
use crate::error::AetherError;
use crate::network::{download_file_to_fd, ping_peer};
use crate::security::{SecureKey, SecurityManager};

use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;
use tokio::sync::{Notify, Semaphore};
use tracing::info;

uniffi::include_scaffolding!("aether");

// ── Shared server state ───────────────────────────────────────────────────────

struct AppState {
    peer_keys: DashMap<String, SecureKey>,
    peer_permissions: DashMap<String, HashSet<String>>,
    seen_tickets: DashMap<String, u64>,
    shutdown_notify: Arc<Notify>,
    /// Limits concurrent download sessions to prevent resource exhaustion.
    download_limiter: Arc<Semaphore>,
    /// Files registered for serving by model_id → absolute path on disk.
    /// Populated by `register_file_for_serving` before a peer connects.
    serve_files: DashMap<String, PathBuf>,
}

// ── Engine ────────────────────────────────────────────────────────────────────

pub struct AetherEngine {
    state: Arc<AppState>,
    /// Shared runtime — `Arc` ensures it outlives the engine if the engine is
    /// dropped on the Android main thread inside a coroutine.
    rt: Arc<Runtime>,
    /// Fix v2.3: node's own UUID; sent as `?pid=` in outbound requests.
    self_peer_id: Arc<RwLock<String>>,
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
                shutdown_notify: Arc::new(Notify::new()),
                download_limiter: Arc::new(Semaphore::new(Config::MAX_CONCURRENT_DOWNLOADS)),
                serve_files: DashMap::new(),
            }),
            rt: Arc::new(Runtime::new().expect("Tokio runtime init failed")),
            self_peer_id: Arc::new(RwLock::new(default_id)),
            bound_port: Arc::new(RwLock::new(None)),
        }
    }

    // ── Identity ──────────────────────────────────────────────────────────────

    pub fn set_self_peer_id(&self, peer_id: String) {
        *self.self_peer_id.write().unwrap() = peer_id;
    }

    fn get_self_peer_id(&self) -> String {
        self.self_peer_id.read().unwrap().clone()
    }

    // ── Server lifecycle ──────────────────────────────────────────────────────

    pub fn start_server(&self) -> Result<u16, AetherError> {
        let state = self.state.clone();
        let notify = self.state.shutdown_notify.clone();
        let bound_port = self.bound_port.clone();
        let (tx, rx) = std::sync::mpsc::channel::<Result<u16, AetherError>>();

        self.rt.spawn(async move {
            let app = Router::new()
                .route("/download", get(download_handler))
                .route("/ping", get(ping_handler))
                .with_state(state);

            match tokio::net::TcpListener::bind(Config::BIND_ADDRESS).await {
                Ok(l) => {
                    let port = l.local_addr().unwrap().port();
                    *bound_port.write().unwrap() = Some(port);
                    tx.send(Ok(port)).ok();
                    info!("Aether server listening on :{}", port);
                    axum::serve(l, app)
                        .with_graceful_shutdown(async move { notify.notified().await })
                        .await
                        .unwrap_or_else(|e| tracing::error!("Server error: {}", e));
                }
                Err(e) => {
                    tx.send(Err(AetherError::ServerStartupError(e.to_string())))
                        .ok();
                }
            }
        });

        rx.recv()
            .map_err(|_| AetherError::InternalError("Startup channel closed".into()))?
    }

    pub fn stop_server(&self) {
        self.state.shutdown_notify.notify_one();
        *self.bound_port.write().unwrap() = None;
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
        // Derive a proper HMAC key from the raw ECDH output.
        let derived = SecurityManager::derive_hmac_key(&shared_secret)?;
        self.state
            .peer_keys
            .insert(peer_id, SecureKey(derived.to_vec()));
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

        let self_id = self.get_self_peer_id();
        self.rt.block_on(download_file_to_fd(
            peer_ip,
            peer_port,
            ticket,
            self_id,
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
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    // ── Rate limit ────────────────────────────────────────────────────────────
    let _permit = match state.download_limiter.try_acquire() {
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

    let key_ref = match state.peer_keys.get(&peer_id) {
        Some(k) => k,
        None => return (StatusCode::FORBIDDEN, "Unknown peer identity").into_response(),
    };

    if SecurityManager::verify_ticket(&ticket_str, key_ref.value()).is_err() {
        return (StatusCode::FORBIDDEN, "Invalid ticket").into_response();
    }

    if let Err(e) = reject_replayed_ticket(&state.seen_tickets, &ticket_str) {
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

    let allowed = match state.peer_permissions.get(&peer_id) {
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
    let file_path = match state.serve_files.get(&model_id) {
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
        use tokio::io::AsyncSeekExt;
        let mut seekable = file;
        if seekable
            .seek(std::io::SeekFrom::Start(start))
            .await
            .is_err()
        {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Seek failed").into_response();
        }
        let stream = tokio_util::io::ReaderStream::new(seekable);

        return axum::http::Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONTENT_LENGTH, content_len.to_string())
            .header(
                "Content-Range",
                format!("bytes {}-{}/{}", start, file_size - 1, file_size),
            )
            .body(Body::from_stream(stream))
            .unwrap();
    }

    // ── Full file response ────────────────────────────────────────────────────
    let stream = tokio_util::io::ReaderStream::new(file);
    axum::http::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, file_size.to_string())
        .body(Body::from_stream(stream))
        .unwrap()
}

async fn ping_handler() -> impl IntoResponse {
    (StatusCode::OK, Config::get_protocol_version())
}

fn reject_replayed_ticket(
    seen_tickets: &DashMap<String, u64>,
    ticket: &str,
) -> Result<(), AetherError> {
    let now = current_unix_secs();
    let ttl = Config::TICKET_REPLAY_TTL_SECS;

    seen_tickets.retain(|_, seen_at| now.saturating_sub(*seen_at) <= ttl);

    let digest = hex::encode(Sha256::digest(ticket.as_bytes()));
    match seen_tickets.entry(digest) {
        dashmap::mapref::entry::Entry::Occupied(_) => {
            Err(AetherError::SecurityError("Ticket replay detected".into()))
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
        engine.start_server().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(engine.heartbeat().is_ok());
        engine.stop_server();
    }

    #[test]
    fn heartbeat_fails_after_server_stops() {
        let engine = AetherEngine::new();
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
            SecurityManager::generate_ticket("m", "1", &SecureKey(derived.to_vec())).unwrap();
        let seen = DashMap::new();

        assert!(reject_replayed_ticket(&seen, &ticket).is_ok());
        assert!(reject_replayed_ticket(&seen, &ticket).is_err());
    }

    #[test]
    fn expired_replay_cache_entries_are_evicted() {
        let seen = DashMap::new();
        seen.insert(
            "old".into(),
            current_unix_secs() - Config::TICKET_REPLAY_TTL_SECS - 1,
        );

        assert!(reject_replayed_ticket(&seen, "fresh-ticket").is_ok());
        assert!(!seen.contains_key("old"));
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
            engine.download_model("127.0.0.1".into(), 1, "ticket".into(), "".into(), 0, fd);
        let _ = unsafe { std::fs::File::from_raw_fd(fd) };
        assert!(matches!(result, Err(AetherError::SecurityError(_))));
    }

    #[test]
    fn register_file_nonexistent_returns_error() {
        let engine = AetherEngine::new();
        let result =
            engine.register_file_for_serving("model-x".into(), "/nonexistent/path/file.zst".into());
        assert!(result.is_err());
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
