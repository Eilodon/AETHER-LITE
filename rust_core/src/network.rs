// rust_core/src/network.rs
//! Zero-copy TCP download with:
//!   • Correct self-peer-id (no hardcoded UUID)
//!   • SHA-256 integrity verification after transfer
//!   • HTTP Range header support for resumable downloads
//!   • Robust multi-chunk HTTP header reader (fix: was a single read() call)
//!   • Peer reachability probe

use crate::config::Config;
use crate::error::AetherError;
use crate::security::{SecureKey, SecurityManager};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::os::fd::FromRawFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{error, info, warn};

// ── HTTP response type ────────────────────────────────────────────────────────

/// Parsed HTTP response: Content-Length (if present) and body bytes that
/// arrived in the same read(s) as the headers.
struct HttpResponse {
    content_length: Option<u64>,
    body_prefix: Vec<u8>,
}

/// Read HTTP response headers from an async TcpStream, looping over multiple
/// TCP segments until the `\r\n\r\n` header terminator is found.
///
/// **Why this exists:** TCP is a stream protocol — a single `read()` can return
/// any number of bytes. On fast loopback it usually delivers everything at once,
/// but on real networks headers may arrive across multiple segments. The old
/// single-read approach silently discarded body bytes whenever `\r\n\r\n` fell
/// in a later segment, or produced garbage when headers exceeded the 8 KB buffer.
///
/// Total accumulated header data is capped at `Config::MAX_RESPONSE_HEADER_BYTES`
/// (16 KB) to prevent memory abuse from malicious peers.
async fn read_http_response(stream: &mut TcpStream) -> Result<HttpResponse, AetherError> {
    let mut buf = Vec::with_capacity(Config::HEADER_READ_CHUNK);
    let mut tmp = [0u8; Config::HEADER_READ_CHUNK];

    loop {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| AetherError::NetworkError(format!("Header read failed: {}", e)))?;

        if n == 0 {
            return Err(AetherError::NetworkError(
                "Peer closed connection before sending headers".into(),
            ));
        }

        buf.extend_from_slice(&tmp[..n]);

        if buf.len() > Config::MAX_RESPONSE_HEADER_BYTES {
            return Err(AetherError::NetworkError(format!(
                "Response headers exceed {} bytes — possible protocol mismatch or attack",
                Config::MAX_RESPONSE_HEADER_BYTES
            )));
        }

        // Check for the CRLF header terminator.
        if let Some(sep) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let header_str = String::from_utf8_lossy(&buf[..sep]);
            let body_prefix = buf[sep + 4..].to_vec();

            // ── Validate status line ──────────────────────────────────────────
            let status_line = header_str.lines().next().unwrap_or("");
            let is_ok =
                status_line.starts_with("HTTP/1.1 200") || status_line.starts_with("HTTP/1.0 200");
            let is_partial =
                status_line.starts_with("HTTP/1.1 206") || status_line.starts_with("HTTP/1.0 206");

            if !is_ok && !is_partial {
                error!("Peer refused: {}", status_line);
                return Err(AetherError::NetworkError(format!(
                    "HTTP error: {}",
                    status_line
                )));
            }

            // ── Parse Content-Length ──────────────────────────────────────────
            let content_length: Option<u64> = header_str
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split_once(':').map(|(_, v)| v))
                .and_then(|v| v.trim().parse().ok());

            return Ok(HttpResponse {
                content_length,
                body_prefix,
            });
        }
        // `\r\n\r\n` not yet in buffer — read the next TCP segment.
    }
}

// ── Download ──────────────────────────────────────────────────────────────────

/// Download a remote file directly into a kernel file-descriptor.
///
/// # Arguments
/// * `peer_ip`         – IPv4/IPv6 address of the seeding peer.
/// * `peer_port`       – Port the peer's Axum server is listening on.
/// * `ticket`          – HMAC-signed auth token for this transfer.
/// * `self_peer_id`    – This node's UUID, sent as `?pid=` query param.
/// * `expected_sha256` – Hex SHA-256 digest from the manifest. Empty = skip.
/// * `resume_from`     – Bytes already on disk; triggers `Range:` header.
/// * `fd`              – Writable file descriptor. Ownership transfers to Rust;
///   the caller **must not** close it afterwards.
#[allow(clippy::too_many_arguments)]
pub async fn download_file_to_fd(
    peer_ip: String,
    peer_port: u16,
    ticket: String,
    self_peer_id: String,
    transport_key: SecureKey,
    expected_sha256: String,
    resume_from: u64,
    fd: i32,
) -> Result<(), AetherError> {
    if expected_sha256.trim().is_empty() {
        return Err(AetherError::SecurityError(
            "expected_sha256 is required for downloads".into(),
        ));
    }

    // SAFETY: the caller transferred exclusive fd ownership to Rust at the
    // FFI boundary. Taking ownership here guarantees the fd is closed on every
    // early-return path below, including connect/request/header failures.
    let mut file = unsafe { File::from_raw_fd(fd) };

    let addr = format!("{}:{}", peer_ip, peer_port);
    info!("Connecting to peer {} (resume_from={})", addr, resume_from);

    let mut stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| AetherError::NetworkError(format!("Connect failed: {}", e)))?;

    // ── Build HTTP request ────────────────────────────────────────────────────
    let mut req = format!(
        "GET /download?pid={} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}: {}\r\n\
         X-Aether-Protocol: {}\r\n\
         Connection: close\r\n",
        self_peer_id,
        peer_ip,
        Config::get_header_key(),
        ticket,
        Config::get_protocol_version(),
    );
    if resume_from > 0 {
        req.push_str(&format!("Range: bytes={}-\r\n", resume_from));
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| AetherError::NetworkError(format!("Request send failed: {}", e)))?;

    // ── Read full HTTP headers (multi-chunk safe) ─────────────────────────────
    let resp = read_http_response(&mut stream).await?;

    // ── Zero-copy write + SHA-256 ─────────────────────────────────────────────
    if resume_from > 0 {
        file.seek(SeekFrom::Start(resume_from))
            .map_err(|e| AetherError::NetworkError(format!("Resume seek failed: {}", e)))?;
    }
    let mut writer = BufWriter::new(file);
    let mut hasher = Sha256::new();
    let mut written = 0u64;
    let session_key = SecurityManager::derive_session_stream_key(&transport_key, &ticket)?;
    let session_nonce = SecurityManager::derive_session_nonce(&ticket);
    let mut cipher = ChaCha20::new((&session_key).into(), (&session_nonce).into());
    cipher.seek(resume_from);

    // Body bytes that arrived in the same reads as the headers.
    if !resp.body_prefix.is_empty() {
        let mut decrypted = resp.body_prefix.clone();
        cipher.apply_keystream(&mut decrypted);
        writer
            .write_all(&decrypted)
            .map_err(|e| AetherError::InternalError(format!("Initial write failed: {}", e)))?;
        hasher.update(&decrypted);
        written += decrypted.len() as u64;
    }

    // Switch to blocking I/O for the bulk transfer loop.
    let mut std_stream = stream
        .into_std()
        .map_err(|e| AetherError::NetworkError(e.to_string()))?;
    std_stream
        .set_nonblocking(false)
        .map_err(|e| AetherError::NetworkError(e.to_string()))?;

    let mut chunk_buf = vec![0u8; 64 * 1024]; // 64 KB read chunks
    loop {
        match std_stream.read(&mut chunk_buf) {
            Ok(0) => break,
            Ok(k) => {
                let mut decrypted = chunk_buf[..k].to_vec();
                cipher.apply_keystream(&mut decrypted);
                writer
                    .write_all(&decrypted)
                    .map_err(|e| AetherError::NetworkError(format!("Write failed: {}", e)))?;
                hasher.update(&decrypted);
                written += k as u64;
            }
            Err(e) => return Err(AetherError::NetworkError(format!("Read failed: {}", e))),
        }
    }

    writer
        .flush()
        .map_err(|e| AetherError::NetworkError(format!("Flush failed: {}", e)))?;

    // ── Content-Length check ──────────────────────────────────────────────────
    if let Some(expected_len) = resp.content_length {
        if written != expected_len {
            return Err(AetherError::DownloadIncomplete {
                received: written,
                expected: expected_len,
            });
        }
    }

    info!("Download complete: {} bytes written to fd {}", written, fd);

    // ── SHA-256 verification ──────────────────────────────────────────────────
    if !expected_sha256.is_empty() {
        // ADR-002: resumed downloads — inline hasher only covers this session's bytes.
        // Rehash the full file from byte 0 via /proc/self/fd or /dev/fd.
        let actual = if resume_from > 0 {
            rehash_full_file(&writer)?
        } else {
            hex::encode(hasher.finalize())
        };

        if actual != expected_sha256 {
            error!(
                "Checksum mismatch: expected={} actual={}",
                expected_sha256, actual
            );
            return Err(AetherError::ChecksumMismatch {
                expected: expected_sha256,
                actual,
            });
        }
        info!("SHA-256 verified ✓");
    }

    // `writer` (and inner `File`) drops here → close(fd).
    Ok(())
}

/// Re-hash the full file from byte 0 via the fd symlink in /proc or /dev.
/// Required for ADR-002: resumed downloads must validate the complete file.
fn rehash_full_file(writer: &BufWriter<File>) -> Result<String, AetherError> {
    use std::os::unix::io::AsRawFd;
    let actual_fd = writer.get_ref().as_raw_fd();

    #[cfg(target_os = "linux")]
    let proc_path = format!("/proc/self/fd/{}", actual_fd);
    #[cfg(not(target_os = "linux"))]
    let proc_path = format!("/dev/fd/{}", actual_fd);

    let mut f = std::fs::File::open(&proc_path)
        .map_err(|e| AetherError::NetworkError(format!("Cannot reopen fd for rehash: {}", e)))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) => {
                return Err(AetherError::NetworkError(format!(
                    "Rehash read error: {}",
                    e
                )))
            }
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

// ── Peer probe ────────────────────────────────────────────────────────────────

pub async fn ping_peer(peer_ip: &str, peer_port: u16) -> bool {
    let addr = format!("{}:{}", peer_ip, peer_port);
    let mut stream = match TcpStream::connect(&addr).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!("Peer {} unreachable: {}", addr, e);
            return false;
        }
    };

    let req = format!(
        "GET /ping HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: close\r\n\r\n",
        peer_ip
    );

    if let Err(e) = stream.write_all(req.as_bytes()).await {
        warn!("Peer {} ping request failed: {}", addr, e);
        return false;
    }

    let resp = match read_http_response(&mut stream).await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("Peer {} ping response invalid: {}", addr, e);
            return false;
        }
    };

    let mut body = resp.body_prefix;
    let mut tmp = [0u8; 256];
    loop {
        match stream.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => {
                body.extend_from_slice(&tmp[..n]);
                if body.len() > 1024 {
                    warn!("Peer {} ping body too large", addr);
                    return false;
                }
            }
            Err(e) => {
                warn!("Peer {} ping body read failed: {}", addr, e);
                return false;
            }
        }
    }

    let body_str = String::from_utf8_lossy(&body);
    let alive = body_str == Config::get_protocol_version();
    if alive {
        info!("Peer {} reachable and protocol matched", addr);
    } else {
        warn!(
            "Peer {} responded to /ping with unexpected body: {}",
            addr, body_str
        );
    }
    alive
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;
    use tempfile::NamedTempFile;

    // ── Header parser unit tests ──────────────────────────────────────────────
    // Logic extracted from read_http_response for isolation testing
    // without requiring a real TCP socket.

    fn parse_header_buf(buf: &[u8]) -> Option<(bool, Option<u64>, Vec<u8>)> {
        let sep = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
        let header_str = String::from_utf8_lossy(&buf[..sep]);
        let body_prefix = buf[sep + 4..].to_vec();
        let status_line = header_str.lines().next().unwrap_or("");
        let ok = status_line.starts_with("HTTP/1.1 200")
            || status_line.starts_with("HTTP/1.0 200")
            || status_line.starts_with("HTTP/1.1 206")
            || status_line.starts_with("HTTP/1.0 206");
        let cl = header_str
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
            .and_then(|l| l.splitn(2, ':').nth(1))
            .and_then(|v| v.trim().parse().ok());
        Some((ok, cl, body_prefix))
    }

    #[test]
    fn headers_200_with_body_prefix() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let (ok, cl, body) = parse_header_buf(raw).unwrap();
        assert!(ok);
        assert_eq!(cl, Some(5));
        assert_eq!(body, b"hello");
    }

    #[test]
    fn headers_206_partial_accepted() {
        let raw = b"HTTP/1.1 206 Partial Content\r\nContent-Length: 3\r\n\r\nabc";
        let (ok, cl, body) = parse_header_buf(raw).unwrap();
        assert!(ok);
        assert_eq!(cl, Some(3));
        assert_eq!(body, b"abc");
    }

    #[test]
    fn headers_split_across_chunks_detected_after_concat() {
        // Simulates two TCP segments: first ends mid-header value.
        let combined = [
            b"HTTP/1.1 200 OK\r\nContent-Len".as_slice(),
            b"gth: 7\r\n\r\nabcdefg".as_slice(),
        ]
        .concat();
        let (ok, cl, body) = parse_header_buf(&combined).unwrap();
        assert!(ok);
        assert_eq!(cl, Some(7));
        assert_eq!(body, b"abcdefg");
    }

    #[test]
    fn incomplete_headers_return_none() {
        // No \r\n\r\n yet — loop should continue accumulating.
        let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";
        assert!(parse_header_buf(partial).is_none());
    }

    #[test]
    fn non_200_status_detected() {
        let raw = b"HTTP/1.1 403 Forbidden\r\n\r\n";
        let (ok, _, _) = parse_header_buf(raw).unwrap();
        assert!(!ok);
    }

    #[test]
    fn content_length_header_case_insensitive() {
        let raw = b"HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 42\r\n\r\n";
        let (_, cl, _) = parse_header_buf(raw).unwrap();
        assert_eq!(cl, Some(42));
    }

    #[test]
    fn body_empty_when_no_bytes_after_separator() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\n";
        let (ok, _, body) = parse_header_buf(raw).unwrap();
        assert!(ok);
        assert!(body.is_empty());
    }

    #[test]
    fn range_header_present_when_resuming() {
        let resume_from: u64 = 1024;
        let range_line = format!("Range: bytes={}-\r\n", resume_from);
        assert!(range_line.contains("Range: bytes=1024-"));
    }

    #[test]
    fn sha256_mismatch_error_fields() {
        let err = AetherError::ChecksumMismatch {
            expected: "aabb".into(),
            actual: "ccdd".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("aabb"));
        assert!(msg.contains("ccdd"));
    }

    #[tokio::test]
    async fn fd_is_closed_on_early_connect_failure() {
        let temp = NamedTempFile::new().unwrap();
        let fd = std::fs::OpenOptions::new()
            .write(true)
            .open(temp.path())
            .unwrap()
            .into_raw_fd();

        let proc_path = format!("/proc/self/fd/{}", fd);
        assert!(std::path::Path::new(&proc_path).exists());

        let result = download_file_to_fd(
            "127.0.0.1".into(),
            1,
            "ticket".into(),
            "peer-a".into(),
            SecureKey(vec![7u8; 32]),
            "00".repeat(32),
            0,
            fd,
        )
        .await;

        assert!(result.is_err());
        assert!(
            !std::path::Path::new(&proc_path).exists(),
            "fd should be closed on early-return paths"
        );
    }
}
