// rust_core/src/error.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AetherError {
    #[error("Server failed to start: {0}")]
    ServerStartupError(String),

    #[error("Network I/O error: {0}")]
    NetworkError(String),

    #[error("Security violation: {0}")]
    SecurityError(String),

    #[error("Invalid ticket or signature")]
    InvalidTicket,

    #[error("Key exchange failed")]
    KeyExchangeFailed,

    #[error("Peer not found in table")]
    PeerNotFound,

    #[error("Surgical patch failed: {0}")]
    PatchError(String),

    /// SHA-256 digest of received data did not match expected value.
    #[error("Checksum mismatch — expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    /// zstd decompression failure.
    #[error("Decompression failed: {0}")]
    DecompressError(String),

    /// ECDSA manifest signature is invalid.
    #[error("Manifest signature verification failed")]
    SignatureVerificationFailed,

    /// Server sent fewer bytes than declared in Content-Length.
    #[error("Download incomplete: received {received} of {expected} bytes")]
    DownloadIncomplete { received: u64, expected: u64 },

    /// Peer exceeded concurrent-connection limit.
    #[error("Rate limit exceeded — too many concurrent connections")]
    RateLimitExceeded,

    #[error("Internal system error: {0}")]
    InternalError(String),
}

impl From<std::io::Error> for AetherError {
    fn from(e: std::io::Error) -> Self {
        AetherError::NetworkError(e.to_string())
    }
}
