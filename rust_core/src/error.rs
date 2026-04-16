// rust_core/src/error.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AetherError {
    #[error("Server failed to start")]
    ServerStartupError(String),

    // ADR-014: Display message is generic; detailed string is for internal logging only.
    // Use tracing::error!() at the call site to log the full detail, then return
    // this variant with a brief label so the peer never sees OS error strings,
    // file paths, or other implementation details.
    #[error("Network error")]
    NetworkError(String),

    #[error("Security violation: {0}")]
    SecurityError(String),

    #[error("Invalid ticket or signature")]
    InvalidTicket,

    #[error("Key exchange failed")]
    KeyExchangeFailed,

    #[error("Peer not found in table")]
    PeerNotFound,

    #[error("Patch failed")]
    PatchError(String),

    /// SHA-256 digest of received data did not match expected value.
    // ADR-014: Do not expose actual hash values in Display — log them instead.
    #[error("Checksum mismatch")]
    ChecksumMismatch { expected: String, actual: String },

    /// zstd decompression failure.
    #[error("Decompression failed")]
    DecompressError(String),

    /// ECDSA manifest signature is invalid.
    #[error("Manifest signature verification failed")]
    SignatureVerificationFailed,

    /// Server sent fewer bytes than declared in Content-Length.
    #[error("Download incomplete")]
    DownloadIncomplete { received: u64, expected: u64 },

    /// Peer exceeded concurrent-connection limit.
    #[error("Rate limit exceeded — too many concurrent connections")]
    RateLimitExceeded,

    // ADR-014: Display message is generic; detailed string is for internal logging only.
    #[error("Internal error")]
    InternalError(String),
}

impl From<std::io::Error> for AetherError {
    fn from(e: std::io::Error) -> Self {
        AetherError::NetworkError(e.to_string())
    }
}
