// rust_core/src/config.rs
pub struct Config;

static HEADER_KEY: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| obfstr::obfstr!("X-Aether-Auth").to_string());
static PROTOCOL_VERSION: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| obfstr::obfstr!("v2.3-swarm-fixed").to_string());

impl Config {
    /// Bind all interfaces; OS picks an available port.
    pub const BIND_ADDRESS: &'static str = "0.0.0.0:0";

    /// Per-read scratch buffer for the HTTP header loop (bytes).
    pub const HEADER_READ_CHUNK: usize = 4096;

    /// Hard cap on total response-header size (bytes).
    /// Protects against peers that stream garbage before \r\n\r\n.
    pub const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024; // 16 KB

    /// Replay-attack window: tickets outside ±N seconds are rejected.
    pub const TICKET_WINDOW_SECS: u64 = 60;

    /// TTL for the in-memory seen-ticket cache. Covers the full acceptance
    /// window in both directions so a captured ticket cannot be replayed
    /// multiple times while still considered fresh.
    pub const TICKET_REPLAY_TTL_SECS: u64 = Self::TICKET_WINDOW_SECS * 2;

    /// Maximum concurrent download sessions served simultaneously.
    pub const MAX_CONCURRENT_DOWNLOADS: usize = 10;

    /// Maximum concurrent downloads allowed per peer to prevent DoS.
    pub const MAX_DOWNLOADS_PER_PEER: usize = 3;

    /// Idle TTL for per-peer limiter entries before background cleanup.
    pub const PEER_LIMITER_IDLE_TTL_SECS: u64 = 15 * 60;

    /// Background cleanup cadence for in-memory eviction tasks.
    pub const BACKGROUND_CLEANUP_INTERVAL_SECS: u64 = 30;

    /// Ceiling for combined old+patch virtual address space (ADR-006: mmap replaces
    /// read_to_end, so this is a virtual address guard rather than a physical RAM limit).
    pub const MAX_PATCH_BUFFERED_INPUT_BYTES: u64 = 256 * 1024 * 1024; // 256 MiB

    /// Individual patch delta ceiling. Typical mobile updates are well below this.
    pub const MAX_PATCH_DELTA_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB

    /// Maximum decompressed output size to prevent decompression bomb attacks.
    /// Zstd has extreme compression ratios; this limits memory/disk exhaustion.
    pub const MAX_DECOMPRESSED_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GB

    /// ADR-013: Maximum length of a single HTTP header value (bytes).
    /// Prevents abnormally long values from consuming memory or enabling attacks.
    /// While MAX_RESPONSE_HEADER_BYTES caps total header size (16 KB),
    /// this limits individual values to 1 KB.
    pub const MAX_HEADER_VALUE_BYTES: usize = 1024;

    /// ADR-015: Maximum consecutive ticket verification failures per peer
    /// before the peer is temporarily blocked from further attempts.
    /// Prevents HMAC computation abuse via repeated invalid tickets.
    pub const MAX_TICKET_VERIFY_FAILURES: u32 = 5;

    /// TTL for consecutive ticket verification failures.
    /// Prevents transient onboarding/key-rotation issues from blocking a peer forever.
    pub const MAX_TICKET_VERIFY_FAILURE_TTL_SECS: u64 = 30 * 60;

    /// Obfuscated auth header name.
    #[inline(always)]
    pub fn get_header_key() -> &'static str {
        HEADER_KEY.as_str()
    }

    /// Obfuscated protocol version string.
    #[inline(always)]
    pub fn get_protocol_version() -> &'static str {
        PROTOCOL_VERSION.as_str()
    }
}
