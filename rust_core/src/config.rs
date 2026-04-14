// rust_core/src/config.rs
pub struct Config;

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

    /// Current bspatch pipeline buffers the old file and patch delta in RAM.
    /// Keep the combined input under this ceiling to avoid OOM on low-RAM devices.
    pub const MAX_PATCH_BUFFERED_INPUT_BYTES: u64 = 256 * 1024 * 1024; // 256 MiB

    /// Individual patch delta ceiling. Typical mobile updates are well below this.
    pub const MAX_PATCH_DELTA_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB

    /// Obfuscated auth header name.
    #[inline(always)]
    pub fn get_header_key() -> &'static str {
        "X-Aether-Auth"
    }

    /// Obfuscated protocol version string.
    #[inline(always)]
    pub fn get_protocol_version() -> &'static str {
        "v2.3-swarm-fixed"
    }
}
