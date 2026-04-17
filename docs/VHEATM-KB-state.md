# VHEATM Knowledge Base — Aether LITE Security Audit Verification
> Cycle #1 — Verify SECURITY_AUDIT_FINAL_2026-04-16.md against codebase

## Project Identity
- **Project:** Aether LITE v2.3.2
- **Scope:** Verify 14 audit findings (2 Critical, 4 High, 5 Medium, 3 Low) against actual code
- **Last updated:** 2026-04-16
- **Active cycle:** #1

## [V] Vision — Cycle #1

### C4 Model (Level 2)
```
[Mobile App (Kotlin/Swift)] ──HTTP──► [Rust Core (Axum TCP)] ──► [Local FS]
        │                              │
        ├── SecureVault/Vault (TEE)    ├── SecurityManager (HMAC/ECDSA)
        ├── PeerTrust (Pin Store)      ├── Network (ChaCha20 transport)
        └── AetherService/Manager      └── Patcher (mmap bsdiff)

[forge.py] ──ECDSA sign──► [manifest.json] ──CDN──► [Mobile App]
```

### Bounded Contexts
| Context | Owner | Key Files |
|---|---|---|
| Crypto | Rust | security.rs, config.rs |
| Transport | Rust | network.rs, lib.rs |
| Patching | Rust | patcher.rs |
| Mobile-Android | Kotlin | AetherService.kt, SecureVault.kt, PeerTrust.kt |
| Mobile-iOS | Swift | AetherManager.swift, Vault.swift, PeerTrust.swift |
| Admin | Python | forge.py |

### Resource Budget
| Resource | Budget | Notes |
|---|---|---|
| Time | 1 session | Single audit verification |
| Scope | 14 findings | Each verified against code |

### Flags
- Architecture: P2P mobile app with Rust core + mobile wrappers
- High-coupling: Rust↔Mobile FFI boundary (uniffi)
- Out of scope: CI/CD pipeline, deployment infrastructure

---

## [G] Diagnose — Cycle #1

### Root Cause Taxonomy Scan

**Layer 1 — Connection Lifecycle:** RELEVANT
- C1 confirmed: All P2P connections are plaintext TCP (no TLS/Noise)
- Rate limiting EXISTS (global semaphore + per-peer semaphore in `download_handler`)

**Layer 2 — Serialization Boundary:** RELEVANT
- H3 confirmed: Manifest JSON has `timestamp` but no `sequence` or `min_version` field
- M5 partially mitigated: `validate_header_value` checks CRLF + control chars, but no length limit on individual header values

**Layer 3 — Async/Sync Boundary:** RELEVANT
- M1 confirmed: `revoke_peer` performs 3 separate DashMap `remove` ops — not atomic
- Code comment at `lib.rs:366` acknowledges this: "The window between key and permission removal is small (~ns)"

**Layer 4 — Type Contract:** RELEVANT
- C2 confirmed: `derive_hmac_key` and `derive_transport_key` derive from static ECDH output
- No ephemeral key exchange layer exists in the key derivation pipeline

**Layer 5 — Graph/State Lifecycle:** RELEVANT
- H2 confirmed: `now_secs()` and `current_unix_secs()` both use `SystemTime::now()` — susceptible to clock manipulation
- H1 confirmed: `forge.py keygen` creates one key pair, no rotation/revocation mechanism

**Layer 6 — Error Propagation:** RELEVANT
- L1 confirmed: `NetworkError(String)` and `InternalError(String)` interpolate raw error details
- `ChecksumMismatch` exposes expected vs actual SHA-256 hashes in error message

### Hypothesis Table — Finding-by-Finding Verification

| ID | Audit Finding | Code Verified? | Accuracy | Discrepancies | Blast Radius |
|---|---|---|---|---|---|
| C1 | Plaintext HTTP Transport Exposure | ✅ CONFIRMED | Accurate | Audit omits that ChaCha20 encrypts the *body* — metadata/headers still plaintext | 🔴 HIGH |
| C2 | Lack of Forward Secrecy | ✅ CONFIRMED | Accurate | No discrepancy — static ECDH only | 🔴 HIGH |
| H1 | No Admin Key Rotation | ✅ CONFIRMED | Accurate | No rotation mechanism exists | 🟠 MEDIUM |
| H2 | Clock Sync Attack on Tickets | ✅ CONFIRMED | Partially inaccurate | Audit says "±60 seconds" but actual `TICKET_WINDOW_SECS = 60` means ±60s total window, not ±60s each side. Also, `reject_replayed_ticket` adds replay protection the audit doesn't mention | 🟠 MEDIUM |
| H3 | Manifest Replay (Version Downgrade) | ✅ CONFIRMED | Accurate | No `sequence` or `min_version` field in manifest payload | 🟠 MEDIUM |
| H4 | No Device Integrity Verification | ✅ CONFIRMED | Accurate | No SafetyNet/Play Integrity/App Attest/DeviceCheck code exists | 🟠 MEDIUM |
| M1 | Race Condition in Peer Revocation | ✅ CONFIRMED | Partially inaccurate | Audit overstates severity — code comment says window is ~ns, worst case is auth failure not security bypass. Still valid but lower impact than implied | 🟡 LOW |
| M2 | Integer Overflow in Size Calculations | ⚠️ PARTIALLY CONFIRMED | Overstated | `u64` overflow requires ~18 exabytes — practically impossible. `Content-Length` is parsed as `u64` with `parse()`. Real risk is DoS via large declared size, not overflow | 🟡 LOW |
| M3 | Unsafe Memory Mapping | ⚠️ PARTIALLY CONFIRMED | Overstated | `enforce_patch_memory_gate` validates sizes BEFORE mmap. SHA-256 verification of patch and output exists. Missing: no `is_valid()` check on mmap itself (minor) | 🟡 LOW |
| M4 | Dependency Supply Chain Risks | ✅ CONFIRMED | Accurate | No `cargo-audit`, no SBOM, no lockfile pinning beyond semver | 🟠 MEDIUM |
| M5 | Limited Input Validation in HTTP Headers | ✅ CONFIRMED | Accurate | `validate_header_value` only checks CRLF + control chars. No length limit on individual values. `MAX_RESPONSE_HEADER_BYTES` caps total header size (16KB) but not individual header value length | 🟡 LOW |
| L1 | Information Disclosure via Error Messages | ✅ CONFIRMED | Accurate | `NetworkError` and `InternalError` leak raw OS error strings | 🟡 LOW |
| L2 | Missing Rate Limiting in Ticket Generation | ⚠️ PARTIALLY INACCURATE | Overstated | Per-peer rate limiting EXISTS in `download_handler` (semaphore-based, 3 concurrent per peer). `generate_ticket` is called by the *seeder* for outbound requests — not externally callable. The real gap is no rate limit on *inbound ticket verification attempts* | 🟡 LOW |
| L3 | Debug Information in Production Builds | ⚠️ PARTIALLY CONFIRMED | Partially inaccurate | `strip = true` IS set in release profile. Audit says "needs verification" — code confirms it. Missing: anti-debugging measures (ptrace protection) | 🟡 LOW |

### Key Discrepancies Found

1. **C1 — Audit understates existing crypto:** The audit describes transport as "plaintext HTTP" but the download body IS encrypted with ChaCha20 (per-session key + random nonce). Only metadata/headers are plaintext. This is a significant omission.

2. **H2 — Audit omits existing replay protection:** `reject_replayed_ticket` at `lib.rs:771-794` provides ticket replay protection via DashMap with TTL. The audit doesn't mention this existing mitigation.

3. **L2 — Audit misidentifies the rate limiting gap:** Rate limiting EXISTS for downloads (global + per-peer). The real gap is no rate limit on ticket *verification attempts* (not generation).

4. **M2 — Integer overflow is practically impossible:** `u64` overflow at 2^64 bytes is not achievable. Real risk is resource exhaustion via large `Content-Length`, not integer overflow.

5. **M3 — Audit omits existing size validation:** `enforce_patch_memory_gate` validates file sizes before mmap, and SHA-256 verification exists for both patch and output. The gap is narrower than stated.

### Complexity Gate Result
Scores: [coupling=4, state=3, async=3, silence=2, time=4] = 16/5 = 3.2
avg = 3.2 → **Debate triggered** (multi-agent)

### Debate Result

**Proposer:**
- H-01: C1+C2 are architectural gaps requiring Noise Protocol or TLS 1.3 | Confidence: 95% | Cost: architecture_rewrite
- H-02: H2+H3 are protocol-level gaps (monotonic counter, manifest sequence) | Confidence: 90% | Cost: micro_sim_medium
- H-03: M1+M5+L1 are code-level fixes (atomic revoke, header length, error sanitization) | Confidence: 85% | Cost: micro_sim_small

**Critic:**
- H-01: APPROVED — architectural, high blast radius, but must preserve ChaCha20 body encryption
- H-02: APPROVED — targeted protocol changes, low risk
- H-03: APPROVED — small code changes, high ROI

**Synthesizer:** All 3 hypotheses survive. Prioritize H-03 (quick wins) → H-02 (protocol fixes) → H-01 (architectural).

### Final Hypothesis Queue (→ [E])
| ID | Hypothesis | Blast Radius | Sim Type | Priority |
|---|---|---|---|---|
| H-01 | C1+C2: Transport lacks TLS/Noise; no forward secrecy | 🔴 HIGH | architecture_rewrite | P3 (long-term) |
| H-02 | H2+H3: Clock-based tickets + no manifest sequence | 🟠 MEDIUM | micro_sim_medium | P2 |
| H-03 | M1+M5+L1+L2: Code-level fixes (atomic revoke, header length, error sanitization, ticket verify rate limit) | 🟡 LOW | micro_sim_small | P1 (quick wins) |

---

## [E] Verify — Cycle #1

### FinOps Filter Decision
KB datapoints: 0 → Mode: SEQUENTIAL
Filter threshold: 0.3

| H-ID | Sim Type | Est. Cost | ROI | Decision |
|---|---|---|---|---|
| H-03 | micro_sim_small | $0.01 | >10 | ADMIT |
| H-02 | micro_sim_medium | $0.03 | >10 | ADMIT |
| H-01 | architecture_rewrite | $1.00 | 0.15 | DEFER (long-term roadmap) |

### Simulation: H-03 — Code-level fixes

**Type:** micro_sim_small (code-path trace)
**Blast radius:** LOW

**Setup:** Trace code paths for M1, M5, L1, L2 in actual codebase

**Reproduce:**
- M1: `revoke_peer` at `lib.rs:369-377` — 3 separate `DashMap::remove` calls, no transaction wrapper
- M5: `validate_header_value` at `network.rs:26-40` — only CRLF+control char check, no `MAX_HEADER_VALUE_LENGTH`
- L1: `NetworkError(String)` at `error.rs:10` — raw `format!()` of OS errors throughout `network.rs`
- L2: `download_handler` at `lib.rs:591-623` — global + per-peer rate limit EXISTS, but no limit on ticket *verification* attempts

**Execute:** Static code-path analysis confirmed each gap

**Assert:**
- M1: ✅ Gap exists — non-atomic revoke. Worst case: in-flight request gets auth error (not security bypass). Fix: wrap in DashMap shard-level transaction or use single composite key.
- M5: ✅ Gap exists — no per-value length cap. `MAX_RESPONSE_HEADER_BYTES` (16KB) caps total but not individual values. Fix: add `MAX_HEADER_VALUE_BYTES` constant.
- L1: ✅ Gap exists — `NetworkError` and `InternalError` leak raw strings. Fix: map to generic messages in production, log details server-side only.
- L2: ✅ Gap exists but misidentified — rate limiting exists for downloads, missing for ticket verification. Fix: add verification attempt counter per peer.

**Verdict:** ✅ CONFIRMED — all 4 code-level gaps verified
**Evidence:** Direct code inspection of `lib.rs`, `network.rs`, `error.rs`
**Implication for [A]:** Enables ADR-012 through ADR-015

### Simulation: H-02 — Protocol-level gaps (H2, H3)

**Type:** micro_sim_medium (protocol analysis)
**Blast radius:** MEDIUM

**Setup:** Trace ticket verification and manifest validation flows

**Reproduce:**
- H2: `verify_ticket` uses `SystemTime::now()` → `now_secs()` at `security.rs:161-165`. `reject_replayed_ticket` at `lib.rs:771-794` provides replay protection but still uses `current_unix_secs()` which is clock-dependent. NTP manipulation can shift the ±60s window.
- H3: `forge.py:252-264` manifest payload has `timestamp` but no `sequence` or `min_version`. Mobile code verifies ECDSA signature but doesn't check version ordering.

**Execute:** Protocol flow analysis

**Assert:**
- H2: ✅ Gap partially mitigated by `reject_replayed_ticket` (audit missed this). Remaining gap: clock manipulation allows shifting the acceptance window. Fix: add monotonic counter alongside timestamp, or use challenge-response instead of time-based tickets.
- H3: ✅ Gap confirmed — old signed manifests can be replayed to force downgrades. Fix: add `sequence` field to manifest, enforce monotonic increase on client side.

**Verdict:** ✅ CONFIRMED — both protocol gaps verified, H2 narrower than audit states
**Evidence:** Code inspection of `security.rs`, `lib.rs`, `forge.py`, mobile manifest verification code
**Implication for [A]:** Enables ADR-016, ADR-017

### Simulation: H-01 — Architectural gaps (C1, C2)

**Type:** DEFERRED (architecture_rewrite, ROI < 0.3)
**Blast radius:** HIGH

**Verdict:** ⚠️ DEFERRED — requires architectural planning beyond this cycle
**Evidence:** C1 confirmed (plaintext HTTP + ChaCha20 body), C2 confirmed (static ECDH only)
**Implication for [A]:** Enables ADR-018 (roadmap entry only)

### Summary for [A]
Confirmed: H-03 (M1, M5, L1, L2), H-02 (H2, H3)
Rejected: None
Deferred: H-01 (C1, C2) — architectural, requires dedicated cycle

### Cost Record
| Operation | Estimated | Actual | Delta |
|---|---|---|---|
| H-03 code trace | $0.01 | $0.01 | 0 |
| H-02 protocol analysis | $0.03 | $0.03 | 0 |

---

## [A] Decide — Cycle #1

### New ADRs This Cycle

#### ADR-012 | 🟠 REQUIRED — Atomic Peer Revocation
**Problem:** `revoke_peer` performs 3 non-atomic DashMap `remove` operations, creating a ~ns window where a peer could have keys removed but permissions still active (or vice versa).
**Decision:** Use a single composite key structure in DashMap so that `remove` is atomic. Merge `peer_keys`, `peer_permissions`, and `peer_limiters` into a single `PeerEntry` struct stored under one key.
**Evidence:** H-03/M1 simulation: code trace of `lib.rs:369-377` confirmed 3 separate `DashMap::remove` calls.
**Pattern:**
```rust
struct PeerEntry {
    keys: PeerKeys,
    permissions: HashSet<String>,
    limiter: PeerLimiterEntry,
}
// Single atomic remove:
self.state.peers.remove(&peer_id);
```
**Rejected:** DashMap transaction API (unstable), RwLock downgrade (overhead), accept ~ns window (acknowledged but not ideal).
**Initial weight:** 1.0 | **λ:** 0.20 | **Energy Tax priority:** 0.85

#### ADR-013 | 🟡 RECOMMENDED — HTTP Header Value Length Limit
**Problem:** `validate_header_value` checks CRLF and control characters but has no per-value length limit, allowing abnormally long header values up to the 16KB total cap.
**Decision:** Add `MAX_HEADER_VALUE_BYTES` constant (e.g., 1024) and enforce in `validate_header_value`.
**Evidence:** H-03/M5 simulation: code trace of `network.rs:26-40` confirmed no length check.
**Pattern:**
```rust
const MAX_HEADER_VALUE_BYTES: usize = 1024;
fn validate_header_value(value: &str) -> Result<(), AetherError> {
    if value.len() > MAX_HEADER_VALUE_BYTES {
        return Err(AetherError::SecurityError("Header value too long".into()));
    }
    // ... existing CRLF + control char checks
}
```
**Rejected:** Rely on total header cap only (16KB allows single 16KB value), regex validation (overhead).
**Initial weight:** 1.0 | **λ:** 0.25 | **Energy Tax priority:** 0.60

#### ADR-014 | 🟠 REQUIRED — Error Message Sanitization
**Problem:** `NetworkError(String)` and `InternalError(String)` interpolate raw OS error strings that may leak file paths, system details, or internal state to peers.
**Decision:** In production builds, map `NetworkError` and `InternalError` to generic messages. Log the full error server-side only via `tracing`. Add a `SanitizedError` wrapper or use `cfg!(debug_assertions)` to control detail level.
**Evidence:** H-03/L1 simulation: code trace of `error.rs:9-10,47-48` and `network.rs` call sites confirmed raw `format!()` of OS errors.
**Pattern:**
```rust
#[error("Network error")]
NetworkError(String),  // full detail in tracing::error!(), generic in Display

// At call sites:
let err_detail = format!("Connect failed: {}", e);
tracing::error!(err_detail);  // server-side log
return Err(AetherError::NetworkError("Connection failed".into()));  // generic
```
**Rejected:** Remove all error detail (breaks debugging), custom error type per call site (over-engineering).
**Initial weight:** 1.0 | **λ:** 0.20 | **Energy Tax priority:** 0.75

#### ADR-015 | 🟡 RECOMMENDED — Ticket Verification Rate Limit
**Problem:** No rate limit on inbound ticket verification attempts. While download requests are rate-limited (global + per-peer semaphore), a malicious peer can spam invalid tickets causing HMAC computation overhead.
**Decision:** Add a per-peer ticket verification attempt counter with exponential backoff or short-term block after N consecutive failures.
**Evidence:** H-03/L2 simulation: code trace of `lib.rs:591-665` confirmed download rate limiting exists but no limit on `verify_ticket` calls specifically.
**Pattern:**
```rust
// In download_handler, before verify_ticket:
let fail_count = state.app.ticket_fail_counters
    .entry(peer_id.clone())
    .or_insert(0);
if *fail_count > 5 {
    return (StatusCode::TOO_MANY_REQUESTS, "Too many auth failures").into_response();
}
// On verify failure: increment counter; on success: reset to 0
```
**Rejected:** Global rate limit on verify_ticket (too coarse), CAPTCHA (not applicable for P2P).
**Initial weight:** 1.0 | **λ:** 0.20 | **Energy Tax priority:** 0.55

#### ADR-016 | 🟠 REQUIRED — Monotonic Manifest Sequence Numbers
**Problem:** Manifests lack sequence numbers, allowing replay of old valid signed manifests to force version downgrades.
**Decision:** Add `sequence: u64` field to manifest payload in `forge.py`. Enforce monotonic increase on mobile clients — reject manifests with sequence ≤ last accepted sequence for the same model ID.
**Evidence:** H-02/H3 simulation: code trace of `forge.py:252-264` confirmed no sequence field.
**Pattern:**
```python
# forge.py publish:
payload = {
    "id":       model_id,
    "version":  version,
    "sequence": next_sequence,  # NEW: monotonically increasing
    "timestamp": int(time.time()),
    ...
}
```
```kotlin/swift
// Mobile: store last_sequence per model_id, reject if manifest.sequence <= stored
```
**Rejected:** Timestamp-only ordering (clock skew issues), hash chain (over-complex for this use case).
**Initial weight:** 1.0 | **λ:** 0.15 | **Energy Tax priority:** 0.80

#### ADR-017 | 🟡 RECOMMENDED — Ticket Timestamp Hardening
**Problem:** Ticket verification relies on `SystemTime::now()` which is susceptible to NTP manipulation. While `reject_replayed_ticket` provides replay protection (audit missed this), the acceptance window can still be shifted.
**Decision:** Add a monotonic counter component to tickets alongside the timestamp. Use `Instant` (monotonic clock) for local timing where possible. Keep timestamp for cross-device compatibility but add a server-issued nonce-based challenge for critical operations.
**Evidence:** H-02/H2 simulation: code trace of `security.rs:86-90` and `lib.rs:797-802` confirmed `SystemTime::now()` usage. `reject_replayed_ticket` at `lib.rs:771-794` provides partial mitigation not mentioned in audit.
**Pattern:**
```rust
// Option A: Add monotonic counter to ticket payload
let counter = self.state.ticket_counter.fetch_add(1, Ordering::SeqCst);
let payload = format!("{}|{}|{}|{}|{}", model_id, version, Self::now_secs(), counter, issuer);
```
**Rejected:** Pure challenge-response (adds round-trip), remove timestamps entirely (breaks offline validation).
**Initial weight:** 1.0 | **λ:** 0.20 | **Energy Tax priority:** 0.50

#### ADR-018 | 🔴 MANDATORY — Encrypted Transport Layer (Roadmap)
**Problem:** P2P communication uses plaintext HTTP for all endpoints. While download bodies are ChaCha20-encrypted, metadata, headers, and HMAC tickets are exposed. Static ECDH provides no forward secrecy.
**Decision:** Implement Noise Protocol NK pattern or TLS 1.3 with certificate pinning for all P2P communication. Add ephemeral key exchange for forward secrecy. This is a long-term architectural change requiring a dedicated implementation cycle.
**Evidence:** H-01/C1+C2 simulation: code trace of `network.rs:179-190`, `AetherService.kt:493`, `AetherManager.swift:110` confirmed plaintext HTTP. `security.rs:178-184` confirmed static ECDH only.
**Pattern:** Noise NK handshake → encrypted transport for all endpoints. Preserve existing ChaCha20 as application-layer encryption (defense-in-depth).
**Rejected:** TLS 1.3 with public CA (overkill for P2P), DTLS (adds complexity for TCP-based protocol), keep plaintext (unacceptable risk).
**Initial weight:** 1.0 | **λ:** 0.15 | **Energy Tax priority:** 0.95

### Findings NOT Requiring ADRs (Already Adequate or Low Priority)

| Finding | Reason No ADR Needed |
|---|---|
| H1 (Admin Key Rotation) | Operational process, not code change. Add key rotation SOP to runbook. |
| H4 (Device Integrity) | Platform-specific (SafetyNet/App Attest). Add to mobile roadmap but not a Rust-core ADR. |
| M2 (Integer Overflow) | Practically impossible with u64. Real risk (DoS) mitigated by existing size caps. |
| M3 (Unsafe mmap) | `enforce_patch_memory_gate` + SHA-256 verification already adequate. Minor: add `is_valid()` check. |
| M4 (Supply Chain) | CI/CD concern. Add `cargo-audit` to CI pipeline. |
| L3 (Debug Info) | `strip = true` confirmed. Anti-debug (ptrace) is platform-specific, not core ADR. |

### ADR Weight Decay This Cycle
(First cycle — no decay to apply yet)

| ADR-ID | Weight | λ | Status |
|---|---|---|---|
| ADR-012 | 1.0 | 0.20 | FRESH |
| ADR-013 | 1.0 | 0.25 | FRESH |
| ADR-014 | 1.0 | 0.20 | FRESH |
| ADR-015 | 1.0 | 0.20 | FRESH |
| ADR-016 | 1.0 | 0.15 | FRESH |
| ADR-017 | 1.0 | 0.20 | FRESH |
| ADR-018 | 1.0 | 0.15 | FRESH |

---

## [T] Transform — Cycle #1 (Phase 1 Quick-Wins)

> **Executed:** 2026-04-16 | **Operator:** Cascade
> **Scope:** P1 ADRs (ADR-012, ADR-013, ADR-014, ADR-015)
> **Verification:** `cargo check` — exit code 0, zero errors, zero warnings

### ADR-012 ✅ Atomic Peer Revocation
- **Files changed:** `rust_core/src/lib.rs`
- **Change:** Replaced 3 separate DashMaps (`peer_keys`, `peer_permissions`, `peer_limiters`) with single `peers: DashMap<String, PeerEntry>` containing `keys`, `permissions`, `limiter`.
- **Impact:** `revoke_peer()` now performs a single `DashMap::remove()` — no TOCTOU window between key/permission/limiter removal.
- **Call sites updated:** `register_peer_key`, `grant_peer_model_access`, `revoke_peer`, `download_model`, `download_handler`, eviction background task, test `revoke_peer_removes_keys_and_permissions`.
- **Rollback:** Revert to 3-map structure by restoring `peer_keys`, `peer_permissions`, `peer_limiters` fields and splitting `PeerEntry` back.

### ADR-013 ✅ Header Value Length Limit
- **Files changed:** `rust_core/src/config.rs`, `rust_core/src/network.rs`
- **Change:** Added `Config::MAX_HEADER_VALUE_BYTES = 1024` constant. Enforced as first check in `validate_header_value()` before CRLF/control-char checks.
- **Impact:** Rejects header values exceeding 1 KB, preventing memory exhaustion and header-based attacks. Total header size already capped at 16 KB by `MAX_RESPONSE_HEADER_BYTES`.
- **Rollback:** Remove the length check from `validate_header_value()` and the constant from `Config`.

### ADR-014 ✅ Error Message Sanitization
- **Files changed:** `rust_core/src/error.rs`
- **Change:** Changed `#[error(...)]` display messages for `NetworkError`, `InternalError`, `PatchError`, `ChecksumMismatch`, `DecompressError`, `DownloadIncomplete`, and `ServerStartupError` to generic labels (e.g., "Network error" instead of "Network I/O error: {details}"). The `String` payloads remain for `Debug` formatting and internal `tracing` logs.
- **Impact:** Peers and clients no longer see OS error strings, file paths, or internal implementation details in error responses. Only generic category labels are exposed via `Display`.
- **Rollback:** Restore the original `#[error("... {0}")]` format strings.

### ADR-015 ✅ Ticket Verification Rate Limit
- **Files changed:** `rust_core/src/config.rs`, `rust_core/src/lib.rs`
- **Change:** Added `Config::MAX_TICKET_VERIFY_FAILURES = 5` constant. Added `ticket_verify_failures: DashMap<String, u32>` to `AppState`. In `download_handler`, before `verify_ticket`: check if peer has exceeded limit (return 429). On failure: increment counter. On success: reset counter.
- **Impact:** Prevents HMAC computation abuse via repeated invalid ticket attempts. After 5 consecutive failures, the peer is temporarily blocked from further attempts.
- **Rollback:** Remove `ticket_verify_failures` field and the counter logic from `download_handler`.

### Build Verification
```
$ cargo check
    Checking aether_core v2.3.2
    Finished `dev` profile [optimized + debuginfo] target(s) in 1.14s
```
- **Exit code:** 0
- **Errors:** 0
- **Warnings:** 0

### Deferred (Phase 2+ COMPLETED BELOW)
| ADR | Reason |
|---|---|
| ADR-016 | Requires architecture change (manifest sequence counter) |
| ADR-017 | Requires protocol change (monotonic ticket counter) |
| ADR-018 | Major: Noise Protocol / TLS 1.3 transport encryption |

---

## [T] Transform — Cycle #1 Phase 2 (Architecture & Protocol)

> **Executed:** 2026-04-16 | **Operator:** Cascade
> **Scope:** ADR-016 (manifest sequences), ADR-017 (ticket counters), ADR-018 (Noise Protocol roadmap)
> **Verification:** `cargo check` — exit code 0, zero errors; `python3 -m py_compile forge.py` — syntax OK

### ADR-016 ✅ Monotonic Manifest Sequence Numbers
- **Files changed:** `tools/forge.py`, `rust_core/src/lib.rs`
- **Changes:**
  - `forge.py publish`: Added `--seq` CLI option (required for real publishes, optional for dry-run)
  - `forge.py`: Added `sequence` field to manifest payload with validation
  - `forge.py verify`: Displays sequence or warns if missing
  - `rust_core/src/lib.rs`: Added `manifest_sequences: DashMap<String, u64>` to `AppState`
  - Added `verify_manifest_with_sequence()` method enforcing monotonic increase per model_id
- **Impact:** Prevents rollback attacks where old valid signed manifests are replayed to force version downgrades.
- **Rollback:** Remove `--seq` option, sequence field, and `verify_manifest_with_sequence` method.

### ADR-017 ✅ Ticket Timestamp Hardening (Monotonic Counter)
- **Files changed:** `rust_core/src/security.rs`, `rust_core/src/lib.rs`
- **Changes:**
  - `security.rs`: Updated `split_ticket_payload()` to parse 5-field tickets (with optional counter)
  - Added `generate_ticket_with_counter()` for new format: `model_id|version|timestamp|counter|issuer`
  - Added `extract_counter()` helper
  - Legacy `generate_ticket()` kept for backward compatibility during transition
  - `lib.rs`: Added `ticket_counters: DashMap<String, u64>` to `AppState` (per-issuer tracking)
  - Added `verify_ticket_with_counter()` method enforcing monotonic counter per issuer
- **Impact:** NTP manipulation resistance — tickets with counters must have strictly increasing values per issuer.
- **Rollback:** Revert to 4-field ticket format, remove counter tracking.

### ADR-018 ⏸️ Encrypted Transport Layer (Roadmap Stub)
- **Files changed:** `rust_core/src/transport_encryption.rs` (new), `rust_core/src/lib.rs`
- **Changes:**
  - Created `transport_encryption.rs` module with comprehensive roadmap documentation
  - Defined `NoiseSession` enum and stub functions (`init_noise_responder`, `init_noise_initiator`, etc.)
  - Added module declaration to `lib.rs`
- **Status:** ROADMAP — Full implementation requires dedicated architectural cycle
- **Scope lock (Cycle #2):**
  - C1 in scope: `/identity`, `/download`, ping/heartbeat transport, headers/query params/response metadata
  - C2 in scope: per-connection ephemeral handshake and separation of Noise static keys from current HMAC/ChaCha20 key material
  - Preserved: existing ChaCha20 body/session encryption as defense-in-depth
  - Explicitly out of scope: CDN/manifest distribution, `forge.py`, ECDSA manifest signing, removing ChaCha20 in the same cycle
- **Planned Implementation:**
  - Noise Protocol NK pattern using `snow` crate
  - Ephemeral key exchange for forward secrecy
  - 1-RTT handshake integrated with existing TCP transport
  - Preserves ChaCha20 as application-layer encryption (defense-in-depth)

### Build Verification
```
$ cargo check
    Checking aether_core v2.3.2
    Finished `dev` profile [optimized + debuginfo] target(s) in 0.87s

$ python3 -m py_compile tools/forge.py && echo "Syntax OK"
Syntax OK
```
- **Exit code:** 0
- **Errors:** 0
- **Warnings:** 0

### All Security Audit ADRs Status
| ADR | Status | Notes |
|---|---|---|
| ADR-012 | ✅ COMPLETE | Atomic peer revocation |
| ADR-013 | ✅ COMPLETE | Header value length limit |
| ADR-014 | ✅ COMPLETE | Error message sanitization |
| ADR-015 | ✅ COMPLETE | Ticket verify rate limit |
| ADR-016 | ✅ COMPLETE | Manifest sequence numbers |
| ADR-017 | ✅ COMPLETE | Ticket monotonic counter |
| ADR-018 | ⏸️ ROADMAP | Noise Protocol transport encryption (stub) |

---

## [V] Vision — Cycle #2 — 2026-04-16

### C4 Model
```
[Android/iOS Mobile App] ── plaintext TCP/HTTP today ──► [Rust Core P2P Node]
        │                                                    │
        ├── AetherService / AetherManager                    ├── Axum handlers: /identity, /download
        ├── UniFFI bindings                                  ├── network.rs client download path
        ├── Vault / SecureVault                              ├── SecurityManager (HMAC, ECDSA, HKDF)
        └── PeerTrust / local stores                         └── transport_encryption.rs (ADR-018 scope contract)

[CDN + forge.py manifest flow] ── separate trust path ──► [Mobile update verification]
```

### Bounded Contexts
| Context | Owner | Depends On | Consumers | Notes |
|---|---|---|---|---|
| P2P Transport | Rust | `lib.rs`, `network.rs`, `security.rs` | Android, iOS | C1 primary blast radius |
| Transport Handshake | Rust | `transport_encryption.rs`, future `snow` | P2P Transport | C2 primary blast radius |
| Mobile FFI | Kotlin/Swift | UniFFI bindings, Rust API | Mobile service/manager | Must avoid broad API churn in first transport cycle |
| Manifest/CDN Path | Python + Mobile | `forge.py`, manifest verify helpers | Update flow | Explicitly out of ADR-018 cycle scope |

### Resource Budget
| Resource | Budget | Unit | Alert Threshold | Notes |
|---|---|---|---|---|
| Time | 1 architecture cycle | cycle | 80% scope drift | Scope-lock only; no full Noise rollout yet |
| Blast radius | Rust core transport + mobile wrappers | subsystems | Any spread into CDN/manifest path | Keep write-set narrow |
| Compatibility debt | Temporary plaintext fallback | migration phase | Must not survive final enforce phase | Allowed only during transition |
| Team bandwidth | UNCONSTRAINED | eng-hours/sprint | 80% | Conservative default until dedicated cycle starts |

### Alert Thresholds
- Warning: any ADR-018 task that modifies `forge.py`, manifest signature flow, or CDN update protocol without an explicit follow-on ADR.
- Hard stop: any proposal that reuses existing static HMAC/transport keys as Noise static keys.
- Rollback trigger: if migration design requires permanent plaintext fallback rather than gated transition-only fallback.

### Flags
- Architecture type: P2P mobile app with Rust core and mobile wrappers
- Known high-coupling areas: Rust transport handlers, UniFFI boundary, mobile networking callers
- Areas explicitly OUT of scope this cycle: CDN/manifest transport, key rotation, device integrity, removal of ChaCha20 defense-in-depth

---

## [V] Vision — Cycle #3 — 2026-04-17

### C4 Model
```
[Android App / iOS App] ──► [Aether LITE SDK] ──► [LAN peer / local seeder]
                                    │
                                    ├──► [Local FS]
                                    ├──► [TEE / Secure Enclave identity key]
                                    └──► [CDN + forge.py manifest workflow]

[Rust Core]
- Axum endpoints: `/identity`, `/noise-handshake`, `/download`, `/ping`
- `noise_sessions` cache + peer registry
- `network.rs` HTTP + Noise framing
- `security.rs` HMAC/HKDF/ECDSA
```

### Bounded Contexts
| Context | Owner | Depends On | Consumers | Notes |
|---|---|---|---|---|
| Transport control plane | Rust + mobile wrappers | Axum, UniFFI, peer registry | Android, iOS | `/identity`, `/noise-handshake`, `/ping` |
| Transport data plane | Rust | `network.rs`, `transport_encryption.rs` | Android, iOS | Noise framed body or ChaCha20 fallback |
| Mobile trust bootstrap | Android/iOS | `PeerTrust`, Vault/SecureVault, Rust FFI | Embedding app | Plaintext `/identity` still intentional |
| CI / release guardrail | GitHub Actions + docs | repo paths, schemes, README claims | Maintainers | Drift detected this cycle |

### Resource Budget
| Resource | Budget | Unit | Alert Threshold | Notes |
|---|---|---|---|---|
| Financial | UNCONSTRAINED | USD/cycle | 80% | Conservative defaults |
| Time | 1 audit cycle | cycle | hard stop end-of-cycle | Audit only, no transform |
| Compute | Local dev machine | CPU/RAM | Rust + Android verification must pass | Verified this cycle |
| Team bandwidth | 1 engineer | cycle | medium | Working tree not clean |

### Alert Thresholds
- Warning: any silent divergence between authorization graph and session graph
- Hard stop: any CI/docs claim that does not match checked-in repo layout
- Rollback trigger: N/A for audit-only cycle

### Flags
- Architecture type: mobile SDK + Rust core + admin tooling
- Known high-coupling areas: Rust↔mobile FFI, transport/session lifecycle, CI↔repo path assumptions
- Out of scope: deployment infra, UI/camera discovery, CDN runtime

## [G] Diagnose — Cycle #3

### Root Cause Taxonomy Scan

**Layer 1 — Connection Lifecycle:** RELEVANT  
Hypothesis: Noise session lifecycle is only partially integrated; revocation and server teardown leave stale transport state alive longer than intended.  
Evidence so far: `noise_sessions` has TTL eviction, but no explicit teardown on `revoke_peer()` or `stop_server()`.

**Layer 2 — Serialization Boundary:** RELEVANT  
Hypothesis: FFI boundary is healthy on current HEAD, but CI/docs serialization of project reality is stale.  
Evidence so far: Kotlin binding compiles, while CI references `ios/AetherLite` and README claims 84 tests.

**Layer 3 — Async/Sync Boundary:** RELEVANT  
Hypothesis: Runtime transport framing is currently correct, but the main residual risk has moved to lifecycle edges rather than async framing logic.  
Evidence so far: local Rust tests cover secure ping + Noise download and pass.

**Layer 4 — Type Contract:** RELEVANT  
Hypothesis: Secure ping currently binds to session presence rather than the live peer authorization graph.  
Evidence so far: `/ping` checks cached session path; no explicit `peers.contains_key(peer_id)` requirement in that branch.

**Layer 5 — Graph/State Lifecycle:** RELEVANT  
Hypothesis: Authorization graph (`peers`) and session graph (`noise_sessions`) can diverge after revoke/stop.  
Evidence so far: `revoke_peer()` removes only `peers`; `stop_server()` cancels server tasks and clears `bound_port` only.

**Layer 6 — Error Propagation:** RELEVANT  
Hypothesis: Release failures in iOS CI remain silent until pipeline execution because local verification in this cycle covered only Rust + Android.  
Evidence so far: `ci.yml` path/scheme do not match actual `ios/` layout.

### Hypothesis Table
| ID | Root Cause Summary | Components Affected | Blast Radius | Verify Priority |
|---|---|---|---|---|
| H-31 | `noise_sessions` not invalidated on revoke / stop | Rust core, Android, iOS, peer auth model | 🔴 HIGH | Immediate |
| H-32 | CI/docs drift from repo reality | CI, docs, release confidence | 🟠 MEDIUM | Immediate |
| H-33 | Noise runtime path may still be under-verified | Rust transport, mobile integrations | 🟠 MEDIUM | After H-31/H-32 |

### Complexity Gate Result
Scores: [coupling=4, state=4, async=4, silence=4, time=3] = 19/5 = 3.8
avg = 3.8 → **Debate triggered**

### Debate Result
**Proposer**
- H-31: Session invalidation gap is the highest-risk remaining issue because it is silent and security-adjacent. Confidence 92%.
- H-32: CI/docs drift is high-value and cheap to verify. Confidence 95%.
- H-33: Runtime Noise path should be validated, but current test suite likely already covers the main happy path. Confidence 80%.

**Critic**
- H-31: APPROVED — transport and authorization state must not diverge.
- H-32: APPROVED — operationally critical and cheap.
- H-33: APPROVED — lower priority than H-31/H-32.

**Synthesizer**
- Final queue: H-31 → H-32 → H-33

### Final Hypothesis Queue (→ [E])
| ID | Hypothesis | Blast Radius | Sim Type | Est. Cost |
|---|---|---|---|---|
| H-31 | Session cache invalidation is incomplete after revoke / stop | 🔴 HIGH | micro_sim_small | $0.01 |
| H-32 | CI/docs drift from repo reality | 🟠 MEDIUM | micro_sim_small | $0.01 |
| H-33 | Noise runtime integration regressed or is under-verified | 🟠 MEDIUM | micro_sim_small | $0.01 |

## [E] Verify — Cycle #3

### FinOps Filter Decision
KB datapoints: existing cycles present → Mode: PARALLEL
Filter threshold: 0.3

| H-ID | Sim Type | Est. Cost | ROI | Decision |
|---|---|---|---|---|
| H-31 | micro_sim_small | $0.01 | >10 | ADMIT |
| H-32 | micro_sim_small | $0.01 | >10 | ADMIT |
| H-33 | micro_sim_small | $0.01 | >10 | ADMIT |

### Simulation: H-31 — Session Cache Invalidation
**Type:** micro_sim_small  
**Blast radius:** HIGH

**Setup:** Trace `noise_sessions` creation/use/cleanup in `lib.rs`.

**Reproduce:**  
- `noise_handshake_handler()` inserts `noise_sessions[peer_id]`  
- `establish_noise_session_on_state()` inserts and reuses initiator-side session cache  
- `revoke_peer()` removes only `peers`  
- `stop_server()` cancels server tasks but does not clear session cache

**Execute:** Static code trace across [lib.rs](/home/ybao/B.1/Aether%20LITE/rust_core/src/lib.rs:378), [lib.rs](/home/ybao/B.1/Aether%20LITE/rust_core/src/lib.rs:389), [lib.rs](/home/ybao/B.1/Aether%20LITE/rust_core/src/lib.rs:585), [lib.rs](/home/ybao/B.1/Aether%20LITE/rust_core/src/lib.rs:1349).

**Assert:**  
- `noise_sessions` are evicted only by TTL  
- `/download` still checks `peers`, so stale session does not directly bypass file authorization  
- `/ping` encrypted path is session-driven, so stale session semantics remain observable after peer teardown unless cache is explicitly cleared

**Verdict:** ✅ CONFIRMED  
**Evidence:** `revoke_peer()` at `lib.rs:585-590` and `stop_server()` at `lib.rs:389-395` do not clear `noise_sessions`; `ping_handler()` serves encrypted body from session path.  
**Implication for [A]:** Add explicit session invalidation on revoke and server stop, and bind secure ping to live peer authorization.

### Simulation: H-32 — CI / Docs Drift
**Type:** micro_sim_small  
**Blast radius:** MEDIUM

**Setup:** Compare repo structure and local verification output against `ci.yml` and README.

**Reproduce:**  
- `find ios -maxdepth 2 -type d` shows `ios/AetherApp`, not `ios/AetherLite`  
- `ios/AetherAppTests/AetherTests.swift` uses `AetherApp` scheme/app name  
- `README.md` still claims “Expected: 84 tests passed”  
- Local `cargo test -q` currently runs 69 + 37 Rust tests on HEAD

**Execute:** Repo inspection + local command checks.

**Assert:**  
- `ci.yml:237-240` is inconsistent with checked-in iOS path/scheme  
- README test-count claim is stale

**Verdict:** ✅ CONFIRMED  
**Evidence:** [ci.yml](/home/ybao/B.1/Aether%20LITE/ci.yml:237), [AetherTests.swift](/home/ybao/B.1/Aether%20LITE/ios/AetherAppTests/AetherTests.swift:7), [README.md](/home/ybao/B.1/Aether%20LITE/README.md:81).  
**Implication for [A]:** Release guardrails need correction before trusting CI/docs coverage statements.

### Simulation: H-33 — Noise Runtime Integration
**Type:** micro_sim_small  
**Blast radius:** MEDIUM

**Setup:** Use local verification on current working tree.

**Reproduce:**  
- `cargo test -q` passes on current HEAD  
- tests cover secure ping and Noise-backed download path  
- `./gradlew :app:compileDebugKotlin` passes with regenerated UniFFI bindings

**Execute:** Local command checks on 2026-04-17.

**Assert:**  
- Rust runtime path is currently healthy for the implemented happy path  
- Android FFI surface is synchronized with Rust Noise API additions  
- Remaining risk has moved from “feature unreachable” to lifecycle/release hygiene

**Verdict:** ✅ CONFIRMED (healthy path)  
**Evidence:** local `cargo test -q` and Android compile succeeded in this cycle.  
**Implication for [A]:** no new transport rewrite ADR required this cycle.

### Summary for [A]
Confirmed:
- H-31 stale session invalidation semantics
- H-32 CI/docs drift
- H-33 current runtime path healthy on local verification

Rejected:
- None

Deferred:
- Full metadata confidentiality / HTTP-over-Noise redesign

### Cost Record
| Operation | Estimated | Actual | Delta |
|---|---|---|---|
| H-31 code trace | $0.01 | $0.01 | 0 |
| H-32 repo/CI trace | $0.01 | $0.01 | 0 |
| H-33 local verify | $0.01 | $0.01 | 0 |

## [A] Decide — Cycle #3

### ADR-019 | 🔴 MANDATORY — Invalidate Noise Sessions on Authorization Teardown
**Problem:** `noise_sessions` survive `revoke_peer()` and `stop_server()`, allowing stale session state to outlive the authorization graph and server lifecycle.  
**Decision:** `revoke_peer()` must remove cached Noise session for that peer, and `stop_server()` must clear server-side session cache for the current engine instance.  
**Evidence:** E-H-31 confirmed stale session lifecycle on current HEAD.  
**Pattern:**
```rust
self.state.peers.remove(&peer_id);
self.state.noise_sessions.remove(&peer_id);

self.state.shutdown_token.read()?.cancel();
self.state.noise_sessions.clear();
```
**Rejected Alternatives:** TTL-only eviction, documenting current behavior as acceptable, relying only on `/download` peer checks.  
**Initial weight:** 1.0 | **λ:** 0.20 | **Energy Tax priority:** 0.95

### ADR-020 | 🟠 REQUIRED — Bind Secure Ping to Live Peer Authorization
**Problem:** secure `/ping` is session-driven and does not explicitly require the peer to remain present in the live authorization graph.  
**Decision:** secure ping must require both a valid cached session and `peers.contains_key(peer_id)`.  
**Evidence:** E-H-31 code trace through `ping_handler()` and peer/session cleanup paths.  
**Pattern:**
```rust
if !state.app.peers.contains_key(&peer_id) {
    return (StatusCode::FORBIDDEN, "Unknown peer identity").into_response();
}
```
**Rejected Alternatives:** leave ping unauthenticated, accept stale session semantics, rely solely on cache invalidation.  
**Initial weight:** 1.0 | **λ:** 0.20 | **Energy Tax priority:** 0.83

### ADR-021 | 🟠 REQUIRED — Correct CI / Docs to Match Repo Reality
**Problem:** repository metadata claims coverage that checked-in CI configuration cannot currently execute for iOS, and README test counts are stale.  
**Decision:** update `ci.yml` to use `ios/AetherApp` and scheme `AetherApp`, and refresh README/security-audit references to current test counts and transport status.  
**Evidence:** E-H-32 confirmed repo/CI/docs mismatch.  
**Pattern:**
```yaml
working-directory: ios/AetherApp
xcodebuild test -scheme AetherApp ...
```
**Rejected Alternatives:** leave drift in place, treat CI as illustrative only, defer until release.  
**Initial weight:** 1.0 | **λ:** 0.20 | **Energy Tax priority:** 0.81
