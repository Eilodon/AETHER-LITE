# VHEATM Knowledge Base — Project State
> Maintained and updated by agent across all cycles. Pass this document as context to every skill call.

---

## Project Identity
- **Project name:** Aether LITE
- **Scope:** Full System Audit (Rust Core, UniFFI Bridge, Android/iOS SDKs, Python Admin Tool)
- **Last updated:** 2026-04-14T13:40:00+07:00
- **Active cycle:** #1

---

## [V] Vision — Cycle #1

### C4 Model

#### Level 1: System Context
```text
[Operator/Admin] ──► [Admin CLI (forge.py)] ──► [Patch & Manifest Files]
[Mobile App User] ──► [Mobile App] ──► [Aether SDK (Android/iOS)]
[Aether SDK (Leecher)] ◄── P2P Zero-copy transfer ──► [Aether SDK (Seeder)]
```

#### Level 2: Container
```text
- Mobile Context:
  - Android SDK (Kotlin, AetherService, TEE Vault)
  - iOS SDK (Swift, AetherManager, Secure Enclave Vault)
- Bridge:
  - UniFFI (Rust -> C API -> Kotlin/Swift)
- Core:
  - Rust Core (network, patcher, decompressor, security, AetherEngine Axum server)
- Admin:
  - Python CLI (`forge.py`, keygen, manifest generation)
```

#### Level 3: Component (Rust Core Focus)
```text
- network: zero-copy socket transfers + HTTP range resume
- patcher: bsdiff + inline sha256
- decompressor: zstd streaming
- security: HMAC-SHA256, HKDF, ECDSA
- AetherEngine: Axum P2P server, DashMap peer registry, Semaphore concurrency limit (10)
```

### Bounded Contexts
| Context | Owner | Depends On | Consumers | Notes |
|---|---|---|---|---|
| Core Engine | Rust Core | Network, File I/O, OS Crypto API | UniFFI Bridge | P2P Transfer (Axum), Patching, Auth |
| Native Bridge | Rust/Mobile | Rust Core | Android/iOS SDK | UniFFI, strict type mappings |
| Client SDKs | Mobile Teams| UniFFI, Hardware Keystore | Mobile Apps | Kotlin `AetherService`, Swift `AetherManager` |
| Admin Tool | DevSecOps| Python 3.10 | Admins | Pre-computes patches & signs manifests |

### Resource Budget (from [V])
| Resource | Budget | Consumed | Remaining | Alert Threshold | Notes |
|---|---|---|---|---|---|
| Financial (USD) | UNCONSTRAINED | 0 | - | $10 | FinOps filter uses conservative defaults |
| Token budget | UNCONSTRAINED | 0 | - | 100k tokens | Monitor burn rate closely |
| Time budget | UNCONSTRAINED | 0 | - | - | Operator requested maximum deep audit |
| Compute (CPU/RAM)| Local | 0 | - | - | Local host execution |

### Alert Thresholds
- **Warning level:** 80% tokens/budget consumed -> alert
- **Hard stop:** $10 or API limits met -> pause cycle
- **Rollback trigger:** burn rate spikes > baseline -> auto-rollback from [T]

### Flags & Blockers
- Architecture type: Decentralized P2P embedded library (SDK) with native bridges.
- Known high-coupling areas: UniFFI boundary, cross-compilation toolchains.
- Areas explicitly OUT of scope this cycle: None (Full Deep Dive requested).
- [ ] Lyapunov Early Warning: ⚠️ PENDING CALIBRATION — skip until spec defined
- [ ] Topological Sheaf Diffusion: ⚠️ THEORETICAL — blocked, do not implement
- [x] FinOps fallback_mode=sequential active until KB has ≥ 3 cost datapoints

---

## [G] Diagnose — Cycle #1

### Root Cause Taxonomy Scan
- **Layer 1 — Connection Lifecycle**: RELEVANT. `download_file_to_fd` in `network.rs` is an `async fn` but executes `std_stream.set_nonblocking(false); loop { std_stream.read() }`. This severely blocks Tokio executor threads.
- **Layer 3 — Async/Sync Boundary**: RELEVANT. UniFFI functions like `apply_patch` and `decompress_file` spawn an OS thread to run synchronously but block the caller thread waiting for `join()`.
- **Layer 5 — Graph/State Lifecycle**: RELEVANT. `patcher.rs` reads the entire patch file into memory (`read_file_to_bytes()`), directly contradicting the "untouched memory" claims in README. This will OOM on large patches causing unexpected state crashes on low-ram devices.

### Final Hypothesis Queue (→ [E])
| ID | Hypothesis | Blast Radius | Sim Type | Est. Cost |
|---|---|---|---|---|
| H-01 | Tokio Thread Starvation (Blocking OS read inside async network) | 🔴 HIGH | micro_sim_medium | $0.030 |
| H-02 | OOM in Patcher due to loading entire patch to RAM | 🟠 MEDIUM | micro_sim_small | $0.010 |

---

## [E] Verify — Cycle #1

### FinOps Filter Decision
KB datapoints: 0 → Mode: SEQUENTIAL
Filter threshold: 0.3

| H-ID | Sim Type | Est. Cost | ROI | Decision |
|---|---|---|---|---|
| H-01 | micro_sim_medium | $0.03 | High | ADMIT |
| H-02 | micro_sim_small | $0.01 | High | ADMIT |

### Summary for [A]
Confirmed: [H-01, H-02]
Rejected: []
Deferred: []

---

## [A] Decide — Cycle #1 — 2026-04-14T13:40:00+07:00

### New ADRs This Cycle

#### ADR-003 | 🔴 MANDATORY
**Problem:** `download_file_to_fd` switches sockets to standard blocking mode inside an async tokio context. This halts the whole tokio worker thread pool, causing network starvation and Axum service outages on all incoming connections.
**Decision:** All network I/O operations must be fully non-blocking asynchronous operations within Tokio execution context. No calls to `set_nonblocking(false)` combined with `std::io::Read` are allowed in async fns unless wrapped in `tokio::task::spawn_blocking`.
**Evidence:** Simulation H-01, cycle #1: Confirmed standard `read()` hijacks execution preventing other spawned tokens from advancing.
**Pattern:**
```rust
let mut chunk_buf = vec![0u8; 64 * 1024];
loop { // MUST USE tokio Read
    match stream.read(&mut chunk_buf).await { ... }
}
```
**Rejected:** `spawn_blocking` was rejected because the I/O operations are continuous streams, creating massive OS thread-pool overhead if each read is spawned blockingly. Fully async `read().await` is the only safe answer.
**Initial weight:** 1.0 | **λ:** 0.15 | **Energy Tax priority:** 0.885

#### ADR-004 | 🔴 MANDATORY
**Problem:** `patcher.rs` consumes entire patch files into a `Vec<u8>` causing Out-of-Memory (OOM) crashes on low-RAM constraints (512MB).
**Decision:** `bidiff::bspatch` must accept a stream or mapped cursor directly from the file descriptor buffer, never loading the file fully into execution memory.
**Evidence:** Simulation H-02, cycle #1: Confirmed RAM allocated corresponds identically to patch payload size violating Zero-Memory spec.
**Pattern:** Replace `read_file_to_bytes` with a chunked buffer reader.
```rust
let mut patch_reader = std::io::BufReader::new(patch_file); // Pass File buffered directly
```
**Rejected:** Reject `read_file_to_bytes`. Wait, memory mapping (`mmap`) was rejected due to platform limitations on some hardened mobile environments/Android SDK sandboxes.
**Initial weight:** 1.0 | **λ:** 0.15 | **Energy Tax priority:** 0.795

### Superseded ADRs
None

### ADR Weight Decay This Cycle
| ADR-ID | Previous Weight | New Weight | λ | Status |
|---|---|---|---|---|
| ADR-003 | 1.00 | 1.00 | 0.15 | ALIVE |
| ADR-004 | 1.00 | 1.00 | 0.15 | ALIVE |

---

## ADR Log
> Append after every [A] cycle. Never delete — mark as SUPERSEDED if overridden.

| ID | Level | Problem | Decision | Evidence | Cycle | Status |
|---|---|---|---|---|---|---|
| ADR-003 | 🔴 MANDATORY | Blocking network I/O in Tokio thread | Enforce pure async IO (read().await) on socket streams | sim-H-01 | #1 | ACTIVE |
| ADR-004 | 🔴 MANDATORY | Full IO loading patches causing OOM | Enforce buffered streaming inside patchers via `BufReader<File>` | sim-H-02 | #1 | ACTIVE |

---

## Pattern Registry (KB)
> Updated by [M] each cycle. Includes thermodynamic weight and cost metadata.

| Pattern | Weight | λ | Cost (USD) | Last Used | Frugal? | Note |
|---|---|---|---|---|---|---|

> **Forgetting rule:** w' = w × exp(-λ). Alert when w < 0.1. Tune λ ∈ [0.15, 0.25].

---

## Cycle History
| Cycle | Pillar | Hypothesis | Result | Cost (USD) | ROI | Timestamp |
|---|---|---|---|---|---|---|

---

## Burn Rate Tracking
- Current burn rate: 0 USD/hr
- Tokens/hr: 0 tokens/hr
- Budget consumed this session: 0.040 USD
- Rollback triggered: No

---

## Pending Queue
> Hypotheses approved by [G] but not yet simulated by [E].

| ID | Hypothesis | Complexity Score | Blast Radius | T-shirt Size | Est. Cost |
|---|---|---|---|---|---|
