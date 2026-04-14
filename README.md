# Aether LITE

[![CI](https://github.com/b-one-labs/aether-lite/actions/workflows/ci.yml/badge.svg)](https://github.com/b-one-labs/aether-lite/actions)
[![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-blue)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.76+-orange)](https://rustup.rs)

**P2P zero-copy file transfer + surgical binary patching SDK for Android & iOS.**

Transfer a 10 GB AI model to a device with 512 MB RAM. Resume after network loss. Apply a 50 MB patch instead of re-downloading 1 GB. All verified with SHA-256. All authenticated with HMAC-SHA256 backed by hardware security chips.

Current threat model: integrity checks are mandatory and enforced in Rust, but authenticated key exchange and peer discovery still belong to the embedding app. The built-in transport is plaintext HTTP and is only appropriate on trusted LANs unless you add TLS/Noise above it.

---

## Why Aether

| Problem | Common approach | Aether |
|---------|----------------|--------|
| Large file transfer on low-RAM devices | Load into app memory → OOM | Zero-copy: socket → kernel → disk, app memory untouched |
| Network drops mid-download | Restart from zero | HTTP Range resume from last byte |
| Pushing 1 GB model update | Re-download full file | bsdiff surgical patch, typically 3–10% of original size |
| Tampered or corrupt files | Hope for the best | SHA-256 verified inline during streaming |
| Model/firmware spoofing | API key in plaintext | ECDSA-P256 signed manifest + HMAC-SHA256 per-peer auth |
| Server dependency for P2P transfer | Central CDN always required | Each node runs its own Axum server, works fully offline on LAN |

---

## Architecture

```
┌─────────────────────────────────────────────┐
│              Kotlin / Swift                  │
│   AetherService.kt   AetherManager.swift     │
│         SecureVault       Vault              │
│    (Android TEE)   (iOS Secure Enclave)      │
└───────────────┬─────────────────────────────┘
                │  UniFFI bridge
┌───────────────▼─────────────────────────────┐
│              Rust Core                       │
│  ┌──────────┐ ┌─────────┐ ┌──────────────┐  │
│  │ network  │ │ patcher │ │ decompressor │  │
│  │zero-copy │ │ bsdiff  │ │    zstd      │  │
│  │ +resume  │ │ +sha256 │ │  streaming   │  │
│  └──────────┘ └─────────┘ └──────────────┘  │
│  ┌──────────────────────────────────────┐    │
│  │ security: HMAC-SHA256, HKDF, ECDSA  │    │
│  └──────────────────────────────────────┘    │
│  ┌──────────────────────────────────────┐    │
│  │ AetherEngine: Axum P2P server,      │    │
│  │ DashMap peer registry, Semaphore    │    │
│  └──────────────────────────────────────┘    │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│           forge.py  (admin tool)             │
│  keygen → publish (compress+patch+sign)      │
│  → manifest.json (ECDSA-P256-SHA256)         │
└─────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

| Tool | Version |
|------|---------|
| Rust | ≥ 1.76 |
| Android Studio | Hedgehog+ (NDK 26+) |
| Xcode | 15+ (macOS only) |
| Python | ≥ 3.10 |

### 1. Run Rust tests

```bash
cd rust_core
cargo test
```

Expected: **40 tests passed** (16 unit + 24 integration).

### 2. Install cross-compilation targets

```bash
# Android
rustup target add aarch64-linux-android x86_64-linux-android

# iOS (macOS only)
rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim
```

### 3. Android

Open `android/` in Android Studio. Gradle sync — Rust compiles automatically via `rust-android-gradle`.
Set `ANDROID_HOME`/`ANDROID_SDK_ROOT` or create `android/local.properties` with `sdk.dir=...` before invoking Gradle outside Android Studio.

```bash
cd android

# JVM unit tests (no device needed)
./gradlew :app:testDebugUnitTest

# Instrumented tests (device or emulator)
./gradlew :app:connectedDebugAndroidTest
```

### 4. iOS

```bash
cd rust_core
cargo install cargo-lipo
cargo lipo --release
# → target/universal/release/libaether_core.a

cargo run --bin uniffi-bindgen generate \
  src/aether.udl --language swift \
  --out-dir ../ios/AetherApp/AetherCore/
```

Drag `libaether_core.a` + generated files into Xcode. Run tests: `⌘U`.

### 5. Admin tool

```bash
cd tools
pip install -r requirements.txt

# Generate keypair (once)
python forge.py keygen --out ./keys

# Dry run to estimate savings
python forge.py publish \
  --new model_v2.bin --old model_v1.bin \
  --id llm-mini --ver 2.0 --key ./keys/admin_private.pem \
  --dry-run

# Publish
python forge.py publish \
  --new model_v2.bin --old model_v1.bin \
  --id llm-mini --ver 2.0 \
  --key ./keys/admin_private.pem \
  --cdn https://cdn.yourdomain.com/models \
  --out ./dist

# Run tool tests
pytest forge_test.py -v
```

---

## Usage

### Android (Kotlin)

```kotlin
// 1. Download with zero-copy + SHA-256 + resume
aetherService.downloadModel(
    peerIp         = "192.168.1.42",
    peerPort       = 54321,
    ticket         = myTicket,
    savePath       = "${filesDir}/models/llm-mini.zst",
    expectedSha256 = manifest.full.sha256,
    resumeFrom     = 0L
)

// 2. Decompress (streaming, no RAM spike)
aetherService.decompressModel(
    compressedPath = "${filesDir}/models/llm-mini.zst",
    outputPath     = "${filesDir}/models/llm-mini.bin"
)

// 3. Smart update (manifest verified before patch applied)
aetherService.updateModelSmart(
    currentVersionPath   = "${filesDir}/models/llm-mini-v1.bin",
    patchPath            = "${filesDir}/cache/patch.bin",
    newVersionPath       = "${filesDir}/models/llm-mini-v2.bin",
    manifestJson         = manifestJson,
    adminPublicKey       = resources.openRawResource(R.raw.app_public_der).readBytes(),
    expectedPatchSha256  = manifest.patch.sha256,
    expectedOutputSha256 = manifest.full.sha256
)
```

### iOS (Swift)

```swift
// 1. Download
try await AetherManager.shared.downloadModel(
    peerIp:         "192.168.1.42",
    peerPort:       54321,
    ticket:         myTicket,
    destUrl:        modelsDir.appendingPathComponent("llm-mini.zst"),
    expectedSha256: manifest.full.sha256,
    resumeFrom:     0
)

// 2. Decompress
try await AetherManager.shared.decompressModel(
    compressedUrl: modelsDir.appendingPathComponent("llm-mini.zst"),
    outputUrl:     modelsDir.appendingPathComponent("llm-mini.bin")
)

// 3. Smart patch
try await AetherManager.shared.applySmartPatch(
    oldUrl:               modelsDir.appendingPathComponent("llm-mini-v1.bin"),
    patchUrl:             cacheDir.appendingPathComponent("patch.bin"),
    newUrl:               modelsDir.appendingPathComponent("llm-mini-v2.bin"),
    manifestJson:         manifestJson,
    adminPublicKeyDer:    adminPublicKeyData,
    expectedPatchSha256:  manifest.patch.sha256,
    expectedOutputSha256: manifest.full.sha256
)
```

---

## Security Model

| Layer | Mechanism |
|-------|-----------|
| Device identity | ECDH P-256 — Android Keystore TEE / iOS Secure Enclave |
| Auth ticket | `model\|version\|timestamp.HMAC-SHA256`, ±60s replay window |
| Timing attack | Constant-time HMAC comparison |
| Key derivation | HKDF-SHA256 from raw ECDH output, label `aether-hmac-v1` |
| Manifest integrity | ECDSA-P256-SHA256, verified on-device before any patch |
| Transfer integrity | SHA-256 computed inline during streaming |
| Patch integrity | SHA-256 of patch file + output file, both verified by Rust |
| Memory safety | `ZeroizeOnDrop` wipes keys from RAM on drop |
| Rate limiting | `Arc<Semaphore>` — 10 max concurrent sessions |
| Binary hardening | LTO + `opt-level=z` + `strip` + `panic=abort` |

---

## Test Coverage

| Scope | Tests |
|-------|-------|
| Rust unit | 33 |
| Rust integration | 34 |
| Android JVM unit | 19 |
| Android instrumented | 6 |
| iOS XCTest | 23 |
| Python (forge tool) | 37 |
| **Total** | **152** |

---

## Protocol Flow

```
Peer A (Seeder)                        Peer B (Leecher)
───────────────                        ────────────────
start_server() → :port
                  ── discovery / rendezvous supplied by app layer ──→
exchange ECDH public keys through an authenticated out-of-band channel
performHandshake(pubB) → secret        performHandshake(pubA) → secret
registerPeerKey(uuid_B, shared_secret) registerPeerKey(uuid_A, shared_secret)
grantPeerModelAccess(uuid_B, model)    grantPeerModelAccess(uuid_A, model)
register_file_for_serving(model_id, path)

                  ←── GET /download?pid=B ───
                       X-Aether-Auth: ticket
verify_ticket() ✓
                  ──── 206 / 200 stream ────→
                       [socket → kernel → fd → disk]
                       [SHA-256 verified inline]

Admin:  forge publish → patch.bin + manifest.json (ECDSA signed)
Peer B: download patch + manifest
        verify_manifest(manifest, sig, admin_pub_key) ✓
        apply_patch(old, patch, new, patch_sha, output_sha) ✓
```

---

## License

**Aether LITE License v1.0** (Based on Business Source License 1.1)

Free for: personal use, academic research, non-profit organizations, startups under $500K ARR (internal use only), open source projects.

Commercial use requires a license — contact B.ONE Labs.

Auto-converts to Apache 2.0 four years after each version's release date.

See [LICENSE](LICENSE) for full terms.

---

*Built by [B.ONE Labs](https://github.com/b-one-labs)*
