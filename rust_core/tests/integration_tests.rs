// rust_core/tests/integration_tests.rs
//! End-to-end integration tests for AetherEngine.
//!
//! Run with:
//!   cargo test -- --test-output immediate
//!
//! These tests exercise the full stack (security + network + patcher +
//! decompressor) without requiring a real Android/iOS device.

use std::io::Write;
use std::os::unix::io::IntoRawFd;
use tempfile::NamedTempFile;

// ─────────────────────────────────────────────────────────────────────────────
// Helper utilities
// ─────────────────────────────────────────────────────────────────────────────

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// Create an AetherEngine with a dummy identity public key already set.
/// Required since start_server() now enforces that the key is non-empty.
fn new_engine_with_identity() -> aether_core::AetherEngine {
    let engine = aether_core::AetherEngine::new().unwrap();
    engine
        .set_self_identity_public_key(vec![0x04u8; 65])
        .unwrap();
    engine
}

fn write_temp(data: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

// ─────────────────────────────────────────────────────────────────────────────
// Security
// ─────────────────────────────────────────────────────────────────────────────

mod security_tests {
    use aether_core::security::{SecureKey, SecurityManager};

    fn key(b: u8) -> SecureKey {
        SecureKey(vec![b; 32])
    }

    #[test]
    fn generate_and_verify_ticket() {
        let secret = key(0x42);
        let ticket =
            SecurityManager::generate_ticket("llm-mini", "2.0", "seeder-1", &secret).unwrap();
        assert!(SecurityManager::verify_ticket(&ticket, &secret).is_ok());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let s1 = key(0x11);
        let s2 = key(0x22);
        let t = SecurityManager::generate_ticket("m", "1", "seeder-1", &s1).unwrap();
        assert!(SecurityManager::verify_ticket(&t, &s2).is_err());
    }

    #[test]
    fn tampered_model_id_is_rejected() {
        let s = key(0x33);
        let t = SecurityManager::generate_ticket("good-model", "1", "seeder-1", &s).unwrap();
        let bad = t.replace("good-model", "evil-model");
        assert!(SecurityManager::verify_ticket(&bad, &s).is_err());
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let s = key(0x44);
        let t = SecurityManager::generate_ticket("m", "1", "seeder-1", &s).unwrap();
        // Flip one character in the base64 signature part
        let mut chars: Vec<char> = t.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(SecurityManager::verify_ticket(&tampered, &s).is_err());
    }

    #[test]
    fn malformed_tickets_are_rejected() {
        let s = key(0x55);
        for bad in ["", "nodot", "a.b.c", "||.sig", "model||1713000000.bad==="] {
            assert!(
                SecurityManager::verify_ticket(bad, &s).is_err(),
                "Expected error for: {bad}"
            );
        }
    }

    #[test]
    fn ticket_format_is_correct() {
        let s = key(0x66);
        let t = SecurityManager::generate_ticket("m", "v1", "seeder-1", &s).unwrap();
        let parts: Vec<&str> = t.splitn(2, '.').collect();
        assert_eq!(parts.len(), 2, "Ticket must have exactly one '.'");
        let fields: Vec<&str> = parts[0].split('|').collect();
        assert_eq!(fields[0], "m");
        assert_eq!(fields[1], "v1");
        assert!(
            fields[2].parse::<u64>().is_ok(),
            "Timestamp must be numeric"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Patcher
// ─────────────────────────────────────────────────────────────────────────────

mod patcher_tests {
    use super::*;
    use aether_core::patcher::apply_patch_fds;
    use qbsdiff::{Bsdiff, ParallelScheme};

    fn make_patch(old: &[u8], new: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        Bsdiff::new(old, new)
            .parallel_scheme(ParallelScheme::Never)
            .compare(&mut out)
            .unwrap();
        out
    }

    #[test]
    fn small_file_roundtrip() {
        let old_data = b"Hello World v1.0 aether test content";
        let new_data = b"Hello World v2.0 aether test content";

        let old_f = write_temp(old_data);
        let patch = make_patch(old_data, new_data);
        let patch_f = write_temp(&patch);
        let out_f = NamedTempFile::new().unwrap();

        let patch_sha = sha256_hex(&patch);
        let out_sha = sha256_hex(new_data);

        apply_patch_fds(
            std::fs::File::open(old_f.path()).unwrap().into_raw_fd(),
            std::fs::File::open(patch_f.path()).unwrap().into_raw_fd(),
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(out_f.path())
                .unwrap()
                .into_raw_fd(),
            &patch_sha,
            &out_sha,
        )
        .unwrap();

        assert_eq!(std::fs::read(out_f.path()).unwrap(), new_data);
    }

    #[test]
    fn binary_content_roundtrip() {
        let old_data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let mut new_data = old_data.clone();
        // Flip some bytes to simulate a binary diff
        for i in (0..4096usize).step_by(17) {
            new_data[i] ^= 0xFF;
        }

        let old_f = write_temp(&old_data);
        let patch = make_patch(&old_data, &new_data);
        let patch_f = write_temp(&patch);
        let out_f = NamedTempFile::new().unwrap();

        let patch_sha = sha256_hex(&patch);
        let out_sha = sha256_hex(&new_data);

        apply_patch_fds(
            std::fs::File::open(old_f.path()).unwrap().into_raw_fd(),
            std::fs::File::open(patch_f.path()).unwrap().into_raw_fd(),
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(out_f.path())
                .unwrap()
                .into_raw_fd(),
            &patch_sha,
            &out_sha,
        )
        .unwrap();

        assert_eq!(std::fs::read(out_f.path()).unwrap(), new_data);
    }

    #[test]
    fn wrong_patch_sha256_is_rejected() {
        let old_data = b"old content abc";
        let new_data = b"new content xyz";

        let old_f = write_temp(old_data);
        let patch = make_patch(old_data, new_data);
        let patch_f = write_temp(&patch);
        let out_f = NamedTempFile::new().unwrap();

        let result = apply_patch_fds(
            std::fs::File::open(old_f.path()).unwrap().into_raw_fd(),
            std::fs::File::open(patch_f.path()).unwrap().into_raw_fd(),
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(out_f.path())
                .unwrap()
                .into_raw_fd(),
            "deadbeefdeadbeef", // ← wrong SHA
            &sha256_hex(new_data),
        );

        assert!(matches!(
            result,
            Err(aether_core::error::AetherError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn wrong_output_sha256_is_rejected() {
        let old_data = b"old version 1";
        let new_data = b"new version 2";

        let old_f = write_temp(old_data);
        let patch = make_patch(old_data, new_data);
        let patch_sha = sha256_hex(&patch);
        let patch_f = write_temp(&patch);
        let out_f = NamedTempFile::new().unwrap();

        let result = apply_patch_fds(
            std::fs::File::open(old_f.path()).unwrap().into_raw_fd(),
            std::fs::File::open(patch_f.path()).unwrap().into_raw_fd(),
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(out_f.path())
                .unwrap()
                .into_raw_fd(),
            &patch_sha,
            "deadbeefdeadbeef", // ← wrong expected output SHA
        );

        assert!(matches!(
            result,
            Err(aether_core::error::AetherError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn empty_sha256_strings_are_rejected() {
        let old_data = b"original";
        let new_data = b"modified";

        let old_f = write_temp(old_data);
        let patch = make_patch(old_data, new_data);
        let patch_f = write_temp(&patch);
        let out_f = NamedTempFile::new().unwrap();

        let result = apply_patch_fds(
            std::fs::File::open(old_f.path()).unwrap().into_raw_fd(),
            std::fs::File::open(patch_f.path()).unwrap().into_raw_fd(),
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(out_f.path())
                .unwrap()
                .into_raw_fd(),
            "",
            "",
        );

        assert!(matches!(
            result,
            Err(aether_core::error::AetherError::SecurityError(_))
        ));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Decompressor
// ─────────────────────────────────────────────────────────────────────────────

mod decompressor_tests {
    use super::*;
    use aether_core::decompressor::decompress_zstd_fds;

    fn zstd_compress(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        zstd::stream::copy_encode(std::io::Cursor::new(data), &mut out, 3).unwrap();
        out
    }

    #[test]
    fn roundtrip_small_text() {
        let original = b"Aether Suite decompressor test data.";
        let compressed = zstd_compress(original);

        let src_f = write_temp(&compressed);
        let dst_f = NamedTempFile::new().unwrap();

        let n = decompress_zstd_fds(
            std::fs::File::open(src_f.path()).unwrap().into_raw_fd(),
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(dst_f.path())
                .unwrap()
                .into_raw_fd(),
        )
        .unwrap();

        assert_eq!(std::fs::read(dst_f.path()).unwrap(), original);
        assert_eq!(n, original.len() as u64);
    }

    #[test]
    fn roundtrip_large_binary() {
        let original: Vec<u8> = (0..=255u8).cycle().take(512 * 1024).collect(); // 512 KB
        let compressed = zstd_compress(&original);

        let src_f = write_temp(&compressed);
        let dst_f = NamedTempFile::new().unwrap();

        let n = decompress_zstd_fds(
            std::fs::File::open(src_f.path()).unwrap().into_raw_fd(),
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(dst_f.path())
                .unwrap()
                .into_raw_fd(),
        )
        .unwrap();

        assert_eq!(n, original.len() as u64);
        assert_eq!(std::fs::read(dst_f.path()).unwrap(), original);
    }

    #[test]
    fn corrupted_input_returns_error() {
        let src_f = write_temp(b"this is not valid zstd data at all!");
        let dst_f = NamedTempFile::new().unwrap();

        let result = decompress_zstd_fds(
            std::fs::File::open(src_f.path()).unwrap().into_raw_fd(),
            std::fs::OpenOptions::new()
                .write(true)
                .open(dst_f.path())
                .unwrap()
                .into_raw_fd(),
        );

        assert!(matches!(
            result,
            Err(aether_core::error::AetherError::DecompressError(_))
        ));
    }

    #[test]
    fn empty_input_produces_empty_output() {
        // Empty zstd stream is valid
        let compressed = zstd_compress(b"");
        let src_f = write_temp(&compressed);
        let dst_f = NamedTempFile::new().unwrap();

        let n = decompress_zstd_fds(
            std::fs::File::open(src_f.path()).unwrap().into_raw_fd(),
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(dst_f.path())
                .unwrap()
                .into_raw_fd(),
        )
        .unwrap();

        assert_eq!(n, 0);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AetherEngine (orchestrator)
// ─────────────────────────────────────────────────────────────────────────────

mod engine_tests {
    use super::*;
    use aether_core::AetherEngine;

    #[test]
    fn two_engines_get_distinct_default_peer_ids() {
        let e1 = AetherEngine::new().unwrap();
        let e2 = AetherEngine::new().unwrap();
        // UUIDs are random — collision probability ≈ 0
        assert_ne!(
            e1.get_self_peer_id_for_test(),
            e2.get_self_peer_id_for_test()
        );
    }

    #[test]
    fn set_peer_id_is_reflected() {
        let engine = AetherEngine::new().unwrap();
        engine.set_self_peer_id("test-node-42".into());
        assert_eq!(engine.get_self_peer_id_for_test(), "test-node-42");
    }

    #[test]
    fn register_key_correct_length_succeeds() {
        let e = AetherEngine::new().unwrap();
        assert!(e.register_peer_key("p1".into(), vec![0xAAu8; 32]).is_ok());
    }

    #[test]
    fn register_key_wrong_lengths_fail() {
        let e = AetherEngine::new().unwrap();
        for len in [0usize, 16, 31, 33, 64] {
            assert!(
                e.register_peer_key("p".into(), vec![0u8; len]).is_err(),
                "Expected error for key length {len}"
            );
        }
    }

    #[test]
    fn server_starts_and_returns_nonzero_port() {
        let engine = new_engine_with_identity();
        let port = engine.start_server().expect("Server should start");
        assert!(port > 0, "Port must be > 0");
        engine.stop_server();
    }

    #[test]
    fn two_servers_get_different_ports() {
        let e1 = new_engine_with_identity();
        let e2 = new_engine_with_identity();
        let p1 = e1.start_server().unwrap();
        let p2 = e2.start_server().unwrap();
        assert_ne!(p1, p2, "Each server must bind a unique port");
        e1.stop_server();
        e2.stop_server();
    }

    #[test]
    fn ping_localhost_server_returns_true() {
        let engine = new_engine_with_identity();
        let port = engine.start_server().unwrap();
        // Give the server a moment to be ready
        std::thread::sleep(std::time::Duration::from_millis(50));
        let alive = engine.ping_peer("127.0.0.1".into(), port).unwrap();
        assert!(alive);
        engine.stop_server();
    }

    #[test]
    fn ping_unreachable_port_returns_false() {
        let engine = AetherEngine::new().unwrap();
        // Port 1 is almost certainly closed/refused in test environments
        let alive = engine.ping_peer("127.0.0.1".into(), 1).unwrap();
        assert!(!alive);
    }

    #[test]
    fn verify_manifest_with_invalid_key_returns_error() {
        let engine = AetherEngine::new().unwrap();
        let result = engine.verify_manifest(
            r#"{"id":"test","version":"1.0"}"#.into(),
            "deadbeef0011".into(),
            vec![0u8; 65], // clearly not a valid DER key
        );
        assert!(result.is_err());
    }

    #[test]
    fn decompress_pipe_roundtrip_via_engine() {
        let engine = AetherEngine::new().unwrap();
        let data: Vec<u8> = b"engine decompress test payload".to_vec();
        let mut compressed = Vec::new();
        zstd::stream::copy_encode(std::io::Cursor::new(&data), &mut compressed, 3).unwrap();

        let src_f = write_temp(&compressed);
        let dst_f = NamedTempFile::new().unwrap();

        let n = engine
            .decompress_file(
                std::fs::File::open(src_f.path()).unwrap().into_raw_fd(),
                std::fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(dst_f.path())
                    .unwrap()
                    .into_raw_fd(),
            )
            .unwrap();

        assert_eq!(n, data.len() as u64);
        assert_eq!(std::fs::read(dst_f.path()).unwrap(), data);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Security — HKDF key derivation
// ─────────────────────────────────────────────────────────────────────────────

mod hkdf_tests {
    use aether_core::security::SecurityManager;

    #[test]
    fn derived_key_differs_from_raw_ecdh_input() {
        let raw = vec![0xABu8; 32];
        let derived = SecurityManager::derive_hmac_key(&raw).unwrap();
        assert_ne!(
            derived.as_ref(),
            raw.as_slice(),
            "HKDF output must not equal raw ECDH input"
        );
    }

    #[test]
    fn hkdf_is_deterministic_for_same_input() {
        let raw = vec![0x42u8; 32];
        let d1 = SecurityManager::derive_hmac_key(&raw).unwrap();
        let d2 = SecurityManager::derive_hmac_key(&raw).unwrap();
        assert_eq!(d1, d2, "HKDF must be deterministic");
    }

    #[test]
    fn different_inputs_produce_different_keys() {
        let r1 = vec![0x11u8; 32];
        let r2 = vec![0x22u8; 32];
        let d1 = SecurityManager::derive_hmac_key(&r1).unwrap();
        let d2 = SecurityManager::derive_hmac_key(&r2).unwrap();
        assert_ne!(
            d1, d2,
            "Different ECDH secrets must produce different HMAC keys"
        );
    }

    #[test]
    fn ticket_roundtrip_still_works_through_hkdf() {
        // register_peer_key applies HKDF internally; tickets signed with the
        // raw secret should still verify after derivation.
        use aether_core::security::SecureKey;
        use aether_core::AetherEngine;

        let engine = AetherEngine::new().unwrap();
        let raw_secret = vec![0xDEu8; 32];
        engine
            .register_peer_key("peer-hkdf".into(), raw_secret.clone())
            .unwrap();

        // The stored key is derived, so generate a ticket using the *derived* key
        // to confirm the engine verifies tickets correctly against its stored key.
        let derived = SecurityManager::derive_hmac_key(&raw_secret).unwrap();
        let ticket = SecurityManager::generate_ticket(
            "model-x",
            "1.0",
            "seeder-1",
            &SecureKey(derived.to_vec()),
        )
        .unwrap();

        // Verify via the download handler path (which calls verify_ticket internally)
        // is hard to test without a real server; verify at the SecurityManager level.
        assert!(SecurityManager::verify_ticket(&ticket, &SecureKey(derived.to_vec()),).is_ok());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Seeder role — register_file_for_serving + HTTP download
// ─────────────────────────────────────────────────────────────────────────────

mod seeder_tests {
    use super::*;
    use aether_core::security::{SecureKey, SecurityManager};
    use aether_core::AetherEngine;

    /// Register a file, start a server, connect as a leecher and verify the
    /// downloaded bytes match the original. This is the first true end-to-end
    /// integration test covering both seeder and leecher roles.
    #[test]
    fn seeder_leecher_full_roundtrip() {
        // ── 1. Prepare file to serve ──────────────────────────────────────────
        let payload = b"Aether seeder integration test payload v2.3.2";
        let serve_f = write_temp(payload);

        // ── 2. Start seeder engine ────────────────────────────────────────────
        let seeder = new_engine_with_identity();
        let model_id = "integration-model";
        let raw_secret = vec![0x55u8; 32];

        seeder
            .register_file_for_serving(model_id.into(), serve_f.path().to_str().unwrap().into())
            .unwrap();

        seeder
            .register_peer_key("leecher-1".into(), raw_secret.clone())
            .unwrap();
        seeder
            .grant_peer_model_access("leecher-1".into(), model_id.into())
            .unwrap();
        let port = seeder.start_server().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(60));

        // ── 3. Build a valid ticket for the leecher ───────────────────────────
        let derived = SecurityManager::derive_hmac_key(&raw_secret).unwrap();
        let ticket = SecurityManager::generate_ticket(
            model_id,
            "1.0",
            "seeder-1",
            &SecureKey(derived.to_vec()),
        )
        .unwrap();

        // ── 4. Download via leecher engine ────────────────────────────────────
        let leecher = AetherEngine::new().unwrap();
        leecher.set_self_peer_id("leecher-1".into());
        leecher
            .register_peer_key("seeder-1".into(), raw_secret.clone())
            .unwrap();

        let out_f = NamedTempFile::new().unwrap();
        let expected = sha256_hex(payload);

        let out_fd = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(out_f.path())
            .unwrap()
            .into_raw_fd();

        leecher
            .download_model(
                "127.0.0.1".into(),
                port,
                "seeder-1".into(),
                ticket,
                expected.clone(),
                0, // fresh download
                out_fd,
            )
            .unwrap();

        // ── 5. Verify downloaded bytes ────────────────────────────────────────
        let downloaded = std::fs::read(out_f.path()).unwrap();
        assert_eq!(downloaded, payload, "Downloaded bytes must match original");
        assert_eq!(sha256_hex(&downloaded), expected, "SHA-256 must match");

        seeder.stop_server();
    }

    /// Verify that a fresh download truncates any stale bytes from a previous
    /// larger file (ADR-005 regression test with seeder in the loop).
    #[test]
    fn fresh_download_truncates_stale_tail_bytes() {
        let payload = b"short payload v2";
        let serve_f = write_temp(payload);

        let seeder = new_engine_with_identity();
        let raw_secret = vec![0x77u8; 32];
        seeder
            .register_file_for_serving(
                "trunc-model".into(),
                serve_f.path().to_str().unwrap().into(),
            )
            .unwrap();
        seeder
            .register_peer_key("leecher-trunc".into(), raw_secret.clone())
            .unwrap();
        seeder
            .grant_peer_model_access("leecher-trunc".into(), "trunc-model".into())
            .unwrap();
        let port = seeder.start_server().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(60));

        let derived = SecurityManager::derive_hmac_key(&raw_secret).unwrap();
        let ticket = SecurityManager::generate_ticket(
            "trunc-model",
            "1.0",
            "seeder-1",
            &SecureKey(derived.to_vec()),
        )
        .unwrap();

        // Pre-fill output file with more bytes than the payload.
        let out_f = NamedTempFile::new().unwrap();
        std::fs::write(
            out_f.path(),
            b"THIS IS OLD DATA THAT IS MUCH LONGER THAN THE NEW PAYLOAD",
        )
        .unwrap();

        let out_fd = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(out_f.path())
            .unwrap()
            .into_raw_fd();

        let leecher = AetherEngine::new().unwrap();
        leecher.set_self_peer_id("leecher-trunc".into());
        leecher
            .register_peer_key("seeder-1".into(), raw_secret.clone())
            .unwrap();
        leecher
            .download_model(
                "127.0.0.1".into(),
                port,
                "seeder-1".into(),
                ticket,
                sha256_hex(payload),
                0,
                out_fd,
            )
            .unwrap();

        let downloaded = std::fs::read(out_f.path()).unwrap();
        assert_eq!(downloaded, payload, "Stale tail bytes must be truncated");
        seeder.stop_server();
    }

    /// Resumed download: simulate partial file on disk, resume from offset,
    /// verify the complete file's SHA-256 (ADR-002 end-to-end regression).
    #[test]
    fn resume_download_full_file_sha256_verified() {
        let full_payload: Vec<u8> = (0..1024usize)
            .map(|i| ((i * 37 + 11) % 251) as u8)
            .collect();
        let serve_f = write_temp(&full_payload);

        let seeder = new_engine_with_identity();
        let raw_secret = vec![0x99u8; 32];
        seeder
            .register_file_for_serving(
                "resume-model".into(),
                serve_f.path().to_str().unwrap().into(),
            )
            .unwrap();
        seeder
            .register_peer_key("leecher-resume".into(), raw_secret.clone())
            .unwrap();
        seeder
            .grant_peer_model_access("leecher-resume".into(), "resume-model".into())
            .unwrap();
        let port = seeder.start_server().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(60));

        let derived = SecurityManager::derive_hmac_key(&raw_secret).unwrap();

        // ── Seed a partial file on disk ──────────────────────────────────────
        let out_f = NamedTempFile::new().unwrap();
        {
            std::fs::write(out_f.path(), &full_payload[..512]).unwrap();
        }

        // ── Session 2: resume from byte 512 ──────────────────────────────────
        {
            let ticket = SecurityManager::generate_ticket(
                "resume-model",
                "1.0",
                "seeder-1",
                &SecureKey(derived.to_vec()),
            )
            .unwrap();
            let leecher = AetherEngine::new().unwrap();
            leecher.set_self_peer_id("leecher-resume".into());
            leecher
                .register_peer_key("seeder-1".into(), raw_secret.clone())
                .unwrap();

            let out_fd = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(out_f.path())
                .unwrap()
                .into_raw_fd();

            leecher
                .download_model(
                    "127.0.0.1".into(),
                    port,
                    "seeder-1".into(),
                    ticket,
                    sha256_hex(&full_payload), // full-file SHA
                    512,                       // resume_from = 512 bytes already on disk
                    out_fd,
                )
                .unwrap();
        }

        let result = std::fs::read(out_f.path()).unwrap();
        assert_eq!(
            result, full_payload,
            "Resumed download must reconstruct exact bytes"
        );
        assert_eq!(
            sha256_hex(&result),
            sha256_hex(&full_payload),
            "Resumed download must pass full-file SHA-256 verification"
        );

        seeder.stop_server();
    }

    #[test]
    fn unauthorized_peer_cannot_download_other_model() {
        let payload = b"premium payload";
        let serve_f = write_temp(payload);

        let seeder = new_engine_with_identity();
        let raw_secret = vec![0xABu8; 32];
        seeder
            .register_file_for_serving("llm-pro".into(), serve_f.path().to_str().unwrap().into())
            .unwrap();
        seeder
            .register_peer_key("peer-basic".into(), raw_secret.clone())
            .unwrap();
        seeder
            .grant_peer_model_access("peer-basic".into(), "llm-lite".into())
            .unwrap();
        let port = seeder.start_server().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(60));

        let derived = SecurityManager::derive_hmac_key(&raw_secret).unwrap();
        let ticket = SecurityManager::generate_ticket(
            "llm-pro",
            "1.0",
            "seeder-1",
            &SecureKey(derived.to_vec()),
        )
        .unwrap();

        let leecher = AetherEngine::new().unwrap();
        leecher.set_self_peer_id("peer-basic".into());
        leecher
            .register_peer_key("seeder-1".into(), raw_secret.clone())
            .unwrap();
        let out_f = NamedTempFile::new().unwrap();
        let out_fd = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(out_f.path())
            .unwrap()
            .into_raw_fd();

        let result = leecher.download_model(
            "127.0.0.1".into(),
            port,
            "seeder-1".into(),
            ticket,
            sha256_hex(payload),
            0,
            out_fd,
        );
        assert!(matches!(
            result,
            Err(aether_core::error::AetherError::NetworkError(_))
        ));

        seeder.stop_server();
    }

    #[test]
    fn heartbeat_probes_real_server() {
        let engine = new_engine_with_identity();
        // Before start: heartbeat must fail
        assert!(
            engine.heartbeat().is_err(),
            "Heartbeat must fail before server starts"
        );

        engine.start_server().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(60));

        // After start: heartbeat must succeed
        assert!(
            engine.heartbeat().is_ok(),
            "Heartbeat must succeed while server is running"
        );

        engine.stop_server();
        std::thread::sleep(std::time::Duration::from_millis(60));

        // After stop: heartbeat must fail again
        assert!(
            engine.heartbeat().is_err(),
            "Heartbeat must fail after server stops"
        );
    }

    /// Mirrors the Android `startSeederNode` flow:
    ///   1. stop existing server (noop if none),
    ///   2. register file for serving,
    ///   3. grant peer model access,
    ///   4. start server,
    ///   5. leecher downloads and verifies content.
    #[test]
    fn start_seeder_node_full_flow() {
        let payload = b"Aether startSeederNode integration test v2.3.2";
        let serve_f = write_temp(payload);
        let seeder = new_engine_with_identity();
        let model_id = "seeder-flow-model";
        let raw_secret = vec![0xCCu8; 32];

        // Step 1: on a fresh engine there is no server to stop.
        // ADR-007: CancellationToken replaced Arc<Notify> — calling stop_server()
        // on a fresh engine is now safe (see unit test
        // stop_server_on_fresh_engine_does_not_poison_start). Skipped here
        // because real startSeederNode guards with isServerRunning().
        // seeder.stop_server();  // ← skipped: mirrors guarded startSeederNode

        // Step 2: register file
        seeder
            .register_file_for_serving(model_id.into(), serve_f.path().to_str().unwrap().into())
            .unwrap();

        // Step 3: register peer key + grant access
        seeder
            .register_peer_key("leecher-flow".into(), raw_secret.clone())
            .unwrap();
        seeder
            .grant_peer_model_access("leecher-flow".into(), model_id.into())
            .unwrap();

        // Step 4: start server
        let port = seeder.start_server().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Build ticket for leecher
        let derived = SecurityManager::derive_hmac_key(&raw_secret).unwrap();
        let ticket = SecurityManager::generate_ticket(
            model_id,
            "1.0",
            "seeder-1",
            &SecureKey(derived.to_vec()),
        )
        .unwrap();

        // Leecher downloads
        let leecher = AetherEngine::new().unwrap();
        leecher.set_self_peer_id("leecher-flow".into());
        leecher
            .register_peer_key("seeder-1".into(), raw_secret.clone())
            .unwrap();

        let out_f = NamedTempFile::new().unwrap();
        let expected = sha256_hex(payload);
        let out_fd = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(out_f.path())
            .unwrap()
            .into_raw_fd();

        leecher
            .download_model(
                "127.0.0.1".into(),
                port,
                "seeder-1".into(),
                ticket,
                expected.clone(),
                0,
                out_fd,
            )
            .unwrap();

        let downloaded = std::fs::read(out_f.path()).unwrap();
        assert_eq!(downloaded, payload, "Downloaded bytes must match original");
        assert_eq!(sha256_hex(&downloaded), expected, "SHA-256 must match");
        seeder.stop_server();
    }

    /// Verify that re-registering a model_id after stopServer replaces the served file.
    #[test]
    fn start_seeder_node_reregister_replaces_file() {
        let payload_v1 = b"version 1 content";
        let payload_v2 = b"version 2 content - updated";
        let serve_v1 = write_temp(payload_v1);
        let serve_v2 = write_temp(payload_v2);

        let seeder = new_engine_with_identity();
        let model_id = "reregister-model";
        let raw_secret = vec![0xDDu8; 32];

        seeder
            .register_file_for_serving(model_id.into(), serve_v1.path().to_str().unwrap().into())
            .unwrap();
        seeder
            .register_peer_key("leecher-re".into(), raw_secret.clone())
            .unwrap();
        seeder
            .grant_peer_model_access("leecher-re".into(), model_id.into())
            .unwrap();

        let port1 = seeder.start_server().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(60));

        let derived = SecurityManager::derive_hmac_key(&raw_secret).unwrap();
        let ticket1 = SecurityManager::generate_ticket(
            model_id,
            "1.0",
            "seeder-1",
            &SecureKey(derived.to_vec()),
        )
        .unwrap();

        let leecher = AetherEngine::new().unwrap();
        leecher.set_self_peer_id("leecher-re".into());
        leecher
            .register_peer_key("seeder-1".into(), raw_secret.clone())
            .unwrap();

        let out1 = NamedTempFile::new().unwrap();
        let out1_fd = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(out1.path())
            .unwrap()
            .into_raw_fd();
        leecher
            .download_model(
                "127.0.0.1".into(),
                port1,
                "seeder-1".into(),
                ticket1,
                sha256_hex(payload_v1),
                0,
                out1_fd,
            )
            .unwrap();
        assert_eq!(std::fs::read(out1.path()).unwrap(), payload_v1);

        // Re-register (startSeederNode sequence)
        seeder.stop_server();
        std::thread::sleep(std::time::Duration::from_millis(100));
        seeder
            .register_file_for_serving(model_id.into(), serve_v2.path().to_str().unwrap().into())
            .unwrap();
        let port2 = seeder.start_server().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Use version "2.0" to produce a distinct ticket nonce (avoids replay rejection)
        let ticket2 = SecurityManager::generate_ticket(
            model_id,
            "2.0",
            "seeder-1",
            &SecureKey(derived.to_vec()),
        )
        .unwrap();
        let out2 = NamedTempFile::new().unwrap();
        let out2_fd = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(out2.path())
            .unwrap()
            .into_raw_fd();
        leecher
            .download_model(
                "127.0.0.1".into(),
                port2,
                "seeder-1".into(),
                ticket2,
                sha256_hex(payload_v2),
                0,
                out2_fd,
            )
            .unwrap();
        assert_eq!(
            std::fs::read(out2.path()).unwrap(),
            payload_v2,
            "Re-registered model must serve new file"
        );
        seeder.stop_server();
    }

    /// Full startSeederNode cycle: server IS running, then stop→reregister→restart.
    /// This is the real-world scenario where stopServer is called on an active server.
    #[test]
    fn start_seeder_node_restart_while_running() {
        let payload_v1 = b"initial model content";
        let payload_v2 = b"updated model content after restart";
        let serve_v1 = write_temp(payload_v1);
        let serve_v2 = write_temp(payload_v2);

        let seeder = new_engine_with_identity();
        let model_id = "restart-model";
        let raw_secret = vec![0xEEu8; 32];

        // Initial start
        seeder
            .register_file_for_serving(model_id.into(), serve_v1.path().to_str().unwrap().into())
            .unwrap();
        seeder
            .register_peer_key("leecher-rst".into(), raw_secret.clone())
            .unwrap();
        seeder
            .grant_peer_model_access("leecher-rst".into(), model_id.into())
            .unwrap();

        let port1 = seeder.start_server().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Download v1
        let derived = SecurityManager::derive_hmac_key(&raw_secret).unwrap();
        let ticket1 = SecurityManager::generate_ticket(
            model_id,
            "1.0",
            "seeder-1",
            &SecureKey(derived.to_vec()),
        )
        .unwrap();

        let leecher = AetherEngine::new().unwrap();
        leecher.set_self_peer_id("leecher-rst".into());
        leecher
            .register_peer_key("seeder-1".into(), raw_secret.clone())
            .unwrap();

        let out1 = NamedTempFile::new().unwrap();
        let out1_fd = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(out1.path())
            .unwrap()
            .into_raw_fd();
        leecher
            .download_model(
                "127.0.0.1".into(),
                port1,
                "seeder-1".into(),
                ticket1,
                sha256_hex(payload_v1),
                0,
                out1_fd,
            )
            .unwrap();
        assert_eq!(std::fs::read(out1.path()).unwrap(), payload_v1);

        // ── startSeederNode: stop → reregister → restart ────────────────────
        seeder.stop_server();
        std::thread::sleep(std::time::Duration::from_millis(100));
        seeder
            .register_file_for_serving(model_id.into(), serve_v2.path().to_str().unwrap().into())
            .unwrap();
        let port2 = seeder.start_server().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Download v2 with a fresh ticket (different version to avoid replay)
        let ticket2 = SecurityManager::generate_ticket(
            model_id,
            "2.0",
            "seeder-1",
            &SecureKey(derived.to_vec()),
        )
        .unwrap();
        let out2 = NamedTempFile::new().unwrap();
        let out2_fd = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(out2.path())
            .unwrap()
            .into_raw_fd();
        leecher
            .download_model(
                "127.0.0.1".into(),
                port2,
                "seeder-1".into(),
                ticket2,
                sha256_hex(payload_v2),
                0,
                out2_fd,
            )
            .unwrap();
        assert_eq!(
            std::fs::read(out2.path()).unwrap(),
            payload_v2,
            "Restarted seeder must serve new file"
        );
        seeder.stop_server();
    }
}
