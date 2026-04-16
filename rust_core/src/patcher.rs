// rust_core/src/patcher.rs
//! Surgical binary-delta patching (bsdiff algorithm).
//!
//! Fix v2.3:
//!   • Verify SHA-256 of the patch file before applying (detects corruption).
//!   • Verify SHA-256 of the output file after applying (guarantees correctness).

use crate::config::Config;
use crate::error::AetherError;
use memmap2::Mmap;
use qbsdiff::Bspatch;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::os::fd::FromRawFd;
use tracing::{error, info};

/// Apply a bsdiff patch to produce a new file, with integrity checks.
///
/// # Arguments
/// * `old_fd`          – Readable FD of the existing (old) file.
/// * `patch_fd`        – Readable FD of the `.bin` delta file.
/// * `new_fd`          – Writable FD for the patched output.
/// * `expected_patch_sha256`  – Hex SHA-256 of the patch file (empty = skip).
/// * `expected_output_sha256` – Hex SHA-256 of the expected output (empty = skip).
///
/// # Safety
/// All FDs must be valid and exclusively owned by the caller, who must
/// **not** close them after calling this function.
pub fn apply_patch_fds(
    old_fd: i32,
    patch_fd: i32,
    new_fd: i32,
    expected_patch_sha256: &str,
    expected_output_sha256: &str,
) -> Result<(), AetherError> {
    if expected_patch_sha256.trim().is_empty() || expected_output_sha256.trim().is_empty() {
        return Err(AetherError::SecurityError(
            "expected patch and output SHA-256 values are required".into(),
        ));
    }

    info!(
        "Surgical patch: old_fd={} patch_fd={} new_fd={}",
        old_fd, patch_fd, new_fd
    );

    // SAFETY: caller guarantees exclusive ownership.
    let old_file = unsafe { File::from_raw_fd(old_fd) };
    let patch_file = unsafe { File::from_raw_fd(patch_fd) };
    let new_file = unsafe { File::from_raw_fd(new_fd) };
    enforce_patch_memory_gate(&old_file, &patch_file)?;

    // ── 1. Memory-map old and patch files (ADR-006) ──────────────────────
    // ADR-006: Replace read_to_end with mmap. The OS manages paging,
    // significantly reducing physical RAM pressure (RSS) on mobile devices.
    let old_mmap = unsafe { Mmap::map(&old_file) }
        .map_err(|e| AetherError::PatchError(format!("Failed to mmap old file: {}", e)))?;
    let patch_mmap = unsafe { Mmap::map(&patch_file) }
        .map_err(|e| AetherError::PatchError(format!("Failed to mmap patch file: {}", e)))?;

    // Verify patch file integrity before applying
    if !expected_patch_sha256.is_empty() {
        let actual_patch_sha = hex::encode(Sha256::digest(&patch_mmap[..]));
        if actual_patch_sha != expected_patch_sha256 {
            error!(
                "Patch SHA-256 mismatch: expected={} actual={}",
                expected_patch_sha256, actual_patch_sha
            );
            return Err(AetherError::ChecksumMismatch {
                expected: expected_patch_sha256.to_string(),
                actual: actual_patch_sha,
            });
        }
        info!("Patch file SHA-256 verified ✓");
    }

    // ── 2. Apply BSDIFF40 patch ────────────────────────────────────────────
    let mut new_writer = BufWriter::new(new_file);

    let patcher = Bspatch::new(&patch_mmap[..]).map_err(|e| {
        error!("bspatch parse error: {:?}", e);
        AetherError::PatchError(format!("bspatch parse: {}", e))
    })?;
    patcher.apply(&old_mmap[..], &mut new_writer).map_err(|e| {
        error!("bspatch apply error: {:?}", e);
        AetherError::PatchError(format!("bspatch apply: {}", e))
    })?;

    new_writer
        .flush()
        .map_err(|e| AetherError::PatchError(format!("Flush failed: {}", e)))?;

    info!("Patch applied successfully");

    // ── 3. Verify output integrity ────────────────────────────────────────
    if !expected_output_sha256.is_empty() {
        let inner = new_writer
            .into_inner()
            .map_err(|e| AetherError::PatchError(format!("Buffer flush error: {}", e)))?;

        verify_output_via_fd(&inner, expected_output_sha256)?;
    }

    info!("Surgical patch complete ✓");
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn enforce_patch_memory_gate(old_file: &File, patch_file: &File) -> Result<(), AetherError> {
    let old_len = old_file
        .metadata()
        .map_err(|e| AetherError::PatchError(format!("Failed to stat old file: {}", e)))?
        .len();
    let patch_len = patch_file
        .metadata()
        .map_err(|e| AetherError::PatchError(format!("Failed to stat patch file: {}", e)))?
        .len();

    if patch_len > Config::MAX_PATCH_DELTA_BYTES {
        return Err(AetherError::PatchError(format!(
            "Patch delta is {} bytes; current mobile-safe ceiling is {} bytes",
            patch_len,
            Config::MAX_PATCH_DELTA_BYTES
        )));
    }

    let combined = old_len.saturating_add(patch_len);
    if combined > Config::MAX_PATCH_BUFFERED_INPUT_BYTES {
        return Err(AetherError::PatchError(format!(
            "Patch inputs (old+patch) total {} bytes, exceeding the {} byte ceiling (virtual address space guard)",
            combined,
            Config::MAX_PATCH_BUFFERED_INPUT_BYTES
        )));
    }

    Ok(())
}

/// Reopen the output file via the kernel fd symlink and hash its full contents.
/// Works on Linux (via /proc/self/fd/<n>) and macOS/iOS (via /dev/fd/<n>).
fn verify_output_via_fd(file: &File, expected_sha256: &str) -> Result<(), AetherError> {
    use std::os::unix::io::AsRawFd;

    let fd = file.as_raw_fd();

    #[cfg(target_os = "linux")]
    let proc_path = format!("/proc/self/fd/{}", fd);
    #[cfg(not(target_os = "linux"))]
    let proc_path = format!("/dev/fd/{}", fd);

    let mut f = std::fs::File::open(&proc_path)
        .map_err(|e| AetherError::PatchError(format!("Cannot reopen output fd: {}", e)))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) => return Err(AetherError::PatchError(format!("Hash read failed: {}", e))),
        }
    }
    let actual = hex::encode(hasher.finalize());
    if actual != expected_sha256 {
        error!(
            "Output SHA-256 mismatch: expected={} actual={}",
            expected_sha256, actual
        );
        return Err(AetherError::ChecksumMismatch {
            expected: expected_sha256.to_string(),
            actual,
        });
    }
    info!("Output SHA-256 verified ✓");
    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use qbsdiff::{Bsdiff, ParallelScheme};
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn sha256_of(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        hex::encode(h.finalize())
    }

    /// Verify a round-trip: create patch from old→new, apply, check output.
    #[test]
    fn bsdiff_roundtrip() {
        let old_data: Vec<u8> = b"Hello, World! This is version 1.".to_vec();
        let new_data: Vec<u8> = b"Hello, World! This is version 2.".to_vec();

        // Create temp files
        let mut old_f = NamedTempFile::new().unwrap();
        let mut new_f = NamedTempFile::new().unwrap();
        let patch_f = NamedTempFile::new().unwrap();
        let output_f = NamedTempFile::new().unwrap();

        old_f.write_all(&old_data).unwrap();
        new_f.write_all(&new_data).unwrap();
        old_f.flush().unwrap();
        new_f.flush().unwrap();

        let patch_path = patch_f.path().to_str().unwrap().to_string();
        let old_path = old_f.path().to_str().unwrap().to_string();
        let new_path = new_f.path().to_str().unwrap().to_string();

        // Generate a BSDIFF40-compatible patch using the same algorithm family
        // as forge.py.
        {
            let old_bytes = std::fs::read(&old_path).unwrap();
            let new_bytes = std::fs::read(&new_path).unwrap();
            let mut patch_out = std::fs::File::create(&patch_path).unwrap();
            Bsdiff::new(&old_bytes, &new_bytes)
                .parallel_scheme(ParallelScheme::Never)
                .compare(&mut patch_out)
                .unwrap();
        }

        // Apply patch
        let old_fd = std::fs::File::open(&old_path).unwrap();
        let patch_fd = std::fs::File::open(&patch_path).unwrap();
        let output_fd = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(output_f.path())
            .unwrap();

        let expected_out_sha = sha256_of(&new_data);
        let patch_sha = sha256_of(&std::fs::read(&patch_path).unwrap());

        use std::os::unix::io::IntoRawFd;
        apply_patch_fds(
            old_fd.into_raw_fd(),
            patch_fd.into_raw_fd(),
            output_fd.into_raw_fd(),
            &patch_sha,
            &expected_out_sha,
        )
        .unwrap();

        let result = std::fs::read(output_f.path()).unwrap();
        assert_eq!(result, new_data);
    }

    #[test]
    fn wrong_patch_sha256_rejected() {
        // Full flow: generate a valid patch, then call apply_patch_fds with a
        // deliberately wrong expected_patch_sha256 and confirm it is rejected.
        let old_data: Vec<u8> = b"version 1 data".to_vec();
        let new_data: Vec<u8> = b"version 2 data".to_vec();

        let mut old_f = NamedTempFile::new().unwrap();
        let mut new_f = NamedTempFile::new().unwrap();
        let patch_f = NamedTempFile::new().unwrap();
        let output_f = NamedTempFile::new().unwrap();

        old_f.write_all(&old_data).unwrap();
        old_f.flush().unwrap();
        new_f.write_all(&new_data).unwrap();
        new_f.flush().unwrap();

        let old_path = old_f.path().to_str().unwrap().to_string();
        let new_path = new_f.path().to_str().unwrap().to_string();
        let patch_path = patch_f.path().to_str().unwrap().to_string();

        {
            let old_bytes = std::fs::read(&old_path).unwrap();
            let new_bytes = std::fs::read(&new_path).unwrap();
            let mut out = std::fs::File::create(&patch_path).unwrap();
            Bsdiff::new(&old_bytes, &new_bytes)
                .parallel_scheme(ParallelScheme::Never)
                .compare(&mut out)
                .unwrap();
        }

        use std::os::unix::io::IntoRawFd;
        let old_fd = std::fs::File::open(&old_path).unwrap().into_raw_fd();
        let patch_fd = std::fs::File::open(&patch_path).unwrap().into_raw_fd();
        let output_fd = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(output_f.path())
            .unwrap()
            .into_raw_fd();

        let result = apply_patch_fds(
            old_fd,
            patch_fd,
            output_fd,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", // wrong SHA
            &sha256_of(&new_data),
        );
        assert!(
            matches!(result, Err(AetherError::ChecksumMismatch { .. })),
            "Expected ChecksumMismatch, got {:?}",
            result
        );
    }

    #[test]
    fn python_bsdiff4_patch_is_accepted() {
        let old_data = b"Hello World version 1.0 test data\n".to_vec();
        let new_data = b"Hello World version 2.0 test data with extra bytes\n".to_vec();
        let patch = BASE64.decode(
            "QlNESUZGNDAuAAAAAAAAACsAAAAAAAAAMwAAAAAAAABCWmg5MUFZJlNZBRPIWwAABfAASAgQACAAIAAhKabQZoF8CuF3JFOFCQBRPIWwQlpoOTFBWSZTWVn4aFsAAADgAGBAQAAgADDNNBJoNpMnF3JFOFCQWfhoW0JaaDkxQVkmU1kuRsb2AAAB0YAAEEAAMmAc4CAAIp6ADQgGgClhaewMFnTDHhdyRThQkC5GxvY=",
        ).unwrap();

        let old_f = NamedTempFile::new().unwrap();
        let patch_f = NamedTempFile::new().unwrap();
        let output_f = NamedTempFile::new().unwrap();
        std::fs::write(old_f.path(), &old_data).unwrap();
        std::fs::write(patch_f.path(), &patch).unwrap();

        let expected_out_sha = sha256_of(&new_data);
        let patch_sha = sha256_of(&patch);

        use std::os::unix::io::IntoRawFd;
        apply_patch_fds(
            std::fs::File::open(old_f.path()).unwrap().into_raw_fd(),
            std::fs::File::open(patch_f.path()).unwrap().into_raw_fd(),
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(output_f.path())
                .unwrap()
                .into_raw_fd(),
            &patch_sha,
            &expected_out_sha,
        )
        .unwrap();

        let result = std::fs::read(output_f.path()).unwrap();
        assert_eq!(result, new_data);
    }

    #[test]
    fn empty_patch_or_output_sha_is_rejected() {
        let old_f = NamedTempFile::new().unwrap();
        let patch_f = NamedTempFile::new().unwrap();
        let output_f = NamedTempFile::new().unwrap();
        std::fs::write(old_f.path(), b"old").unwrap();
        std::fs::write(patch_f.path(), b"patch").unwrap();

        use std::os::unix::io::IntoRawFd;
        let result = apply_patch_fds(
            std::fs::File::open(old_f.path()).unwrap().into_raw_fd(),
            std::fs::File::open(patch_f.path()).unwrap().into_raw_fd(),
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(output_f.path())
                .unwrap()
                .into_raw_fd(),
            "",
            "abc",
        );

        assert!(matches!(result, Err(AetherError::SecurityError(_))));
    }

    #[test]
    fn oversized_patch_file_is_rejected_before_reading() {
        let old_f = NamedTempFile::new().unwrap();
        let patch_f = NamedTempFile::new().unwrap();
        let output_f = NamedTempFile::new().unwrap();

        std::fs::write(old_f.path(), b"old").unwrap();
        std::fs::write(patch_f.path(), b"patch").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(patch_f.path())
            .unwrap()
            .set_len(Config::MAX_PATCH_DELTA_BYTES + 1)
            .unwrap();

        use std::os::unix::io::IntoRawFd;
        let result = apply_patch_fds(
            std::fs::File::open(old_f.path()).unwrap().into_raw_fd(),
            std::fs::File::open(patch_f.path()).unwrap().into_raw_fd(),
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(output_f.path())
                .unwrap()
                .into_raw_fd(),
            &"00".repeat(32),
            &"11".repeat(32),
        );

        assert!(matches!(result, Err(AetherError::PatchError(_))));
        assert_eq!(result.unwrap_err().to_string(), "Patch failed");
    }
}
