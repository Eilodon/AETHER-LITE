// rust_core/src/decompressor.rs
//! zstd streaming decompression via file descriptors.
//!
//! Decompresses a `.zst` file created by `forge.py` (Zstandard level 19)
//! into a raw binary output file, without loading the entire payload into RAM.

use crate::config::Config;
use crate::error::AetherError;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::os::fd::FromRawFd;
use tracing::{info, warn};

/// Decompress a zstd-compressed file descriptor into an output file descriptor.
///
/// # Arguments
/// * `compressed_fd` – Readable FD of the `.zst` file. Ownership → Rust.
/// * `output_fd`     – Writable FD of the destination. Ownership → Rust.
///
/// Both FDs are closed when this function returns.
pub fn decompress_zstd_fds(compressed_fd: i32, output_fd: i32) -> Result<u64, AetherError> {
    info!(
        "Decompressing: compressed_fd={} → output_fd={}",
        compressed_fd, output_fd
    );

    // SAFETY: caller transferred exclusive FD ownership.
    let compressed_file = unsafe { File::from_raw_fd(compressed_fd) };
    let output_file = unsafe { File::from_raw_fd(output_fd) };

    let mut decoder = zstd::Decoder::new(compressed_file)
        .map_err(|e| AetherError::DecompressError(format!("Decoder init failed: {}", e)))?;

    // ADR-004: Dynamic decompression limit based on available disk space.
    // The fixed 2GB ceiling can exhaust disk on low-storage mobile devices.
    // We now cap at 80% of available disk space, never exceeding the
    // absolute MAX_DECOMPRESSED_SIZE bomb-protection ceiling.
    let dynamic_limit = match available_disk_space(&output_file) {
        Ok(free) => {
            let safe = (free as f64 * 0.8) as u64;
            let limit = std::cmp::min(Config::MAX_DECOMPRESSED_SIZE, safe);
            info!(
                "ADR-004: disk free={} bytes, dynamic limit={} bytes (cap={})",
                free, limit, Config::MAX_DECOMPRESSED_SIZE
            );
            limit
        }
        Err(e) => {
            warn!("ADR-004: cannot query disk space ({}), falling back to static limit", e);
            Config::MAX_DECOMPRESSED_SIZE
        }
    };

    let mut writer = BufWriter::new(output_file);
    let mut buf = vec![0u8; 256 * 1024]; // 256 KB chunks
    let mut total_bytes = 0u64;

    loop {
        match decoder.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total_bytes += n as u64;
                // SECURITY: Prevent decompression bomb attacks (dynamic ceiling)
                if total_bytes > dynamic_limit {
                    return Err(AetherError::DecompressError(format!(
                        "Decompressed size exceeds dynamic limit of {} bytes (bomb protection, disk-space-aware)",
                        dynamic_limit
                    )));
                }
                writer
                    .write_all(&buf[..n])
                    .map_err(|e| AetherError::DecompressError(format!("Write failed: {}", e)))?;
            }
            Err(e) => {
                return Err(AetherError::DecompressError(format!("Read failed: {}", e)));
            }
        }
    }

    writer
        .flush()
        .map_err(|e| AetherError::DecompressError(format!("Flush failed: {}", e)))?;

    info!("Decompression complete: {} bytes written", total_bytes);
    Ok(total_bytes)
}

/// Query available disk space for the filesystem containing the given file.
/// Uses POSIX `fstatfs` which works on Linux, Android, macOS, and iOS.
fn available_disk_space(file: &File) -> std::io::Result<u64> {
    use std::os::unix::io::AsRawFd;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    let fd = file.as_raw_fd();
    if unsafe { libc::fstatfs(fd, &mut stat) } == 0 {
        // f_bavail = free blocks available to unprivileged process
        let free = stat.f_bavail as u64 * stat.f_bsize as u64;
        Ok(free)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::io::IntoRawFd;
    use tempfile::NamedTempFile;

    #[test]
    fn compress_then_decompress_roundtrip() {
        let original = b"The quick brown fox jumps over the lazy dog. ".repeat(1000);

        // Compress using zstd encoder
        let compressed_f = NamedTempFile::new().unwrap();
        {
            let mut enc = zstd::Encoder::new(
                std::fs::File::create(compressed_f.path()).unwrap(),
                3, // low level for test speed
            )
            .unwrap();
            enc.write_all(&original).unwrap();
            enc.finish().unwrap();
        }

        // Decompress via our function
        let output_f = NamedTempFile::new().unwrap();
        let comp_fd = std::fs::File::open(compressed_f.path())
            .unwrap()
            .into_raw_fd();
        let out_fd = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(output_f.path())
            .unwrap()
            .into_raw_fd();

        let bytes_written = decompress_zstd_fds(comp_fd, out_fd).unwrap();

        let result = std::fs::read(output_f.path()).unwrap();
        assert_eq!(result, original);
        assert_eq!(bytes_written, original.len() as u64);
    }

    #[test]
    fn invalid_data_returns_error() {
        let bad_f = NamedTempFile::new().unwrap();
        std::fs::write(bad_f.path(), b"this is not zstd").unwrap();

        let out_f = NamedTempFile::new().unwrap();
        let src_fd = std::fs::File::open(bad_f.path()).unwrap().into_raw_fd();
        let dst_fd = std::fs::OpenOptions::new()
            .write(true)
            .open(out_f.path())
            .unwrap()
            .into_raw_fd();

        let result = decompress_zstd_fds(src_fd, dst_fd);
        assert!(matches!(result, Err(AetherError::DecompressError(_))));
    }
}
