#!/usr/bin/env python3
"""
tools/forge.py  –  Aether Forge v2.3
======================================
Model deployment admin tool.

Install:
    pip install cryptography zstandard click bsdiff4

Commands:
    forge keygen   – Generate admin ECDSA key pair
    forge publish  – Compress, patch, sign and export a deployment package
    forge verify   – Verify a manifest.json signature
    forge info     – Show file stats (size + SHA-256)
"""

import click
import zstandard as zstd
import bsdiff4
import os
import sys
import json
import time
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature


# ── Helpers ────────────────────────────────────────────────────────────────────

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def load_private_key(path: str, passphrase: str | None = None) -> ec.EllipticCurvePrivateKey:
    with open(path, "rb") as f:
        password = None if passphrase is None else passphrase.encode("utf-8")
        return serialization.load_pem_private_key(f.read(), password=password)


def load_public_key(path: str) -> ec.EllipticCurvePublicKey:
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# ── Core functions ─────────────────────────────────────────────────────────────

def canonical_json(obj: dict) -> str:
    """
    Produce the deterministic JSON string used for signing.

    Fix v2.3: This function is now shared by both sign and verify paths,
    eliminating any possibility of sign/verify mismatch from different
    serialization formats. Matches AetherService.toCanonicalJson() and
    AetherManager.canonicalJSON() on mobile.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sign_manifest(payload: dict, private_key: ec.EllipticCurvePrivateKey) -> str:
    """Sign the canonical JSON of payload with ECDSA-P256-SHA256."""
    canonical = canonical_json(payload)
    signature = private_key.sign(canonical.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    return signature.hex()


def verify_manifest_sig(
    payload: dict, sig_hex: str, public_key: ec.EllipticCurvePublicKey
) -> bool:
    try:
        canonical = canonical_json(payload)
        public_key.verify(
            bytes.fromhex(sig_hex),
            canonical.encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except InvalidSignature:
        return False


def compress_file(src: str, dst: str, level: int = 19, dry_run: bool = False) -> int:
    """Zstd-compress src → dst. Returns output size. Skips I/O in dry-run mode."""
    cctx = zstd.ZstdCompressor(level=level, threads=-1)
    if dry_run:
        class _CountingWriter:
            def __init__(self) -> None:
                self.size = 0

            def write(self, data: bytes) -> int:
                self.size += len(data)
                return len(data)

            def flush(self) -> None:
                return None

        counter = _CountingWriter()
        with open(src, "rb") as s:
            cctx.copy_stream(s, counter)
        return counter.size
    with open(src, "rb") as s, open(dst, "wb") as d:
        cctx.copy_stream(s, d)
    return os.path.getsize(dst)


def create_patch(old: str, new_: str, patch: str, dry_run: bool = False) -> int:
    """Create bsdiff4 delta. Returns patch size. Skips I/O in dry-run mode."""
    click.echo(f"  🔬  Diffing  {Path(old).name}  →  {Path(new_).name}")
    if dry_run:
        old_size = os.path.getsize(old)
        new_size = os.path.getsize(new_)
        est = max(0, new_size - old_size) + 512  # rough estimate
        click.echo(f"  [dry-run]  Estimated patch size: ~{human_size(est)}")
        return est
    bsdiff4.file_diff(old, new_, patch)
    size = os.path.getsize(patch)
    reduction = 1.0 - size / max(1, os.path.getsize(new_))
    click.echo(f"  📦  Patch: {human_size(size)}  (saved {reduction:.0%} vs full)")
    return size


# ── CLI ────────────────────────────────────────────────────────────────────────

@click.group()
@click.version_option("2.3.2")
def cli():
    """🔥  Aether Forge – model deployment admin tool."""
    pass


# ── keygen ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--out", default="keys", show_default=True)
@click.option("--passphrase", default=None, help="Encrypt admin_private.pem with this passphrase.")
def keygen(out: str, passphrase: str | None):
    """Generate an ECDSA-P256 admin key pair.

    \b
    admin_private.pem  →  Keep secret. Never commit.
    app_public.pem     →  Bundle in the mobile app binary.
    """
    os.makedirs(out, exist_ok=True)
    priv = ec.generate_private_key(ec.SECP256R1())

    encryption = (
        serialization.NoEncryption()
        if not passphrase
        else serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
    )

    with open(f"{out}/admin_private.pem", "wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        ))
    with open(f"{out}/app_public.pem", "wb") as f:
        f.write(priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    click.echo(f"🔑  Keys written to {out}/")
    if passphrase:
        click.echo("    admin_private.pem  ← encrypted with provided passphrase")
    else:
        click.echo("    admin_private.pem  ← UNENCRYPTED, keep secret, never commit")
    click.echo(f"    app_public.pem     ← embed in APK / app bundle")


# ── publish ────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--new",  "new_file",  required=True, type=click.Path(exists=True))
@click.option("--old",  "old_file",  default=None,  type=click.Path(exists=True))
@click.option("--id",   "model_id",  required=True)
@click.option("--ver",  "version",   required=True)
@click.option("--seq",  "sequence",  default=None, type=int,
              help="Monotonic sequence number (ADR-016). Required for production manifests.")
@click.option("--key",  "key_path",  default=None, type=click.Path(exists=True),
              help="Path to admin_private.pem. Required unless --dry-run is set.")
@click.option("--passphrase", default=None, help="Passphrase for encrypted admin_private.pem.")
@click.option("--cdn",  "cdn_base",  default="https://cdn.example.com/models", show_default=True)
@click.option("--out",  "out_dir",   default="dist", show_default=True)
@click.option("--compress-level", default=19, show_default=True, type=click.IntRange(1, 22))
@click.option("--dry-run", is_flag=True, default=False,
              help="Simulate without writing any output files. --key is not required.")
def publish(new_file, old_file, model_id, version, sequence, key_path, passphrase,
            cdn_base, out_dir, compress_level, dry_run):
    """Compress, patch (if --old given), sign, and export a deployment package.

    \b
    With --dry-run: prints what would happen without writing any files or signing.
    Useful for estimating output sizes before a slow compression run.
    The --key flag is optional in dry-run mode; no signing occurs.
    """
    # Guard: --key is mandatory for a real publish.
    if not dry_run and not key_path:
        raise click.UsageError("--key is required when not using --dry-run.")

    if not dry_run:
        os.makedirs(out_dir, exist_ok=True)

    # Only load the private key when actually signing.
    priv_key  = None if dry_run else load_private_key(key_path, passphrase=passphrase)
    dr_prefix = "[dry-run] " if dry_run else ""

    click.echo(f"\n🔥  {dr_prefix}Publishing {model_id} v{version}\n")

    # ── 1. Compress full version ──────────────────────────────────────────────
    full_filename = f"{model_id}_v{version}_full.zst"
    full_path     = f"{out_dir}/{full_filename}"
    raw_size      = os.path.getsize(new_file)

    click.echo(f"  📦  {dr_prefix}Compressing (Zstd level {compress_level})…")
    full_size = compress_file(new_file, full_path, compress_level, dry_run=dry_run)
    ratio     = raw_size / max(1, full_size)
    click.echo(f"      {human_size(raw_size)} → {human_size(full_size)}  (ratio {ratio:.2f}x)")

    # ADR-007: dry-run must not hash new_file (uncompressed) and report it as the
    # compressed artefact's SHA-256 — that value would be wrong and misleading.
    full_sha = "[dry-run: sha256 not computed]" if dry_run else sha256_file(full_path)

    # ── 2. Create delta patch (optional) ─────────────────────────────────────
    patch_info = None
    if old_file:
        patch_filename = f"{model_id}_v{version}_patch.bin"
        patch_path     = f"{out_dir}/{patch_filename}"
        patch_size     = create_patch(old_file, new_file, patch_path, dry_run=dry_run)
        patch_sha      = "[dry-run: sha256 not computed]" if dry_run else sha256_file(patch_path)
        patch_info     = {
            "url":       f"{cdn_base}/{patch_filename}",
            "filename":  patch_filename,
            "size":      patch_size,
            "sha256":    patch_sha,
            "algorithm": "bsdiff4",
        }

    # ── 3. Build + sign manifest ──────────────────────────────────────────────
    # ADR-016: sequence is mandatory for real publishes, optional for dry-run.
    if not dry_run and sequence is None:
        raise click.UsageError("--seq is required when not using --dry-run (ADR-016: monotonic sequence)")
    payload = {
        "id":        model_id,
        "version":   version,
        "sequence":  sequence,  # ADR-016: monotonic counter, None only in dry-run
        "timestamp": int(time.time()),
        "full": {
            "url":      f"{cdn_base}/{full_filename}",
            "filename": full_filename,
            "size":     full_size,
            "sha256":   full_sha,
        },
        "patch": patch_info,
    }

    if dry_run:
        # Do NOT sign a dry-run manifest. Signing a payload that contains
        # placeholder SHA values produces a cryptographically valid signature
        # over garbage data — a dry-run manifest could accidentally pass mobile
        # signature verification. The "_dry_run" sentinel causes `forge verify`
        # (and any conforming mobile verifier) to explicitly reject it.
        final_manifest = {
            "payload":   payload,
            "signature": None,   # no signature; serialised as JSON null
            "_dry_run":  True,   # explicit machine-readable sentinel
        }
    else:
        signature      = sign_manifest(payload, priv_key)
        final_manifest = {"payload": payload, "signature": signature}

    manifest_path = f"{out_dir}/manifest.json"
    if not dry_run:
        with open(manifest_path, "w") as f:
            json.dump(final_manifest, f, indent=2)

    # ── 4. Summary ────────────────────────────────────────────────────────────
    click.echo(f"\n{'[DRY-RUN] Would produce' if dry_run else '✅  Ready'} in {out_dir}/")
    click.echo(f"    Full  : {full_filename}  ({human_size(full_size)})")
    if patch_info:
        click.echo(f"    Patch : {patch_info['filename']}  ({human_size(patch_info['size'])})")
    click.echo(f"    Manifest: manifest.json  {'(not written — dry-run)' if dry_run else '(signed ✓)'}")


# ── verify ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--manifest", "mpath", required=True, type=click.Path(exists=True))
@click.option("--key",      "kpath", required=True, type=click.Path(exists=True))
def verify(mpath: str, kpath: str):
    """Verify the ECDSA signature of a manifest.json."""
    with open(mpath) as f:
        data = json.load(f)

    # Reject dry-run manifests explicitly — they have no valid signature and
    # contain placeholder SHA values. Accepting them would be a no-op at best
    # and a security hole at worst if somehow shipped to production.
    if data.get("_dry_run"):
        click.echo(
            "❌  This is a dry-run manifest — it has no signature and cannot be verified.\n"
            "    Re-run publish without --dry-run to produce a signed manifest.",
            err=True,
        )
        sys.exit(2)

    pub_key = load_public_key(kpath)
    payload   = data.get("payload", {})
    sig_hex   = data.get("signature", "")

    if verify_manifest_sig(payload, sig_hex, pub_key):
        click.echo("✅  Signature VALID")
        click.echo(f"    Model   : {payload.get('id')}  v{payload.get('version')}")
        seq = payload.get("sequence")
        if seq is not None:
            click.echo(f"    Sequence: {seq}")
        else:
            click.echo("    Sequence: ⚠️  MISSING (ADR-016: manifests must have monotonic sequence)")
        click.echo(f"    Issued  : {time.ctime(payload.get('timestamp', 0))}")
    else:
        click.echo("❌  Signature INVALID — manifest may have been tampered with!", err=True)
        sys.exit(1)


# ── info ───────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
def info(file_path: str):
    """Print size and SHA-256 of a file."""
    size = os.path.getsize(file_path)
    sha  = sha256_file(file_path)
    click.echo(f"📄  {file_path}")
    click.echo(f"    Size   : {human_size(size)}  ({size} bytes)")
    click.echo(f"    SHA256 : {sha}")


if __name__ == "__main__":
    cli()
