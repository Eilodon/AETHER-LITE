#!/usr/bin/env python3
"""
tools/forge_test.py – Unit tests for forge.py
=============================================

Run with:
    pip install pytest cryptography zstandard bsdiff4
    pytest tools/forge_test.py -v
"""

import json
import os
import sys
import time
import hashlib
import tempfile
import pytest

# Make forge importable
sys.path.insert(0, os.path.dirname(__file__))
import forge as f
from cryptography.hazmat.primitives.asymmetric import ec


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def key_pair():
    """Fresh ECDSA P-256 key pair for each test."""
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


@pytest.fixture
def sample_payload():
    return {
        "id":        "llm-mini",
        "version":   "2.0.0",
        "timestamp": 1713000000,
        "full": {"url": "https://cdn/model.zst", "size": 1024, "sha256": "abc123"},
        "patch": None,
    }


# ── canonical_json ────────────────────────────────────────────────────────────

class TestCanonicalJson:

    def test_sorts_keys(self):
        result = f.canonical_json({"z": "last", "a": "first", "m": "mid"})
        assert result == '{"a":"first","m":"mid","z":"last"}'

    def test_no_whitespace(self):
        result = f.canonical_json({"key": "val"})
        assert " " not in result

    def test_matches_mobile_output(self):
        payload = {"id": "llm-mini", "version": "2.0", "timestamp": 1713000000}
        result  = f.canonical_json(payload)
        assert result == '{"id":"llm-mini","timestamp":1713000000,"version":"2.0"}'

    def test_empty_dict(self):
        assert f.canonical_json({}) == "{}"

    def test_nested_null_preserved(self):
        result = f.canonical_json({"patch": None})
        # json.dumps(None) → "null"
        assert '"patch":null' in result

    def test_sign_verify_use_same_canonical(self, key_pair):
        priv, pub = key_pair
        payload = {"z": "zoo", "a": "ant", "m": "monkey"}
        sig   = f.sign_manifest(payload, priv)
        valid = f.verify_manifest_sig(payload, sig, pub)
        assert valid, "Same canonical JSON must verify"


# ── sign + verify ─────────────────────────────────────────────────────────────

class TestSignVerify:

    def test_roundtrip(self, key_pair, sample_payload):
        priv, pub = key_pair
        sig   = f.sign_manifest(sample_payload, priv)
        assert f.verify_manifest_sig(sample_payload, sig, pub)

    def test_wrong_key_fails(self, sample_payload):
        priv1 = ec.generate_private_key(ec.SECP256R1())
        priv2 = ec.generate_private_key(ec.SECP256R1())
        sig   = f.sign_manifest(sample_payload, priv1)
        assert not f.verify_manifest_sig(sample_payload, sig, priv2.public_key())

    def test_tampered_payload_fails(self, key_pair, sample_payload):
        priv, pub = key_pair
        sig    = f.sign_manifest(sample_payload, priv)
        tampered = dict(sample_payload)
        tampered["id"] = "evil-model"
        assert not f.verify_manifest_sig(tampered, sig, pub)

    def test_invalid_sig_hex_fails(self, key_pair, sample_payload):
        _, pub = key_pair
        assert not f.verify_manifest_sig(sample_payload, "deadbeef0000", pub)

    def test_empty_sig_hex_fails(self, key_pair, sample_payload):
        _, pub = key_pair
        assert not f.verify_manifest_sig(sample_payload, "", pub)


# ── sha256_file ───────────────────────────────────────────────────────────────

class TestSha256:

    def test_known_vector(self, tmp_path):
        p = tmp_path / "empty.bin"
        p.write_bytes(b"")
        assert f.sha256_file(str(p)) == \
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_different_content_different_hash(self, tmp_path):
        a = tmp_path / "a.bin"
        b = tmp_path / "b.bin"
        a.write_bytes(b"hello v1")
        b.write_bytes(b"hello v2")
        assert f.sha256_file(str(a)) != f.sha256_file(str(b))

    def test_large_file(self, tmp_path):
        p = tmp_path / "large.bin"
        data = b"x" * (2 * 1024 * 1024)  # 2 MB
        p.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        assert f.sha256_file(str(p)) == expected


# ── human_size ────────────────────────────────────────────────────────────────

class TestHumanSize:

    def test_bytes(self):   assert "B"  in f.human_size(512)
    def test_kilobytes(self): assert "KB" in f.human_size(2048)
    def test_megabytes(self): assert "MB" in f.human_size(2 * 1024 * 1024)
    def test_gigabytes(self): assert "GB" in f.human_size(2 * 1024 ** 3)


# ── compress_file ─────────────────────────────────────────────────────────────

class TestCompressFile:

    def test_output_is_smaller_than_input(self, tmp_path):
        src = tmp_path / "input.bin"
        dst = tmp_path / "output.zst"
        data = b"aether " * 10_000  # highly compressible
        src.write_bytes(data)
        out_size = f.compress_file(str(src), str(dst), level=3)
        assert out_size < len(data), "Compressed output must be smaller than input"
        assert dst.exists()

    def test_dry_run_estimates_compressed_size_and_writes_no_file(self, tmp_path):
        src = tmp_path / "input.bin"
        dst = tmp_path / "output.zst"
        data = b"compress me " * 1000
        src.write_bytes(data)
        size = f.compress_file(str(src), str(dst), level=3, dry_run=True)
        assert size < len(data), "Dry-run must estimate compressed size for compressible input"
        assert not dst.exists(), "Dry-run must not write output file"


# ── create_patch ──────────────────────────────────────────────────────────────

class TestCreatePatch:

    def test_produces_valid_bsdiff_patch(self, tmp_path):
        import bsdiff4
        old = tmp_path / "old.bin"
        new = tmp_path / "new.bin"
        patch = tmp_path / "delta.bin"
        output = tmp_path / "patched.bin"
        old.write_bytes(b"Hello World version 1.0 test data")
        new.write_bytes(b"Hello World version 2.0 test data")

        f.create_patch(str(old), str(new), str(patch))

        assert patch.exists()
        # bsdiff4.file_patch(src_path, dst_path, patch_path) — 3 args
        bsdiff4.file_patch(str(old), str(output), str(patch))
        assert output.read_bytes() == new.read_bytes()

    def test_dry_run_writes_no_file(self, tmp_path):
        old = tmp_path / "old.bin"
        new = tmp_path / "new.bin"
        patch = tmp_path / "delta.bin"
        old.write_bytes(b"v1")
        new.write_bytes(b"v2")

        f.create_patch(str(old), str(new), str(patch), dry_run=True)
        assert not patch.exists()


# ── CLI (via Click test runner) ───────────────────────────────────────────────

class TestCLI:

    def test_keygen_creates_both_key_files(self, tmp_path):
        from click.testing import CliRunner
        result = CliRunner().invoke(f.cli, ["keygen", "--out", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert (tmp_path / "admin_private.pem").exists()
        assert (tmp_path / "app_public.pem").exists()

    def test_verify_valid_manifest(self, tmp_path):
        from click.testing import CliRunner
        runner = CliRunner()

        # Generate keys
        runner.invoke(f.cli, ["keygen", "--out", str(tmp_path)])

        # Create a minimal manifest manually and sign it
        priv = f.load_private_key(str(tmp_path / "admin_private.pem"))
        payload = {"id": "m", "version": "1.0", "timestamp": int(time.time()),
                   "full": {"url": "x", "size": 1, "sha256": "aaa", "filename": "f.zst"},
                   "patch": None}
        sig    = f.sign_manifest(payload, priv)
        mfest  = {"payload": payload, "signature": sig}
        mpath  = tmp_path / "manifest.json"
        mpath.write_text(json.dumps(mfest))

        result = runner.invoke(f.cli, [
            "verify",
            "--manifest", str(mpath),
            "--key",      str(tmp_path / "app_public.pem"),
        ])
        assert result.exit_code == 0
        assert "VALID" in result.output

    def test_verify_tampered_manifest_exits_nonzero(self, tmp_path):
        from click.testing import CliRunner
        runner = CliRunner()
        runner.invoke(f.cli, ["keygen", "--out", str(tmp_path)])

        priv = f.load_private_key(str(tmp_path / "admin_private.pem"))
        payload = {"id": "good", "version": "1.0", "timestamp": int(time.time()),
                   "full": {"url": "x", "size": 1, "sha256": "aaa", "filename": "f.zst"},
                   "patch": None}
        sig = f.sign_manifest(payload, priv)

        # Tamper after signing
        payload["id"] = "evil"
        mfest = {"payload": payload, "signature": sig}
        mpath = tmp_path / "manifest.json"
        mpath.write_text(json.dumps(mfest))

        result = runner.invoke(f.cli, [
            "verify",
            "--manifest", str(mpath),
            "--key",      str(tmp_path / "app_public.pem"),
        ])
        assert result.exit_code != 0

    def test_verify_dry_run_manifest_exits_code_2(self, tmp_path):
        """ADR-007: forge verify must explicitly reject dry-run manifests (exit 2)."""
        from click.testing import CliRunner
        runner = CliRunner()
        runner.invoke(f.cli, ["keygen", "--out", str(tmp_path)])

        # Build a dry-run manifest (signature=null, _dry_run=true)
        payload = {"id": "m", "version": "1.0", "timestamp": 1713000000,
                   "full": {"url": "x", "size": 1, "sha256": "[dry-run: sha256 not computed]",
                            "filename": "f.zst"},
                   "patch": None}
        mfest = {"payload": payload, "signature": None, "_dry_run": True}
        mpath = tmp_path / "manifest.json"
        mpath.write_text(__import__("json").dumps(mfest))

        result = runner.invoke(f.cli, [
            "verify",
            "--manifest", str(mpath),
            "--key",      str(tmp_path / "app_public.pem"),
        ])
        assert result.exit_code == 2, (
            f"Expected exit code 2 for dry-run manifest, got {result.exit_code}\n{result.output}"
        )

    def test_publish_dry_run_does_not_require_key(self, tmp_path):
        """ADR-007: --key must be optional in dry-run mode."""
        from click.testing import CliRunner
        model = tmp_path / "model.bin"
        model.write_bytes(b"fake model data " * 100)
        dist = tmp_path / "dist"

        result = CliRunner().invoke(f.cli, [
            "publish",
            "--new", str(model),
            "--id",  "test-model",
            "--ver", "1.0",
            "--out", str(dist),
            "--dry-run",
            # intentionally no --key
        ])
        assert result.exit_code == 0, result.output
        assert not dist.exists(), "Dry-run must not create dist directory"


    def test_info_shows_sha256_and_size(self, tmp_path):
        from click.testing import CliRunner
        p = tmp_path / "sample.bin"
        p.write_bytes(b"test data for info command")
        result = CliRunner().invoke(f.cli, ["info", str(p)])
        assert result.exit_code == 0
        assert "SHA256" in result.output
        assert "Size"   in result.output

    def test_publish_dry_run_writes_no_files(self, tmp_path):
        from click.testing import CliRunner
        runner = CliRunner()
        runner.invoke(f.cli, ["keygen", "--out", str(tmp_path / "keys")])

        model = tmp_path / "model.bin"
        model.write_bytes(b"fake model data " * 100)
        dist  = tmp_path / "dist"

        result = runner.invoke(f.cli, [
            "publish",
            "--new",  str(model),
            "--id",   "test-model",
            "--ver",  "1.0",
            "--key",  str(tmp_path / "keys" / "admin_private.pem"),
            "--out",  str(dist),
            "--dry-run",
        ])
        assert result.exit_code == 0, result.output
        assert not dist.exists(), "Dry-run must not create dist directory"
        assert "dry-run" in result.output.lower() or "DRY" in result.output


# ── canonical_json — special character escaping ───────────────────────────────

class TestCanonicalJsonEscaping:
    """Verify canonical_json output matches Python json.dumps for edge-case strings.

    These tests guard against regressions where mobile implementations might
    diverge from forge.py's serialization for model IDs with special characters.
    Python's json.dumps handles all these cases correctly by design.
    """

    def test_string_with_double_quote(self):
        result = f.canonical_json({"id": 'say "hi"'})
        # Python json.dumps escapes correctly
        assert result == '{"id":"say \\"hi\\""}'

    def test_string_with_backslash(self):
        result = f.canonical_json({"path": "C:\\Users\\admin"})
        assert result == '{"path":"C:\\\\Users\\\\admin"}'

    def test_string_with_newline(self):
        result = f.canonical_json({"desc": "line1\nline2"})
        assert result == '{"desc":"line1\\nline2"}'

    def test_null_value_serialised_as_json_null(self):
        result = f.canonical_json({"patch": None})
        assert result == '{"patch":null}'

    def test_sign_verify_with_special_chars(self, key_pair):
        priv, pub = key_pair
        payload = {
            "id":      'model-"test"',
            "version": "1\\0",
            "timestamp": 1713000000,
            "full":    {"url": "https://cdn/x.zst", "size": 1, "sha256": "abc"},
            "patch":   None,
        }
        sig   = f.sign_manifest(payload, priv)
        valid = f.verify_manifest_sig(payload, sig, pub)
        assert valid, "Signature must verify for payloads with special characters"

    def test_integer_not_quoted(self):
        result = f.canonical_json({"timestamp": 1713000000})
        assert result == '{"timestamp":1713000000}'
        assert '"1713000000"' not in result  # must not be quoted


# ── publish CLI — real publish (not dry-run) ──────────────────────────────────

class TestPublishRealRun:

    def test_publish_creates_signed_manifest_and_artefacts(self, tmp_path, key_pair):
        """Full publish pipeline: compress → sign → verify manifest output."""
        from click.testing import CliRunner
        runner = CliRunner()

        # Write keys to disk
        priv_key, pub_key = key_pair
        from cryptography.hazmat.primitives import serialization
        key_dir = tmp_path / "keys"
        key_dir.mkdir()
        (key_dir / "admin_private.pem").write_bytes(
            priv_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        (key_dir / "app_public.pem").write_bytes(
            pub_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        model   = tmp_path / "model.bin"
        model.write_bytes(b"fake model data " * 500)
        dist    = tmp_path / "dist"

        result = runner.invoke(f.cli, [
            "publish",
            "--new",  str(model),
            "--id",   "llm-mini",
            "--ver",  "3.0",
            "--seq",  "1",
            "--key",  str(key_dir / "admin_private.pem"),
            "--out",  str(dist),
            "--compress-level", "1",   # fast for tests
        ])
        assert result.exit_code == 0, result.output

        manifest_path = dist / "manifest.json"
        assert manifest_path.exists(), "manifest.json must be created"

        with open(manifest_path) as fp:
            data = __import__("json").load(fp)

        assert data.get("_dry_run") is None, "Real publish must not set _dry_run"
        assert data["signature"] is not None, "Real publish must have a signature"
        assert data["payload"]["id"] == "llm-mini"
        assert data["payload"]["version"] == "3.0"
        assert data["payload"]["sequence"] == 1

        # Verify the written manifest passes `forge verify`
        verify_result = runner.invoke(f.cli, [
            "verify",
            "--manifest", str(manifest_path),
            "--key",      str(key_dir / "app_public.pem"),
        ])
        assert verify_result.exit_code == 0, verify_result.output
        assert "VALID" in verify_result.output

    def test_publish_requires_key_without_dry_run(self, tmp_path):
        """publish without --dry-run must fail if --key is omitted."""
        from click.testing import CliRunner
        model = tmp_path / "model.bin"
        model.write_bytes(b"data")
        result = CliRunner().invoke(f.cli, [
            "publish",
            "--new", str(model),
            "--id",  "m",
            "--ver", "1.0",
            "--out", str(tmp_path / "dist"),
            # no --key, no --dry-run
        ])
        assert result.exit_code != 0, "Must fail without --key when not dry-run"

    def test_publish_requires_seq_without_dry_run(self, tmp_path, key_pair):
        """ADR-016: real publish must provide --seq."""
        from click.testing import CliRunner
        from cryptography.hazmat.primitives import serialization

        runner = CliRunner()
        priv_key, _ = key_pair
        key_dir = tmp_path / "keys"
        key_dir.mkdir()
        (key_dir / "admin_private.pem").write_bytes(
            priv_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

        model = tmp_path / "model.bin"
        model.write_bytes(b"data")
        result = runner.invoke(f.cli, [
            "publish",
            "--new", str(model),
            "--id", "m",
            "--ver", "1.0",
            "--key", str(key_dir / "admin_private.pem"),
            "--out", str(tmp_path / "dist"),
        ])
        assert result.exit_code != 0, "Must fail without --seq when not dry-run"
        assert "--seq is required" in result.output
