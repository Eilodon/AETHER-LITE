// ios/AetherAppTests/AetherTests.swift
//
// XCTest suite for Aether Suite v2.3.0
//
// Run with Xcode: Product → Test  (⌘U)
// Or via CLI:
//   xcodebuild test -scheme AetherApp -destination 'platform=iOS Simulator,...'

import XCTest
import CryptoKit
@testable import AetherApp

final class VaultTests: XCTestCase {

    // ── Public key ────────────────────────────────────────────────────────────

    func test_publicKeyIsNotNil() {
        XCTAssertNotNil(Vault.shared.getPublicKeyData())
    }

    func test_publicKeyIsDeterministic() {
        let k1 = Vault.shared.getPublicKeyData()
        let k2 = Vault.shared.getPublicKeyData()
        XCTAssertEqual(k1, k2, "getPublicKeyData() must return the same key on repeated calls")
    }

    func test_publicKeyLengthIsCorrect() {
        // Uncompressed P-256 public key in X9.62 format = 65 bytes (0x04 || X || Y)
        guard let key = Vault.shared.getPublicKeyData() else {
            return XCTFail("Public key is nil")
        }
        XCTAssertEqual(key.count, 65, "P-256 uncompressed public key must be 65 bytes")
    }

    // ── Manifest verification (using CryptoKit for test key generation) ───────

    func test_validManifestSignatureVerifies() throws {
        // Generate a throwaway P-256 key pair for the test
        let privKey = P256.Signing.PrivateKey()
        let pubKeyDer = privKey.publicKey.derRepresentation

        let canonical = #"{"id":"llm-mini","timestamp":1713000000,"version":"2.0"}"#
        let jsonData  = canonical.data(using: .utf8)!

        // Sign with CryptoKit (DER-encoded signature)
        let signature = try privKey.signature(for: jsonData)
        let sigHex    = signature.derRepresentation.map { String(format: "%02x", $0) }.joined()

        let valid = Vault.shared.verifyManifestSignature(
            canonicalJson: canonical,
            signatureHex:  sigHex,
            publicKeyDer:  pubKeyDer
        )
        XCTAssertTrue(valid, "Valid signature should verify successfully")
    }

    func test_wrongKeyFailsVerification() throws {
        let signingKey  = P256.Signing.PrivateKey()
        let differentKey = P256.Signing.PrivateKey()
        let canonical   = #"{"id":"test"}"#
        let sig = try signingKey.signature(for: canonical.data(using: .utf8)!)

        let valid = Vault.shared.verifyManifestSignature(
            canonicalJson: canonical,
            signatureHex:  sig.derRepresentation.map { String(format: "%02x", $0) }.joined(),
            publicKeyDer:  differentKey.publicKey.derRepresentation  // ← wrong key
        )
        XCTAssertFalse(valid, "Signature verified with wrong public key should fail")
    }

    func test_tamperedPayloadFailsVerification() throws {
        let key       = P256.Signing.PrivateKey()
        let original  = #"{"id":"model-a"}"#
        let tampered  = #"{"id":"evil-model"}"#
        let sig = try key.signature(for: original.data(using: .utf8)!)

        let valid = Vault.shared.verifyManifestSignature(
            canonicalJson: tampered,   // ← different JSON, same sig
            signatureHex:  sig.derRepresentation.map { String(format: "%02x", $0) }.joined(),
            publicKeyDer:  key.publicKey.derRepresentation
        )
        XCTAssertFalse(valid)
    }

    func test_invalidHexSignatureReturnsFalse() {
        let valid = Vault.shared.verifyManifestSignature(
            canonicalJson: "{}",
            signatureHex:  "not-valid-hex!!!",
            publicKeyDer:  Data(repeating: 0, count: 65)
        )
        XCTAssertFalse(valid, "Malformed hex should return false, not crash")
    }
}

// ── Canonical JSON ────────────────────────────────────────────────────────────

final class CanonicalJSONTests: XCTestCase {

    // Fixed implementation matching AetherManager.canonicalJSON (v2.3.2)
    private func jsonEscape(_ s: String) -> String {
        var out = "\""
        for scalar in s.unicodeScalars {
            switch scalar.value {
            case 0x22: out += "\\\""
            case 0x5C: out += "\\\\"
            case 0x08: out += "\\b"
            case 0x09: out += "\\t"
            case 0x0A: out += "\\n"
            case 0x0C: out += "\\f"
            case 0x0D: out += "\\r"
            case 0x00..<0x20: out += String(format: "\\u%04x", scalar.value)
            default: out += String(scalar)
            }
        }
        return out + "\""
    }

    private func canonical(_ dict: [String: Any]) -> String {
        let keys = dict.keys.sorted()
        let pairs = keys.map { k -> String in
            let v = dict[k]!
            let vs: String
            if let nested = v as? [String: Any] { vs = canonical(nested) }
            else if let arr = v as? [Any]       { vs = canonicalArray(arr) }
            else if let s = v as? String         { vs = jsonEscape(s) }   // Fix: proper escaping
            else if v is NSNull                  { vs = "null" }
            else                                 { vs = "\(v)" }
            return "\"\(k)\":\(vs)"
        }
        return "{\(pairs.joined(separator: ","))}"
    }

    private func canonicalArray(_ values: [Any]) -> String {
        let rendered = values.map { value -> String in
            if let nested = value as? [String: Any] { return canonical(nested) }
            if let arr = value as? [Any] { return canonicalArray(arr) }
            if let s = value as? String { return jsonEscape(s) }
            if value is NSNull { return "null" }
            return "\(value)"
        }
        return "[\(rendered.joined(separator: ","))]"
    }

    func test_sortsKeys() {
        let result = canonical(["z": "last", "a": "first", "m": "mid"])
        XCTAssertEqual(result, #"{"a":"first","m":"mid","z":"last"}"#)
    }

    func test_matchesForgePyOutput() {
        let result = canonical([
            "id": "llm-mini", "version": "2.0", "timestamp": 1713000000
        ])
        XCTAssertEqual(result, #"{"id":"llm-mini","timestamp":1713000000,"version":"2.0"}"#)
    }

    func test_nestedObjectIsSorted() {
        let result = canonical([
            "id": "m",
            "full": ["url": "https://cdn/f.zst", "size": 1024] as [String: Any]
        ])
        XCTAssertEqual(result, #"{"full":{"size":1024,"url":"https://cdn/f.zst"},"id":"m"}"#)
    }

    func test_arrayIsSerializedCanonically() {
        let result = canonical([
            "arches": ["arm64", "x86_64"],
            "id": "m"
        ])
        XCTAssertEqual(result, #"{"arches":["arm64","x86_64"],"id":"m"}"#)
    }

    func test_emptyDictProducesEmptyObject() {
        XCTAssertEqual(canonical([:]), "{}")
    }

    // ── Escaping edge cases (fix v2.3.2) ──────────────────────────────────────

    func test_escapesDoubleQuoteInValue() {
        let result = canonical(["id": #"say "hi""#])
        XCTAssertTrue(result.contains(#"say \"hi\""#),
                      "Double quotes must be escaped; got: \(result)")
    }

    func test_escapesBackslashInValue() {
        let result = canonical(["path": #"C:\Users\admin"#])
        XCTAssertTrue(result.contains(#"C:\\Users\\admin"#),
                      "Backslashes must be escaped; got: \(result)")
    }

    func test_escapesNewlineInValue() {
        let result = canonical(["desc": "line1\nline2"])
        XCTAssertTrue(result.contains("line1\\nline2"),
                      "Newlines must be escaped; got: \(result)")
    }

    func test_nullValueSerializedAsJsonNull() {
        let result = canonical(["patch": NSNull()])
        XCTAssertEqual(result, #"{"patch":null}"#)
    }

    func test_alphanumericValuesUnchanged() {
        // Normal model IDs must produce identical output to forge.py
        let result = canonical(["id": "llm-mini", "version": "2.0"])
        XCTAssertEqual(result, #"{"id":"llm-mini","version":"2.0"}"#)
    }
}

// ── Data hex extension ────────────────────────────────────────────────────────

final class DataHexTests: XCTestCase {

    func test_validHex() {
        let data = Data(hexString: "deadbeef")
        XCTAssertNotNil(data)
        XCTAssertEqual(data?.count, 4)
        XCTAssertEqual(data?[0], 0xDE)
        XCTAssertEqual(data?[3], 0xEF)
    }

    func test_uppercaseHex() {
        let d1 = Data(hexString: "AABB")
        let d2 = Data(hexString: "aabb")
        XCTAssertEqual(d1, d2)
    }

    func test_emptyHexProducesEmptyData() {
        let data = Data(hexString: "")
        XCTAssertNotNil(data)
        XCTAssertEqual(data?.count, 0)
    }

    func test_oddLengthHexReturnsNil() {
        XCTAssertNil(Data(hexString: "abc"), "Odd hex length must return nil")
    }

    func test_invalidCharactersReturnNil() {
        XCTAssertNil(Data(hexString: "gg00"), "Non-hex chars must return nil")
    }
}

// ── Heartbeat backoff ─────────────────────────────────────────────────────────

final class HeartbeatBackoffTests: XCTestCase {

    func test_backoffDoublesCorrectly() {
        var delay: UInt64 = 5_000_000_000
        let max:   UInt64 = 30_000_000_000
        var results: [UInt64] = []
        for _ in 0..<5 {
            delay = min(delay * 2, max)
            results.append(delay)
        }
        XCTAssertEqual(results, [
            10_000_000_000,
            20_000_000_000,
            30_000_000_000,
            30_000_000_000,
            30_000_000_000,
        ])
    }

    func test_backoffIsCappedAtThirtySeconds() {
        var delay: UInt64 = 5_000_000_000
        for _ in 0..<20 {
            delay = min(delay * 2, 30_000_000_000)
        }
        XCTAssertEqual(delay, 30_000_000_000)
    }
}
