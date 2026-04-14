// ios/AetherApp/Managers/Vault.swift
//
// Vault – Secure Enclave identity key + ECDSA manifest verification (v2.3)

import Foundation
import Security
import CryptoKit

final class Vault {

    static let shared = Vault()
    private init() {}

    private let tag     = "com.b_one.aether.identity.v2".data(using: .utf8)!
    private let keyType = kSecAttrKeyTypeECSECPrimeRandom

    // ── ECDH Identity ─────────────────────────────────────────────────────────

    func getPublicKeyData() -> Data? {
        guard let privateKey = loadOrCreatePrivateKey(),
              let publicKey  = SecKeyCopyPublicKey(privateKey) else { return nil }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            print("❌ Vault: export public key failed – \(error!.takeRetainedValue())")
            return nil
        }
        return data
    }

    func performHandshake(peerPublicKeyBytes: Data) -> Data? {
        // ── 1. Format check: must be 65-byte X9.62 uncompressed point (0x04 prefix) ──
        guard peerPublicKeyBytes.count == 65, peerPublicKeyBytes[0] == 0x04 else {
            print("❌ Vault: peer key must be a 65-byte X9.62 uncompressed P-256 point")
            return nil
        }

        // ── 2. Curve validation via CryptoKit ─────────────────────────────────
        // CryptoKit's P256.KeyAgreement.PublicKey is explicitly tied to NIST P-256
        // (secp256r1). This init throws if:
        //   • The point is not on P-256 (e.g. secp256k1, brainpoolP256r1)
        //   • The point is at infinity (small-subgroup attack)
        //   • The coordinates are out of range for P-256
        // SecKeyCreateWithData (below) accepts any 256-bit EC curve, so without
        // this gate an attacker could send a crafted key on a weak curve and
        // influence the shared secret in a predictable way.
        guard (try? P256.KeyAgreement.PublicKey(x963Representation: peerPublicKeyBytes)) != nil else {
            print("❌ Vault: peer key failed P-256 curve validation")
            return nil
        }

        // ── 3. ECDH via Secure Enclave private key ────────────────────────────
        // The Secure Enclave key lives in a SecKey handle, so we must use the
        // SecKey API for the actual exchange. CryptoKit validation above guarantees
        // the peer key is a valid P-256 point before we hand it to SecKey.
        guard let privateKey = loadOrCreatePrivateKey() else { return nil }

        let keyAttrs: [String: Any] = [
            kSecAttrKeyType as String:       keyType,
            kSecAttrKeyClass as String:      kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard let peerPublicKey = SecKeyCreateWithData(
            peerPublicKeyBytes as CFData, keyAttrs as CFDictionary, &error
        ) else {
            print("❌ Vault: SecKey import failed – \(error!.takeRetainedValue())")
            return nil
        }

        let params: [String: Any] = [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32]
        guard let secret = SecKeyCopyKeyExchangeResult(
            privateKey, .ecdhKeyExchangeStandard, peerPublicKey,
            params as CFDictionary, &error
        ) as Data? else {
            print("❌ Vault: ECDH failed – \(error!.takeRetainedValue())")
            return nil
        }
        return secret
    }

    // ── Manifest ECDSA Verification ───────────────────────────────────────────

    /// Verify the ECDSA-P256-SHA256 signature produced by `forge.py`.
    ///
    /// - Parameters:
    ///   - canonicalJson:  Sorted-key, no-whitespace JSON string of the payload.
    ///   - signatureHex:   Hex-encoded DER signature from `manifest.json`.
    ///   - publicKeyDer:   DER bytes of `app_public.pem` (bundled in the app bundle).
    /// - Returns: `true` if the signature is valid; `false` otherwise.
    func verifyManifestSignature(
        canonicalJson: String,
        signatureHex: String,
        publicKeyDer: Data
    ) -> Bool {
        guard let sigData = Data(hexString: signatureHex),
              let jsonData = canonicalJson.data(using: .utf8) else {
            print("❌ Vault: malformed signature hex or JSON encoding")
            return false
        }

        do {
            // Reconstruct EC P-256 public key from DER-encoded SubjectPublicKeyInfo
            let pubKey = try P256.Signing.PublicKey(derRepresentation: publicKeyDer)
            // CryptoKit expects raw IEEE P1363 signature, but Python/OpenSSL produces DER.
            // Convert DER → P1363 (raw 64-byte r||s).
            let rawSig = try P256.Signing.ECDSASignature(derRepresentation: sigData)
            return pubKey.isValidSignature(rawSig, for: jsonData)
        } catch {
            print("❌ Vault: manifest verification error – \(error)")
            return false
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    private func loadOrCreatePrivateKey() -> SecKey? {
        loadPrivateKey() ?? createPrivateKey()
    }

    private func loadPrivateKey() -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String:              kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String:        keyType,
            kSecReturnRef as String:          true
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else {
            return nil
        }
        return (result as! SecKey)
    }

    private func createPrivateKey() -> SecKey? {
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            nil
        ) else { return nil }

        let attrs: [String: Any] = [
            kSecAttrKeyType as String:       keyType,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String:       kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String:    true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String:  access
            ]
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            print("❌ Vault: key generation failed – \(error!.takeRetainedValue())")
            return nil
        }
        print("✅ Vault: Secure Enclave key created")
        return key
    }
}

// ── Data hex extension ────────────────────────────────────────────────────────

extension Data {
    init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var data = Data(capacity: hexString.count / 2)
        var idx  = hexString.startIndex
        while idx < hexString.endIndex {
            let nextIdx = hexString.index(idx, offsetBy: 2)
            guard let byte = UInt8(hexString[idx..<nextIdx], radix: 16) else { return nil }
            data.append(byte)
            idx = nextIdx
        }
        self = data
    }
}
