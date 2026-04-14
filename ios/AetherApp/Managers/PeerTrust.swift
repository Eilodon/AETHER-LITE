import Foundation
import CryptoKit

enum PeerTrustMode: String, Codable {
    case tofu = "TOFU"
    case qrPinned = "QR_PINNED"
}

struct PeerPin: Codable, Equatable {
    let peerId: String
    let publicKeyHex: String
    let publicKeySha256: String
    let protocolVersion: String
    let trustMode: PeerTrustMode
    let addedAtEpochMs: UInt64
    let lastValidatedAtEpochMs: UInt64
}

struct PeerTrustDecision {
    let pin: PeerPin
    let trustEstablishedNow: Bool
}

enum PeerTrustError: LocalizedError {
    case invalidOnboardingScheme
    case fingerprintMismatch
    case pinnedPeerMismatch(String)
    case untrustedPeer

    var errorDescription: String? {
        switch self {
        case .invalidOnboardingScheme:
            return "Unsupported onboarding scheme"
        case .fingerprintMismatch:
            return "Peer fingerprint mismatch"
        case .pinnedPeerMismatch(let message):
            return message
        case .untrustedPeer:
            return "Peer is not pinned; complete QR onboarding or enable TOFU"
        }
    }
}

enum PeerTrust {
    static let onboardingScheme = "aether-peer-pin-v1"
    private static let onboardingUriPrefix = "aether://peer-pin?data="

    static func fingerprintHex(_ publicKey: Data) -> String {
        SHA256.hash(data: publicKey).map { String(format: "%02x", $0) }.joined()
    }

    static func createOnboardingPayload(
        peerId: String,
        publicKeyHex: String,
        protocolVersion: String
    ) throws -> String {
        let normalizedKeyHex = publicKeyHex.lowercased()
        guard let publicKeyData = Data(hexString: normalizedKeyHex) else {
            throw PeerTrustError.fingerprintMismatch
        }
        let payload = [
            "peer_id": peerId,
            "protocol_version": protocolVersion,
            "public_key_hex": normalizedKeyHex,
            "public_key_sha256": fingerprintHex(publicKeyData),
            "scheme": onboardingScheme
        ]
        return canonicalJSONString(payload)
    }

    static func createOnboardingURI(
        peerId: String,
        publicKeyHex: String,
        protocolVersion: String
    ) throws -> String {
        let payload = try createOnboardingPayload(
            peerId: peerId,
            publicKeyHex: publicKeyHex,
            protocolVersion: protocolVersion
        )
        let encoded = Data(payload.utf8)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return onboardingUriPrefix + encoded
    }

    static func parseOnboardingPayload(
        _ payloadOrURI: String,
        nowEpochMs: UInt64 = PeerPinStore.currentEpochMs()
    ) throws -> PeerPin {
        let payload: String
        if payloadOrURI.hasPrefix(onboardingUriPrefix) {
            let encoded = String(payloadOrURI.dropFirst(onboardingUriPrefix.count))
            let base64 = encoded
                .replacingOccurrences(of: "-", with: "+")
                .replacingOccurrences(of: "_", with: "/")
            let padded = base64 + String(repeating: "=", count: (4 - base64.count % 4) % 4)
            guard let data = Data(base64Encoded: padded),
                  let decoded = String(data: data, encoding: .utf8) else {
                throw PeerTrustError.invalidOnboardingScheme
            }
            payload = decoded
        } else {
            payload = payloadOrURI
        }

        guard let data = payload.data(using: .utf8),
              let raw = try JSONSerialization.jsonObject(with: data) as? [String: String],
              raw["scheme"] == onboardingScheme,
              let peerId = raw["peer_id"],
              let publicKeyHex = raw["public_key_hex"]?.lowercased(),
              let expectedFingerprint = raw["public_key_sha256"]?.lowercased(),
              let publicKeyData = Data(hexString: publicKeyHex)
        else {
            throw PeerTrustError.invalidOnboardingScheme
        }

        let fingerprint = fingerprintHex(publicKeyData)
        guard fingerprint == expectedFingerprint else {
            throw PeerTrustError.fingerprintMismatch
        }

        return PeerPin(
            peerId: peerId,
            publicKeyHex: publicKeyHex,
            publicKeySha256: fingerprint,
            protocolVersion: raw["protocol_version"] ?? "",
            trustMode: .qrPinned,
            addedAtEpochMs: nowEpochMs,
            lastValidatedAtEpochMs: nowEpochMs
        )
    }

    static func evaluateHandshake(
        peerId: String,
        publicKeyHex: String,
        protocolVersion: String,
        existingPin: PeerPin?,
        trustOnFirstUse: Bool,
        nowEpochMs: UInt64 = PeerPinStore.currentEpochMs()
    ) throws -> PeerTrustDecision {
        let normalizedKeyHex = publicKeyHex.lowercased()
        guard let publicKeyData = Data(hexString: normalizedKeyHex) else {
            throw PeerTrustError.fingerprintMismatch
        }
        let fingerprint = fingerprintHex(publicKeyData)
        let currentProtocol = protocolVersion.isEmpty ? (existingPin?.protocolVersion ?? "") : protocolVersion

        if let existingPin {
            guard existingPin.peerId == peerId else {
                throw PeerTrustError.pinnedPeerMismatch("Pinned peer ID mismatch")
            }
            guard existingPin.publicKeySha256 == fingerprint else {
                throw PeerTrustError.pinnedPeerMismatch("Pinned peer fingerprint mismatch")
            }
            guard existingPin.publicKeyHex == normalizedKeyHex else {
                throw PeerTrustError.pinnedPeerMismatch("Pinned peer public key mismatch")
            }
            return PeerTrustDecision(
                pin: PeerPin(
                    peerId: existingPin.peerId,
                    publicKeyHex: existingPin.publicKeyHex,
                    publicKeySha256: existingPin.publicKeySha256,
                    protocolVersion: currentProtocol,
                    trustMode: existingPin.trustMode,
                    addedAtEpochMs: existingPin.addedAtEpochMs,
                    lastValidatedAtEpochMs: nowEpochMs
                ),
                trustEstablishedNow: false
            )
        }

        guard trustOnFirstUse else {
            throw PeerTrustError.untrustedPeer
        }

        return PeerTrustDecision(
            pin: PeerPin(
                peerId: peerId,
                publicKeyHex: normalizedKeyHex,
                publicKeySha256: fingerprint,
                protocolVersion: currentProtocol,
                trustMode: .tofu,
                addedAtEpochMs: nowEpochMs,
                lastValidatedAtEpochMs: nowEpochMs
            ),
            trustEstablishedNow: true
        )
    }

    private static func canonicalJSONString(_ object: [String: String]) -> String {
        let keys = object.keys.sorted()
        let pairs = keys.map { key -> String in
            let value = object[key] ?? ""
            return "\(quote(key)):\(quote(value))"
        }
        return "{\(pairs.joined(separator: ","))}"
    }

    private static func quote(_ s: String) -> String {
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
            case 0x00..<0x20:
                out += String(format: "\\u%04x", scalar.value)
            default:
                out += String(scalar)
            }
        }
        out += "\""
        return out
    }
}

final class PeerPinStore {
    private let defaults: UserDefaults
    private let storageKey = "aether.peerPins"

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    func get(peerId: String) -> PeerPin? {
        var pins = loadAll()
        return pins[peerId]
    }

    func save(_ pin: PeerPin) {
        var pins = loadAll()
        pins[pin.peerId] = pin
        persist(pins)
    }

    func remove(peerId: String) {
        var pins = loadAll()
        pins.removeValue(forKey: peerId)
        persist(pins)
    }

    private func loadAll() -> [String: PeerPin] {
        guard let data = defaults.data(forKey: storageKey) else { return [:] }
        return (try? JSONDecoder().decode([String: PeerPin].self, from: data)) ?? [:]
    }

    private func persist(_ pins: [String: PeerPin]) {
        guard let data = try? JSONEncoder().encode(pins) else { return }
        defaults.set(data, forKey: storageKey)
    }

    static func currentEpochMs() -> UInt64 {
        UInt64(Date().timeIntervalSince1970 * 1000)
    }
}
