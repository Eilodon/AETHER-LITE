import Foundation
import Security
import AetherFFI

struct ParsedManifestForUpdate {
    let modelId: String
    let sequence: UInt64
    let payloadJson: String
    let canonicalJson: String
    let signatureHex: String
}

protocol ManifestSequenceStore {
    func getLastAccepted(modelId: String) -> UInt64
    func persistAccepted(modelId: String, sequence: UInt64)
}

protocol ManifestVerificationEngine {
    func canonicalizeJson(json: String) throws -> String
    func seedManifestSequence(modelId: String, sequence: UInt64) throws
    func verifyManifestWithSequence(
        modelId: String,
        sequence: UInt64,
        canonicalJson: String,
        sigHex: String,
        publicKeyDer: [UInt8]
    ) throws
}

extension AetherEngine: ManifestVerificationEngine {}

struct UserDefaultsManifestSequenceStore: ManifestSequenceStore {
    let defaults: UserDefaults
    let key: String

    func getLastAccepted(modelId: String) -> UInt64 {
        let sequences = defaults.dictionary(forKey: key) as? [String: UInt64] ?? [:]
        return sequences[modelId] ?? 0
    }

    func persistAccepted(modelId: String, sequence: UInt64) {
        var sequences = defaults.dictionary(forKey: key) as? [String: UInt64] ?? [:]
        sequences[modelId] = sequence
        defaults.set(sequences, forKey: key)
    }
}

final class KeychainManifestSequenceStore: ManifestSequenceStore {
    private let service: String
    private let defaults: UserDefaults
    private let legacyKey: String

    init(
        service: String,
        defaults: UserDefaults = .standard,
        legacyKey: String
    ) {
        self.service = service
        self.defaults = defaults
        self.legacyKey = legacyKey
        migrateFromUserDefaults()
    }

    func getLastAccepted(modelId: String) -> UInt64 {
        loadAll()[modelId] ?? 0
    }

    func persistAccepted(modelId: String, sequence: UInt64) {
        var sequences = loadAll()
        sequences[modelId] = sequence
        persist(sequences)
    }

    private func loadAll() -> [String: UInt64] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return [:] }
        return (try? JSONDecoder().decode([String: UInt64].self, from: data)) ?? [:]
    }

    private func persist(_ sequences: [String: UInt64]) {
        guard let data = try? JSONEncoder().encode(sequences) else { return }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        let updateQuery: [String: Any] = [
            kSecValueData as String: data,
        ]

        let status = SecItemUpdate(query as CFDictionary, updateQuery as CFDictionary)
        if status == errSecItemNotFound {
            let addQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                kSecValueData as String: data,
            ]
            SecItemAdd(addQuery as CFDictionary, nil)
        }
    }

    private func migrateFromUserDefaults() {
        let oldSequences = defaults.dictionary(forKey: legacyKey) as? [String: UInt64] ?? [:]
        guard !oldSequences.isEmpty else { return }

        var merged = loadAll()
        for (modelId, sequence) in oldSequences where sequence > 0 && merged[modelId] == nil {
            merged[modelId] = sequence
        }
        persist(merged)
        defaults.removeObject(forKey: legacyKey)
    }
}

enum ManifestVerificationHelper {
    static func parseAndVerifyForUpdate(
        manifestJson: String,
        adminPublicKeyDer: Data,
        engine: ManifestVerificationEngine,
        sequenceStore: ManifestSequenceStore
    ) throws -> ParsedManifestForUpdate {
        guard let data = manifestJson.data(using: .utf8),
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let payload = root["payload"] as? [String: Any],
              let signature = root["signature"] as? String
        else {
            throw AetherError.InternalError("Invalid manifest JSON")
        }
        guard let modelId = payload["id"] as? String, !modelId.isEmpty else {
            throw AetherError.SecurityError("Manifest model ID missing")
        }
        guard let sequenceNumber = payload["sequence"] as? NSNumber else {
            throw AetherError.SecurityError("Manifest sequence missing (ADR-016)")
        }
        let sequence = sequenceNumber.uint64Value
        guard sequence > 0 else {
            throw AetherError.SecurityError("Manifest sequence must be > 0 (ADR-016)")
        }
        let payloadData = try JSONSerialization.data(withJSONObject: payload, options: [])
        guard let payloadJson = String(data: payloadData, encoding: .utf8) else {
            throw AetherError.InternalError("Payload JSON encoding failed")
        }
        let canonicalJson = try engine.canonicalizeJson(json: payloadJson)

        let lastAccepted = sequenceStore.getLastAccepted(modelId: modelId)
        if lastAccepted > 0 {
            try engine.seedManifestSequence(modelId: modelId, sequence: lastAccepted)
        }
        try engine.verifyManifestWithSequence(
            modelId: modelId,
            sequence: sequence,
            canonicalJson: canonicalJson,
            sigHex: signature,
            publicKeyDer: [UInt8](adminPublicKeyDer)
        )
        sequenceStore.persistAccepted(modelId: modelId, sequence: sequence)

        return ParsedManifestForUpdate(
            modelId: modelId,
            sequence: sequence,
            payloadJson: payloadJson,
            canonicalJson: canonicalJson,
            signatureHex: signature
        )
    }
}
