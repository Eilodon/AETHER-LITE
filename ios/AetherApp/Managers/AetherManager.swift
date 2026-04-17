// ios/AetherApp/Managers/AetherManager.swift
//
// AetherManager v2.3 – Fixes:
//  • FD double-close: use Darwin.open() for raw fd instead of FileHandle wrapper.
//  • Engine init moved off main thread (init() is now sync-safe).
//  • Manifest ECDSA verification before applying any patch.
//  • decompress() exposed for post-download zstd inflation.
//  • Heartbeat has bounded retry with exponential back-off.

import Foundation
import Network
import Combine
import Darwin    // for open(2), O_WRONLY, O_RDONLY, O_CREAT, O_TRUNC
import CryptoKit
import AetherFFI

@MainActor
final class AetherManager: ObservableObject {

    static let shared = AetherManager()
    private static let manifestSequenceDefaultsKey = "aether.manifest.sequences"
    private static let manifestSequenceKeychainService = "com.b_one.aether.manifest.sequences"

    @Published private(set) var isNodeActive = false
    @Published private(set) var activePort: UInt16 = 0
    @Published private(set) var lastError: String?

    private var engine: AetherEngine?
    private var monitor    = NWPathMonitor()
    private let monitorQ   = DispatchQueue(label: "com.b_one.aether.network")
    private var heartbeatTask: Task<Void, Never>?
    private let peerPinStore = PeerPinStore()
    // ADR-010: single source of truth — query from Rust config instead of hardcoding
    private lazy var protocolVersion: String = { engine?.getProtocolVersion() ?? "v2" }()

    private static let MAX_HEARTBEAT_FAILURES = 5

    private init() {
        // Fix v2.3: engine initialisation can spin up a Tokio runtime — do it
        // on a background thread so we never block the main run loop.
        Task.detached(priority: .userInitiated) {
            // ADR-001: constructor now throws AetherError
            guard let eng = try? AetherEngine() else {
                await MainActor.run { self.lastError = "AetherEngine init failed" }
                return
            }

            eng.setSelfPeerId(peerId: self.getStablePeerId())
            if let publicKey = Vault.shared.getPublicKeyData() {
                try eng.setSelfIdentityPublicKey(publicKeyX962: [UInt8](publicKey))
            }

            await MainActor.run {
                self.engine = eng
            }
            await self.setupNetworkMonitor()
            await self.startHeartbeat()
        }
    }

    // ── Node lifecycle ─────────────────────────────────────────────────────────

    func startNode() {
        guard !isNodeActive, let engine else { return }

        Task.detached(priority: .userInitiated) {
            do {
                let port = try engine.startServer()
                print("✅ AetherManager: node started on port \(port)")
                await MainActor.run {
                    self.isNodeActive = true
                    self.activePort   = port
                }
                // TODO: Register Bonjour "_aether._tcp" at `port` for LAN discovery
            } catch {
                print("❌ AetherManager: node start failed – \(error)")
                await MainActor.run { self.lastError = error.localizedDescription }
            }
        }
    }

    func stopNode() {
        engine?.stopServer()
        isNodeActive = false
        activePort   = 0
    }

    // ── Peer registration ──────────────────────────────────────────────────────

    func registerPeer(peerId: String, sharedSecret: Data, allowedModelIds: [String] = []) {
        guard let engine else {
            lastError = "Engine not initialised"
            return
        }
        do {
            try engine.registerPeerKey(peerId: peerId, sharedSecret: Array(sharedSecret))
            for modelId in allowedModelIds {
                try engine.grantPeerModelAccess(peerId: peerId, modelId: modelId)
            }
        } catch {
            lastError = error.localizedDescription
        }
    }

    func performAuthenticatedHandshake(
        peerIp: String,
        peerPort: UInt16,
        expectedPeerId: String? = nil,
        expectedPeerPublicKeySha256: String? = nil,
        trustOnFirstUse: Bool = true
    ) async throws -> (peerId: String, publicKeySha256: String, trustEstablishedNow: Bool) {
        guard let engine else {
            throw AetherError.InternalError("Engine not initialised")
        }

        let url = URL(string: "http://\(peerIp):\(peerPort)/identity")!
        let (data, _) = try await URLSession.shared.data(from: url)
        let doc = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        guard let peerId = doc?["peer_id"] as? String,
              let publicKeyHex = doc?["public_key_hex"] as? String,
              let noiseStaticPublicKeyHex = doc?["noise_static_public_key_hex"] as? String,
              !publicKeyHex.isEmpty,
              !noiseStaticPublicKeyHex.isEmpty,
              let publicKey = Data(hexString: publicKeyHex)
        else {
            throw AetherError.InternalError("Peer identity document invalid")
        }
        let peerProtocolVersion = (doc?["protocol_version"] as? String) ?? ""
        // ADR-010: centralized validation in Rust — rejects blank or incompatible version
        try engine?.validatePeerProtocol(peerVersion: peerProtocolVersion)

        if let expectedPeerId, expectedPeerId != peerId {
            throw AetherError.SecurityError("Peer ID mismatch")
        }

        let fingerprint = PeerTrust.fingerprintHex(publicKey)
        if let expectedPeerPublicKeySha256, expectedPeerPublicKeySha256 != fingerprint {
            throw AetherError.SecurityError("Peer public key fingerprint mismatch")
        }

        let existingPin = peerPinStore.get(peerId: peerId)
        let trustDecision: PeerTrustDecision
        if let existingPin {
            trustDecision = try PeerTrust.evaluateHandshake(
                peerId: peerId,
                publicKeyHex: publicKeyHex,
                protocolVersion: peerProtocolVersion,
                existingPin: existingPin,
                trustOnFirstUse: false
            )
        } else if expectedPeerPublicKeySha256 != nil {
            trustDecision = try PeerTrust.pinnedDecisionFromVerifiedFingerprint(
                peerId: peerId,
                publicKeyHex: publicKeyHex,
                protocolVersion: peerProtocolVersion
            )
        } else if trustOnFirstUse {
            throw AetherError.SecurityError(
                "Plaintext /identity bootstrap requires an existing pin or expected peer fingerprint; TOFU over HTTP is disabled"
            )
        } else {
            throw AetherError.SecurityError(
                "Peer is not pinned; complete QR onboarding or provide an expected peer fingerprint before using /identity"
            )
        }

        guard let sharedSecret = Vault.shared.performHandshake(peerPublicKeyBytes: publicKey) else {
            throw AetherError.KeyExchangeFailed
        }

        try engine.registerPeerKey(peerId: peerId, sharedSecret: [UInt8](sharedSecret))
        try engine.registerPeerNoiseStaticKey(
            peerId: peerId,
            publicKey: Array(Data(hexString: noiseStaticPublicKeyHex) ?? Data())
        )
        try engine.establishNoiseSession(peerIp: peerIp, peerPort: peerPort, peerId: peerId)
        peerPinStore.save(trustDecision.pin)
        return (peerId, fingerprint, trustDecision.trustEstablishedNow)
    }

    func exportSelfPeerOnboardingPayload() throws -> String {
        guard let publicKey = Vault.shared.getPublicKeyData() else {
            throw AetherError.InternalError("Identity key unavailable")
        }
        return try PeerTrust.createOnboardingPayload(
            peerId: getStablePeerId(),
            publicKeyHex: publicKey.map { String(format: "%02x", $0) }.joined(),
            protocolVersion: protocolVersion
        )
    }

    func exportSelfPeerOnboardingURI() throws -> String {
        guard let publicKey = Vault.shared.getPublicKeyData() else {
            throw AetherError.InternalError("Identity key unavailable")
        }
        return try PeerTrust.createOnboardingURI(
            peerId: getStablePeerId(),
            publicKeyHex: publicKey.map { String(format: "%02x", $0) }.joined(),
            protocolVersion: protocolVersion
        )
    }

    func importPeerPin(onboardingPayloadOrURI: String) throws -> PeerPin {
        let pin = try PeerTrust.parseOnboardingPayload(onboardingPayloadOrURI)
        peerPinStore.save(pin)
        return pin
    }

    func getPinnedPeer(peerId: String) -> PeerPin? {
        peerPinStore.get(peerId: peerId)
    }

    func removePinnedPeer(peerId: String) {
        peerPinStore.remove(peerId: peerId)
        // ADR-011: also revoke in Rust engine so the peer cannot download
        // in the current session (previously only cleared persistent storage).
        try? engine?.revokePeer(peerId: peerId)
    }

    // ── Zero-Copy Download ─────────────────────────────────────────────────────

    /// Download a remote model file directly to [destUrl].
    ///
    /// Fix v2.3: Uses Darwin.open() to obtain a raw fd.  There is NO Swift
    /// FileHandle wrapping the fd — so there is no double-close risk.
    /// Rust is the sole owner of the fd and closes it when done.
    ///
    /// - Parameters:
    ///   - expectedSha256: Hex SHA-256 from manifest; required.
    ///   - resumeFrom:     Bytes already on disk; 0 for a fresh download.
    func downloadModel(
        peerIp: String,
        peerPort: UInt16,
        seederPeerId: String,
        ticket: String,
        destUrl: URL,
        expectedSha256: String,
        resumeFrom: UInt64 = 0
    ) async throws {
        guard let engine else {
            throw AetherError.InternalError("Engine not initialised")
        }
        // Ensure destination file exists on disk
        if !FileManager.default.fileExists(atPath: destUrl.path) {
            FileManager.default.createFile(atPath: destUrl.path, contents: nil)
        }

        print("🚀 Zero-Copy download → \(destUrl.lastPathComponent)")

        // ADR-005: use O_TRUNC on fresh downloads so stale bytes from a prior larger file
        // don't survive and corrupt the SHA-256 check.
        let flags: Int32 = resumeFrom == 0
            ? (O_WRONLY | O_CREAT | O_TRUNC)
            : (O_WRONLY | O_CREAT)
        let fd = Darwin.open(destUrl.path, flags, 0o644)
        guard fd >= 0 else {
            throw AetherError.NetworkError("Failed to open \(destUrl.path): errno \(errno)")
        }
        // Seek to resume position if needed
        if resumeFrom > 0 {
            Darwin.lseek(fd, off_t(resumeFrom), SEEK_SET)
        }

        // Rust takes ownership of `fd` — we must NOT close it after this call.
        try await Task.detached(priority: .userInitiated) {
            try engine.downloadModel(
                peerIp:         peerIp,
                peerPort:       peerPort,
                seederPeerId:   seederPeerId,
                ticket:         ticket,
                expectedSha256: expectedSha256,
                resumeFrom:     resumeFrom,
                fd:             fd
            )
        }.value

        // fd is already closed by Rust at this point — do NOT call Darwin.close(fd).
        print("✅ Download complete → \(destUrl.lastPathComponent)")
    }

    // ── Decompression ──────────────────────────────────────────────────────────

    /// Decompress a `.zst` file produced by forge.py.
    /// Automatically deletes the compressed file on success.
    func decompressModel(compressedUrl: URL, outputUrl: URL) async throws {
        guard let engine else {
            throw AetherError.InternalError("Engine not initialised")
        }

        if !FileManager.default.fileExists(atPath: outputUrl.path) {
            FileManager.default.createFile(atPath: outputUrl.path, contents: nil)
        }

        let srcFd = Darwin.open(compressedUrl.path, O_RDONLY)
        guard srcFd >= 0 else {
            throw AetherError.DecompressError("Cannot open \(compressedUrl.path): errno \(errno)")
        }
        let dstFd = Darwin.open(outputUrl.path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
        guard dstFd >= 0 else {
            Darwin.close(srcFd)
            throw AetherError.DecompressError("Cannot open \(outputUrl.path): errno \(errno)")
        }

        let bytesWritten = try await Task.detached(priority: .utility) {
            try engine.decompressFile(compressedFd: srcFd, outputFd: dstFd)
        }.value

        // Both fds closed by Rust. Remove the compressed file.
        try? FileManager.default.removeItem(at: compressedUrl)
        print("✅ Decompressed \(bytesWritten) bytes → \(outputUrl.lastPathComponent)")
    }

    // ── Surgical Patching ──────────────────────────────────────────────────────

    /// Apply a bsdiff patch for a bandwidth-efficient model update.
    ///
    /// Fix v2.3:
    ///  • Manifest ECDSA signature is verified BEFORE any patch is applied.
    ///  • SHA-256 of both patch and output are verified by Rust.
    ///  • Raw fds via Darwin.open — no FileHandle double-close.
    func applySmartPatch(
        oldUrl: URL,
        patchUrl: URL,
        newUrl: URL,
        manifestJson: String,
        adminPublicKeyDer: Data,
        expectedPatchSha256: String,
        expectedOutputSha256: String
    ) async throws {
        guard let engine else {
            throw AetherError.InternalError("Engine not initialised")
        }

        // ── 1. Verify manifest signature ──────────────────────────────────────
        let manifest = try ManifestVerificationHelper.parseAndVerifyForUpdate(
            manifestJson: manifestJson,
            adminPublicKeyDer: adminPublicKeyDer,
            engine: engine,
            sequenceStore: KeychainManifestSequenceStore(
                service: Self.manifestSequenceKeychainService,
                defaults: .standard,
                legacyKey: Self.manifestSequenceDefaultsKey
            )
        )
        print("✅ Manifest signature + sequence verified in Rust")

        // ── 2. ADR-003: Check available RAM before patching ───────────────────
        let oldSize = (try? FileManager.default.attributesOfItem(atPath: oldUrl.path)[.size] as? UInt64) ?? 0
        let patchSize = (try? FileManager.default.attributesOfItem(atPath: patchUrl.path)[.size] as? UInt64) ?? 0
        do {
            try engine.checkPatchRamFeasibility(oldFileSize: oldSize, patchFileSize: patchSize)
        } catch {
            throw AetherError.PatchError("ADR-003: Insufficient RAM for patching (old=\(oldSize)B, patch=\(patchSize)B)")
        }

        // ── 3. Open raw fds (no FileHandle wrappers) ──────────────────────────
        if !FileManager.default.fileExists(atPath: newUrl.path) {
            FileManager.default.createFile(atPath: newUrl.path, contents: nil)
        }

        let oldFd   = Darwin.open(oldUrl.path,   O_RDONLY)
        let patchFd = Darwin.open(patchUrl.path,  O_RDONLY)
        let newFd   = Darwin.open(newUrl.path,    O_WRONLY | O_CREAT | O_TRUNC, 0o644)

        guard oldFd >= 0, patchFd >= 0, newFd >= 0 else {
            // Clean up any that did open
            if oldFd >= 0   { Darwin.close(oldFd) }
            if patchFd >= 0 { Darwin.close(patchFd) }
            if newFd >= 0   { Darwin.close(newFd) }
            throw AetherError.PatchError("Failed to open file descriptors")
        }

        // ── 4. Apply patch (Rust closes all three fds on return) ──────────────
        print("🔪 Surgical patch starting…")
        try await Task.detached(priority: .utility) {
            try engine.applyPatch(
                oldFd:               oldFd,
                patchFd:             patchFd,
                newFd:               newFd,
                expectedPatchSha256: expectedPatchSha256,
                expectedOutputSha256: expectedOutputSha256
            )
        }.value

        // fds are already closed by Rust — do NOT close them here.
        try? FileManager.default.removeItem(at: patchUrl)
        print("✨ Patch success → \(newUrl.lastPathComponent)")
    }

    // ── Peer Ping ──────────────────────────────────────────────────────────────

    func pingPeer(ip: String, port: UInt16, peerId: String? = nil) async -> Bool {
        do {
            return try await Task.detached(priority: .utility) {
                if let peerId {
                    return try self.engine?.pingPeerSecure(peerIp: ip, peerPort: port, peerId: peerId) ?? false
                }
                return try self.engine?.pingPeer(peerIp: ip, peerPort: port) ?? false
            }.value
        } catch {
            return false
        }
    }

    // ── Heartbeat ──────────────────────────────────────────────────────────────

    /// Fix v2.3: Bounded retry with exponential back-off.
    private func startHeartbeat() {
        heartbeatTask?.cancel()
        heartbeatTask = Task.detached(priority: .background) { [weak self] in
            var consecutiveFailures = 0
            // 5 s base — mirrors Config::HEARTBEAT_INTERVAL on the Rust side.
            let baseDelayNS: UInt64 = 5_000_000_000
            var delayNS = baseDelayNS

            while !Task.isCancelled {
                do {
                    // ADR-006: heartbeat now throws — `try` required for catch to fire.
                    // Guard engine explicitly: optional chaining `self?.engine?.heartbeat()`
                    // would succeed silently when engine is nil, masking startup failures.
                    guard let eng = self?.engine else {
                        try? await Task.sleep(nanoseconds: delayNS)
                        continue
                    }
                    try eng.heartbeat()
                    consecutiveFailures = 0
                    delayNS = 5_000_000_000
                } catch {
                    consecutiveFailures += 1
                    print("⚠️ Heartbeat failed (\(consecutiveFailures)/\(Self.MAX_HEARTBEAT_FAILURES))")
                    if consecutiveFailures >= Self.MAX_HEARTBEAT_FAILURES {
                        print("❌ Heartbeat max failures — restarting node")
                        await self?.restartNode()
                        consecutiveFailures = 0
                        delayNS = 5_000_000_000
                    } else {
                        delayNS = min(delayNS * 2, 30_000_000_000) // cap at 30s
                    }
                }
                try? await Task.sleep(nanoseconds: delayNS)
            }
        }
    }

    // ── Network monitor ────────────────────────────────────────────────────────

    private func setupNetworkMonitor() {
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            Task { @MainActor in
                if path.status == .satisfied && path.usesInterfaceType(.wifi) {
                    if !self.isNodeActive { self.startNode() }
                } else {
                    self.stopNode()
                }
            }
        }
        monitor.start(queue: monitorQ)
    }

    private func restartNode() {
        // ADR-007: guard — only stop if server is actually running
        if engine?.isServerRunning() == true {
            engine?.stopServer()
            // Poll until server is actually stopped (TCP socket released)
            Task.detached(priority: .userInitiated) {
                while await self.engine?.isServerRunning() == true {
                    try? await Task.sleep(nanoseconds: 50_000_000)
                }
                await MainActor.run {
                    self.startNode()
                }
            }
            return
        }
        isNodeActive = false
        activePort = 0
        startNode()
    }

    private func getStablePeerId() -> String {
        guard let publicKey = Vault.shared.getPublicKeyData() else {
            return UUID().uuidString
        }
        return SHA256.hash(data: publicKey).map { String(format: "%02x", $0) }.joined()
    }

}

// ── AetherEngine seeder extension ────────────────────────────────────────────

extension AetherManager {

    /// Register a local file to be served to authenticated peers.
    ///
    /// Must be called before starting the node if this device acts as a seeder.
    /// `modelId` must match the model_id field embedded in the HMAC ticket payload.
    func registerFileForServing(modelId: String, fileUrl: URL) {
        guard let engine else {
            lastError = "Engine not initialised"
            return
        }
        do {
            try engine.registerFileForServing(modelId: modelId, filePath: fileUrl.path)
            print("✅ AetherManager: registered seeder file \(modelId) → \(fileUrl.lastPathComponent)")
        } catch {
            lastError = error.localizedDescription
            print("❌ AetherManager: registerFileForServing failed – \(error)")
        }
    }

    func grantPeerModelAccess(peerId: String, modelId: String) {
        guard let engine else {
            lastError = "Engine not initialised"
            return
        }
        do {
            try engine.grantPeerModelAccess(peerId: peerId, modelId: modelId)
        } catch {
            lastError = error.localizedDescription
            print("❌ AetherManager: grantPeerModelAccess failed – \(error)")
        }
    }
}
