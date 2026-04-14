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

    @Published private(set) var isNodeActive = false
    @Published private(set) var activePort: UInt16 = 0
    @Published private(set) var lastError: String?

    private var engine: AetherEngine?
    private var monitor    = NWPathMonitor()
    private let monitorQ   = DispatchQueue(label: "com.b_one.aether.network")
    private var heartbeatTask: Task<Void, Never>?

    private static let MAX_HEARTBEAT_FAILURES = 5

    private init() {
        // Fix v2.3: engine initialisation can spin up a Tokio runtime — do it
        // on a background thread so we never block the main run loop.
        Task.detached(priority: .userInitiated) {
            let eng = AetherEngine()

            eng.setSelfPeerId(peerId: self.getStablePeerId())

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
            try self.engine?.decompressFile(compressedFd: srcFd, outputFd: dstFd) ?? 0
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
        let (canonicalJson, signatureHex) = try parseManifest(manifestJson)

        let valid = Vault.shared.verifyManifestSignature(
            canonicalJson: canonicalJson,
            signatureHex: signatureHex,
            publicKeyDer: adminPublicKeyDer
        )
        guard valid else {
            throw AetherError.SignatureVerificationFailed
        }
        print("✅ Manifest signature verified")

        // ── 2. Open raw fds (no FileHandle wrappers) ──────────────────────────
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

        // ── 3. Apply patch (Rust closes all three fds on return) ──────────────
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

    func pingPeer(ip: String, port: UInt16) async -> Bool {
        do {
            return try await Task.detached(priority: .utility) {
                try self.engine?.pingPeer(peerIp: ip, peerPort: port) ?? false
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
        engine?.stopServer()
        isNodeActive = false
        activePort = 0

        Task.detached(priority: .userInitiated) {
            try? await Task.sleep(nanoseconds: 250_000_000)
            await MainActor.run {
                self.startNode()
            }
        }
    }

    private func getStablePeerId() -> String {
        guard let publicKey = Vault.shared.getPublicKeyData() else {
            return UUID().uuidString
        }
        return SHA256.hash(data: publicKey).map { String(format: "%02x", $0) }.joined()
    }

    // ── Manifest JSON helpers ─────────────────────────────────────────────────

    /// Parse manifest.json → (canonicalJson, signatureHex)
    private func parseManifest(_ json: String) throws -> (String, String) {
        guard let data = json.data(using: .utf8),
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let payload   = root["payload"]   as? [String: Any],
              let signature = root["signature"] as? String
        else {
            throw AetherError.InternalError("Invalid manifest JSON")
        }
        let canonical = canonicalJSON(payload)
        return (canonical, signature)
    }

    /// Produce deterministic sorted-key JSON matching forge.py's output.
    ///
    /// Fix v2.3.2: String values are now properly escaped via `jsonEscapeString(_:)`
    /// so that values containing `"`, `\`, or control characters produce valid JSON
    /// and match the output of Python's `json.dumps()`. Previously `"\"\(str)\""` would
    /// produce invalid JSON (and a different canonical string than forge.py) for any
    /// model ID or version field containing a special character.
    private func canonicalJSON(_ dict: [String: Any]) -> String {
        let sortedKeys = dict.keys.sorted()
        let pairs = sortedKeys.map { key -> String in
            let val = dict[key]!
            let valStr: String
            if let nested = val as? [String: Any] {
                valStr = canonicalJSON(nested)
            } else if let arr = val as? [Any] {
                valStr = canonicalJSONArray(arr)
            } else if let str = val as? String {
                valStr = jsonEscapeString(str)   // Fix: proper JSON string escaping
            } else if val is NSNull {
                valStr = "null"
            } else {
                valStr = "\(val)"
            }
            return "\"\(jsonEscapeRawKey(key))\":\(valStr)"
        }
        return "{\(pairs.joined(separator: ","))}"
    }

    /// Wrap a Swift String in JSON quotes with all required escape sequences.
    /// Handles: `"` → `\"`, `\` → `\\`, control chars → `\uXXXX`.
    /// Matches Python's `json.dumps(s)` output for any valid Unicode string.
    private func jsonEscapeString(_ s: String) -> String {
        var out = "\""
        for scalar in s.unicodeScalars {
            switch scalar.value {
            case 0x22: out += "\\\""    // quotation mark
            case 0x5C: out += "\\\\"   // reverse solidus
            case 0x08: out += "\\b"    // backspace
            case 0x09: out += "\\t"    // tab
            case 0x0A: out += "\\n"    // newline
            case 0x0C: out += "\\f"    // form feed
            case 0x0D: out += "\\r"    // carriage return
            case 0x00..<0x20:          // other control characters
                out += String(format: "\\u%04x", scalar.value)
            default:
                out += String(scalar)
            }
        }
        out += "\""
        return out
    }

    private func canonicalJSONArray(_ values: [Any]) -> String {
        let rendered = values.map { value -> String in
            if let nested = value as? [String: Any] {
                return canonicalJSON(nested)
            } else if let arr = value as? [Any] {
                return canonicalJSONArray(arr)
            } else if let str = value as? String {
                return jsonEscapeString(str)
            } else if value is NSNull {
                return "null"
            } else {
                return "\(value)"
            }
        }
        return "[\(rendered.joined(separator: ","))]"
    }

    /// Escape a JSON object key (same rules as string values).
    private func jsonEscapeRawKey(_ key: String) -> String {
        // Keys follow the same escaping rules; strip surrounding quotes added by jsonEscapeString.
        let escaped = jsonEscapeString(key)
        return String(escaped.dropFirst().dropLast())
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
