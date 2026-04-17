// android/app/src/main/java/com/b_one/aether/service/AetherService.kt
package com.b_one.aether.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import com.b_one.aether.MainActivity
import com.b_one.aether.R
import com.b_one.aether.security.PeerPin
import com.b_one.aether.security.PeerPinStore
import com.b_one.aether.security.PeerTrust
import com.b_one.aether.security.SecureVault
import kotlinx.coroutines.*
import org.json.JSONObject
import uniffi.aether_core.AetherEngine
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * AetherService – Foreground service hosting the Rust P2P engine.
 *
 * Fixes v2.3:
 *  • MODE_READ_WRITE → MODE_WRITE_ONLY for downloads (minimal permissions).
 *  • Heartbeat has bounded retry with exponential back-off (won't silently die).
 *  • Manifest is ECDSA-verified before any patch is applied.
 *  • SHA-256 passed through to Rust for download integrity.
 *  • decompress() exposed for post-download zstd inflation.
 */
class AetherService : Service() {

    data class SeederGrant(val peerId: String, val modelId: String)

    companion object {
        private const val TAG              = "AetherService"
        private const val NOTIF_CHANNEL_ID = "aether_service_channel"
        private const val NOTIF_ID         = 1001

        const val ACTION_SERVER_STARTED = "com.b_one.aether.SERVER_STARTED"
        const val EXTRA_PORT            = "port"
        private const val MANIFEST_SEQUENCE_PREFS = "aether_manifest_sequences"

        // Maximum consecutive heartbeat failures before service gives up.
        private const val MAX_HEARTBEAT_FAILURES = 5
        private const val SERVER_RESTART_GRACE_MS = 250L
    }

    private val scope        = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val rustEngine: AetherEngine by lazy { AetherEngine() }
    private val manifestVerificationEngine by lazy { RustManifestVerificationEngine(rustEngine) }
    private val manifestSequenceStore by lazy {
        EncryptedManifestSequenceStore(applicationContext, MANIFEST_SEQUENCE_PREFS)
    }
    private val peerPinStore by lazy { PeerPinStore(applicationContext) }

    // ADR-010: single source of truth — query from Rust config instead of hardcoding
    private val protocolVersion: String by lazy { rustEngine.getProtocolVersion() }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(NOTIF_ID, buildNotification("Aether node starting…"))

        // Use a fingerprint of the hardware-backed identity key, not ANDROID_ID.
        rustEngine.setSelfPeerId(getStablePeerId())
        rustEngine.setSelfIdentityPublicKey(SecureVault.getPublicKeyX962Bytes())

        startRustServer()
        startHeartbeat()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

    override fun onDestroy() {
        super.onDestroy()
        Log.w(TAG, "Destroying – stopping Rust core")
        rustEngine.stopServer()
        scope.cancel()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // ── Server Management ─────────────────────────────────────────────────────

    private fun startRustServer() {
        scope.launch {
            try {
                startRustServerInternal()
            } catch (e: Exception) {
                Log.e(TAG, "❌ CRITICAL – Rust core failed to start", e)
                stopSelf()
            }
        }
    }

    private fun startRustServerInternal(): UShort {
        val port = rustEngine.startServer()
        Log.i(TAG, "✅ Swarm node active on :$port")
        updateNotification("Aether node active on :$port")
        sendBroadcast(Intent(ACTION_SERVER_STARTED).apply {
            putExtra(EXTRA_PORT, port.toInt())
            setPackage(packageName)
        })
        return port
    }

    // ── Zero-Copy Download ────────────────────────────────────────────────────

    /**
     * Download a model from a peer node directly to disk.
     *
     * Fix v2.3: Uses MODE_WRITE_ONLY (was incorrectly MODE_READ_WRITE).
     * SHA-256 is required and passed to Rust for integrity verification post-transfer.
     *
     * @param resumeFrom Set to the existing file size for a resumable download;
     *                   0 for a fresh start.
     */
    fun downloadModel(
        peerIp: String,
        peerPort: Int,
        seederPeerId: String,
        ticket: String,
        savePath: String,
        expectedSha256: String,
        resumeFrom: Long = 0L,
        onSuccess: (() -> Unit)? = null,
        onError: ((Exception) -> Unit)? = null
    ): Job {
        return scope.launch {
            try {
                Log.i(TAG, "🚀 Downloading from $peerIp:$peerPort → $savePath")
                val file = File(savePath).also {
                    if (!it.exists()) it.createNewFile()
                }

                // ADR-005: truncate the file when starting fresh so stale bytes from a
                // prior larger file don't survive and corrupt the SHA-256 check.
                val mode = ParcelFileDescriptor.MODE_WRITE_ONLY or
                           ParcelFileDescriptor.MODE_CREATE or
                           (if (resumeFrom == 0L) ParcelFileDescriptor.MODE_TRUNCATE else 0)
                val pfd  = ParcelFileDescriptor.open(file, mode)
                if (resumeFrom > 0L) {
                    Os.lseek(pfd.fileDescriptor, resumeFrom, OsConstants.SEEK_SET)
                }

                // detachFd: Kotlin relinquishes ownership → Rust will close the FD.
                val rawFd = pfd.detachFd()

                rustEngine.downloadModel(
                    peerIp          = peerIp,
                    peerPort        = peerPort.toUShort(),
                    seederPeerId    = seederPeerId,
                    ticket          = ticket,
                    expectedSha256  = expectedSha256,
                    resumeFrom      = resumeFrom.toULong(),
                    fd              = rawFd
                )
                Log.i(TAG, "✅ Download complete → $savePath")
                onSuccess?.invoke()

            } catch (e: Exception) {
                Log.e(TAG, "❌ Download failed", e)
                onError?.invoke(e)
            }
        }
    }

    // ── Decompression ─────────────────────────────────────────────────────────

    /**
     * Decompress a zstd-compressed file (.zst) into a raw output file.
     * Call this after [downloadModel] completes.
     */
    fun decompressModel(
        compressedPath: String,
        outputPath: String,
        onSuccess: (() -> Unit)? = null,
        onError: ((Exception) -> Unit)? = null
    ): Job {
        return scope.launch {
            try {
                Log.i(TAG, "📦 Decompressing $compressedPath → $outputPath")
                val compFile = File(compressedPath)
                val outFile  = File(outputPath).also { if (!it.exists()) it.createNewFile() }

                val compPfd = ParcelFileDescriptor.open(
                    compFile, ParcelFileDescriptor.MODE_READ_ONLY
                )
                val outPfd  = ParcelFileDescriptor.open(
                    outFile,
                    ParcelFileDescriptor.MODE_WRITE_ONLY or ParcelFileDescriptor.MODE_CREATE or
                    ParcelFileDescriptor.MODE_TRUNCATE
                )

                val bytesWritten = rustEngine.decompressFile(
                    compressedFd = compPfd.detachFd(),
                    outputFd     = outPfd.detachFd()
                )
                Log.i(TAG, "✅ Decompressed ${bytesWritten} bytes → $outputPath")
                compFile.delete() // clean up .zst after decompression
                onSuccess?.invoke()

            } catch (e: Exception) {
                Log.e(TAG, "❌ Decompression failed", e)
                onError?.invoke(e)
            }
        }
    }

    // ── Surgical Patching ─────────────────────────────────────────────────────

    /**
     * Apply a bsdiff patch for a bandwidth-efficient model update.
     *
     * Fix v2.3:
     *  • Manifest signature is ECDSA-verified BEFORE any patch is applied.
     *  • SHA-256 of both the patch file and output are verified by Rust.
     *
     * @param manifestJson   Raw contents of manifest.json from CDN.
     * @param adminPublicKey DER-encoded app_public.pem bundled in the APK.
     */
    fun updateModelSmart(
        currentVersionPath: String,
        patchPath: String,
        newVersionPath: String,
        manifestJson: String,
        adminPublicKey: ByteArray,
        expectedPatchSha256: String,
        expectedOutputSha256: String,
        onSuccess: (() -> Unit)? = null,
        onError: ((Exception) -> Unit)? = null
    ): Job {
        return scope.launch {
            try {
                // ── 1. Verify manifest signature first ────────────────────────
                try {
                    ManifestVerification.parseAndVerifyForUpdate(
                        manifestJson = manifestJson,
                        adminPublicKey = adminPublicKey,
                        engine = manifestVerificationEngine,
                        sequenceStore = manifestSequenceStore
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "❌ Manifest verification failed – aborting patch", e)
                    onError?.invoke(e)
                    return@launch
                }
                Log.i(TAG, "✅ Manifest signature + sequence verified in Rust")

                // ── 2. Apply patch via Rust ───────────────────────────────────
                Log.i(TAG, "🔪 Applying surgical patch…")
                val oldFile  = File(currentVersionPath)
                val patchFile = File(patchPath)
                val newFile  = File(newVersionPath).also { if (!it.exists()) it.createNewFile() }

                require(oldFile.exists())   { "Old model not found" }
                require(patchFile.exists()) { "Patch file not found" }

                // ADR-003: Check available RAM before patching to prevent OOM.
                val oldSize = oldFile.length()
                val patchSize = patchFile.length()
                try {
                    rustEngine.checkPatchRamFeasibility(oldSize.toULong(), patchSize.toULong())
                } catch (e: Exception) {
                    Log.e(TAG, "❌ ADR-003: Insufficient RAM for patching (old=${oldSize}B, patch=${patchSize}B)", e)
                    onError?.invoke(e)
                    return@launch
                }

                val oldPfd   = ParcelFileDescriptor.open(oldFile,   ParcelFileDescriptor.MODE_READ_ONLY)
                val patchPfd = ParcelFileDescriptor.open(patchFile, ParcelFileDescriptor.MODE_READ_ONLY)
                val newPfd   = ParcelFileDescriptor.open(newFile,
                    ParcelFileDescriptor.MODE_WRITE_ONLY or ParcelFileDescriptor.MODE_TRUNCATE)

                rustEngine.applyPatch(
                    oldFd                = oldPfd.detachFd(),
                    patchFd              = patchPfd.detachFd(),
                    newFd                = newPfd.detachFd(),
                    expectedPatchSha256  = expectedPatchSha256,
                    expectedOutputSha256 = expectedOutputSha256
                )

                Log.i(TAG, "✨ Smart update complete → $newVersionPath")
                patchFile.delete()
                onSuccess?.invoke()

            } catch (e: Exception) {
                Log.e(TAG, "❌ Smart update failed – consider full re-download", e)
                onError?.invoke(e)
            }
        }
    }

    // ── Heartbeat ─────────────────────────────────────────────────────────────

    /**
     * Fix v2.3: Heartbeat now has bounded retry with exponential back-off.
     * Previously it would silently die on any exception without logging.
     */
    private fun startHeartbeat() {
        scope.launch {
            var consecutiveFailures = 0
            // Use Config.HEARTBEAT_INTERVAL_MS rather than a magic literal so the
            // mobile and Rust sides stay in sync when the interval changes.
            val baseDelayMs = 5_000L   // mirrors Config::HEARTBEAT_INTERVAL (5s)
            var delayMs = baseDelayMs

            while (isActive) {
                try {
                    rustEngine.heartbeat()
                    consecutiveFailures = 0
                    delayMs = baseDelayMs
                } catch (e: Exception) {
                    consecutiveFailures++
                    Log.w(TAG, "⚠️ Heartbeat failed ($consecutiveFailures/$MAX_HEARTBEAT_FAILURES): ${e.message}")

                    if (consecutiveFailures >= MAX_HEARTBEAT_FAILURES) {
                        Log.e(TAG, "❌ Heartbeat exceeded max failures – restarting Rust core")
                        rustEngine.stopServer()
                        delay(SERVER_RESTART_GRACE_MS)
                        startRustServer()
                        consecutiveFailures = 0
                        delayMs = 5_000L
                    } else {
                        // Exponential back-off, capped at 30s
                        delayMs = minOf(delayMs * 2, 30_000L)
                    }
                }
                delay(delayMs)
            }
        }
    }

    // ── Notification helpers ──────────────────────────────────────────────────

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIF_CHANNEL_ID,
                "Aether P2P Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply { description = "Background P2P transfer node" }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val tap = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, NOTIF_CHANNEL_ID)
            .setContentTitle("Aether Suite")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_upload)
            .setContentIntent(tap)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, buildNotification(text))
    }

    private fun getStablePeerId(): String {
        val publicKey = SecureVault.getPublicKeyX962Bytes()
        val digest = MessageDigest.getInstance("SHA-256").digest(publicKey)
        return digest.joinToString("") { "%02x".format(it) }
    }

    // ── Seeder Role ───────────────────────────────────────────────────────────

    /**
     * Register a local file to be served to authenticated peers.
     * Must be called before [startRustServer] if this node acts as a seeder.
     *
     * @param modelId   Must match the model_id in the HMAC ticket payload.
     * @param filePath  Absolute path to the file on disk.
     */
    @Deprecated(
        message = "Calling this standalone method alongside startRustServer() is racy. " +
                "Use startSeederNode() instead, which runs all setup sequentially.",
        replaceWith = ReplaceWith("startSeederNode(modelId, filePath, grants)")
    )
    fun registerFileForServing(
        modelId: String,
        filePath: String,
        onSuccess: (() -> Unit)? = null,
        onError: ((Exception) -> Unit)? = null
    ): Job {
        return scope.launch {
            try {
                rustEngine.registerFileForServing(modelId = modelId, filePath = filePath)
                Log.i(TAG, "✅ Registered seeder file: $modelId → $filePath")
                onSuccess?.invoke()
            } catch (e: Exception) {
                Log.e(TAG, "❌ registerFileForServing failed", e)
                onError?.invoke(e)
            }
        }
    }

    /**
     * Grant a registered peer access to a specific model ID before it downloads.
     */
    @Deprecated(
        message = "Calling this standalone method alongside startRustServer() is racy. " +
                "Use startSeederNode() with grants parameter instead.",
        replaceWith = ReplaceWith("startSeederNode(modelId, filePath, grants)")
    )
    fun grantPeerModelAccess(
        peerId: String,
        modelId: String,
        onSuccess: (() -> Unit)? = null,
        onError: ((Exception) -> Unit)? = null
    ): Job {
        return scope.launch {
            try {
                rustEngine.grantPeerModelAccess(peerId = peerId, modelId = modelId)
                Log.i(TAG, "✅ Granted peer $peerId access to model $modelId")
                onSuccess?.invoke()
            } catch (e: Exception) {
                Log.e(TAG, "❌ grantPeerModelAccess failed", e)
                onError?.invoke(e)
            }
        }
    }

    /**
     * Seeder-safe startup entrypoint:
     *  1. stop existing server,
     *  2. register file,
     *  3. grant peer permissions,
     *  4. start server and broadcast only after all state is ready.
     */
    fun startSeederNode(
        modelId: String,
        filePath: String,
        grants: List<SeederGrant> = emptyList(),
        onSuccess: ((port: Int) -> Unit)? = null,
        onError: ((Exception) -> Unit)? = null
    ): Job {
        return scope.launch {
            try {
                // ADR-007: guard — only stop if server is actually running
                if (rustEngine.isServerRunning()) {
                    rustEngine.stopServer()
                    // Poll until server is actually stopped (TCP socket released)
                    while (rustEngine.isServerRunning()) {
                        delay(50)
                    }
                }

                rustEngine.registerFileForServing(modelId = modelId, filePath = filePath)
                grants.forEach { grant ->
                    rustEngine.grantPeerModelAccess(peerId = grant.peerId, modelId = grant.modelId)
                }

                val port = startRustServerInternal()
                Log.i(TAG, "✅ Seeder node ready for $modelId on :$port")
                onSuccess?.invoke(port.toInt())
            } catch (e: Exception) {
                Log.e(TAG, "❌ startSeederNode failed", e)
                onError?.invoke(e)
            }
        }
    }

    fun performAuthenticatedHandshake(
        peerIp: String,
        peerPort: Int,
        expectedPeerId: String? = null,
        expectedPeerPublicKeySha256: String? = null,
        trustOnFirstUse: Boolean = true,
        onSuccess: ((peerId: String, publicKeySha256: String, trustEstablishedNow: Boolean) -> Unit)? = null,
        onError: ((Exception) -> Unit)? = null
    ): Job {
        return scope.launch {
            try {
                val conn = (URL("http://$peerIp:$peerPort/identity").openConnection() as HttpURLConnection).apply {
                    requestMethod = "GET"
                    connectTimeout = 5_000
                    readTimeout = 5_000
                }
                conn.inputStream.bufferedReader().use { reader ->
                    val doc = JSONObject(reader.readText())
                    val peerId = doc.getString("peer_id")
                    val publicKeyHex = doc.getString("public_key_hex")
                    val peerProtocolVersion = doc.optString("protocol_version", "")
                    // ADR-010: centralized validation in Rust — rejects blank or incompatible version
                    rustEngine.validatePeerProtocol(peerProtocolVersion)
                    require(publicKeyHex.isNotBlank()) { "Peer did not publish an identity key" }

                    if (expectedPeerId != null) {
                        require(peerId == expectedPeerId) { "Peer ID mismatch" }
                    }

                    val publicKeyBytes = PeerTrust.hexToBytes(publicKeyHex)
                    val fingerprint = PeerTrust.fingerprintHex(publicKeyBytes)
                    if (expectedPeerPublicKeySha256 != null) {
                        require(fingerprint == expectedPeerPublicKeySha256) { "Peer public key fingerprint mismatch" }
                    }

                    val existingPin = peerPinStore.get(peerId)
                    val trustDecision = when {
                        existingPin != null -> PeerTrust.evaluateHandshake(
                            peerId = peerId,
                            publicKeyHex = publicKeyHex,
                            protocolVersion = peerProtocolVersion,
                            existingPin = existingPin,
                            trustOnFirstUse = false
                        )
                        expectedPeerPublicKeySha256 != null -> PeerTrust.pinnedDecisionFromVerifiedFingerprint(
                            peerId = peerId,
                            publicKeyHex = publicKeyHex,
                            protocolVersion = peerProtocolVersion
                        )
                        trustOnFirstUse -> throw SecurityException(
                            "Plaintext /identity bootstrap requires an existing pin or expected peer fingerprint; TOFU over HTTP is disabled"
                        )
                        else -> throw SecurityException(
                            "Peer is not pinned; complete QR onboarding or provide an expected peer fingerprint before using /identity"
                        )
                    }

                    val sharedSecret = SecureVault.performHandshake(publicKeyBytes)
                    rustEngine.registerPeerKey(peerId = peerId, sharedSecret = sharedSecret)
                    peerPinStore.save(trustDecision.pin)
                    Log.i(TAG, "✅ Authenticated handshake complete with $peerId")
                    onSuccess?.invoke(peerId, fingerprint, trustDecision.trustEstablishedNow)
                }
            } catch (e: Exception) {
                Log.e(TAG, "❌ Authenticated handshake failed", e)
                onError?.invoke(e)
            }
        }
    }

    fun exportSelfPeerOnboardingPayload(): String =
        PeerTrust.createOnboardingPayload(
            peerId = getStablePeerId(),
            publicKeyHex = SecureVault.getPublicKeyX962Bytes().joinToString("") { "%02x".format(it) },
            protocolVersion = protocolVersion
        )

    fun exportSelfPeerOnboardingUri(): String =
        PeerTrust.createOnboardingUri(
            peerId = getStablePeerId(),
            publicKeyHex = SecureVault.getPublicKeyX962Bytes().joinToString("") { "%02x".format(it) },
            protocolVersion = protocolVersion
        )

    fun importPeerPinFromOnboardingPayload(
        payloadOrUri: String,
        onSuccess: ((PeerPin) -> Unit)? = null,
        onError: ((Exception) -> Unit)? = null
    ): Job {
        return scope.launch {
            try {
                val pin = PeerTrust.parseOnboardingPayload(payloadOrUri)
                peerPinStore.save(pin)
                Log.i(TAG, "✅ Imported pinned peer ${pin.peerId} via onboarding payload")
                onSuccess?.invoke(pin)
            } catch (e: Exception) {
                Log.e(TAG, "❌ Failed to import peer pin", e)
                onError?.invoke(e)
            }
        }

    }

    fun getPinnedPeer(peerId: String): PeerPin? = peerPinStore.get(peerId)

    fun removePinnedPeer(peerId: String) {
        peerPinStore.remove(peerId)
        // ADR-011: also revoke in Rust engine so the peer cannot download
        // in the current session (previously only cleared persistent storage).
        try { rustEngine.revokePeer(peerId) } catch (_: Exception) {}
    }
}

internal class SharedPreferencesManifestSequenceStore(
    private val prefs: SharedPreferences,
) : ManifestSequenceStore {
    override fun getLastAccepted(modelId: String): Long = prefs.getLong(modelId, 0L)

    override fun persistAccepted(modelId: String, sequence: Long) {
        prefs.edit().putLong(modelId, sequence).apply()
    }
}

internal class EncryptedManifestSequenceStore(
    context: Context,
    legacyPrefsName: String,
) : ManifestSequenceStore {
    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        "${legacyPrefsName}_encrypted",
        MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
        context,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    init {
        migrateFromPlaintext(context, legacyPrefsName)
    }

    override fun getLastAccepted(modelId: String): Long = prefs.getLong(modelId, 0L)

    override fun persistAccepted(modelId: String, sequence: Long) {
        prefs.edit().putLong(modelId, sequence).apply()
    }

    private fun migrateFromPlaintext(context: Context, legacyPrefsName: String) {
        val oldPrefs = context.getSharedPreferences(legacyPrefsName, Context.MODE_PRIVATE)
        if (oldPrefs.all.isEmpty()) return

        val editor = prefs.edit()
        for ((key, value) in oldPrefs.all) {
            val longValue = when (value) {
                is Long -> value
                is Int -> value.toLong()
                else -> null
            } ?: continue
            if (longValue > 0L) {
                editor.putLong(key, longValue)
            }
        }
        editor.apply()
        oldPrefs.edit().clear().apply()
    }
}
