package com.b_one.aether.security

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import org.json.JSONObject
import java.security.MessageDigest
import java.util.Base64

enum class PeerTrustMode {
    TOFU,
    QR_PINNED
}

data class PeerPin(
    val peerId: String,
    val publicKeyHex: String,
    val publicKeySha256: String,
    val protocolVersion: String,
    val trustMode: PeerTrustMode,
    val addedAtEpochMs: Long,
    val lastValidatedAtEpochMs: Long
)

data class PeerTrustDecision(
    val pin: PeerPin,
    val trustEstablishedNow: Boolean
)

object PeerTrust {
    const val ONBOARDING_SCHEME = "aether-peer-pin-v1"
    private const val ONBOARDING_URI_PREFIX = "aether://peer-pin?data="

    fun fingerprintHex(publicKeyBytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(publicKeyBytes)
            .joinToString("") { "%02x".format(it) }

    fun createOnboardingPayload(
        peerId: String,
        publicKeyHex: String,
        protocolVersion: String,
        canonicalize: (Map<String, Any?>) -> String = ::defaultCanonicalize
    ): String {
        val normalizedKeyHex = publicKeyHex.lowercase()
        val fingerprint = fingerprintHex(hexToBytes(normalizedKeyHex))
        return canonicalize(
            mapOf(
                "peer_id" to peerId,
                "protocol_version" to protocolVersion,
                "public_key_hex" to normalizedKeyHex,
                "public_key_sha256" to fingerprint,
                "scheme" to ONBOARDING_SCHEME
            )
        )
    }

    private fun defaultCanonicalize(map: Map<String, Any?>): String {
        val keys = map.keys.sorted()
        val pairs = keys.map { key ->
            val v = map.getValue(key)
            val rendered = when (v) {
                null -> "null"
                is String -> quote(v)
                is Number, is Boolean -> v.toString()
                else -> throw IllegalArgumentException("Unsupported canonical JSON value type")
            }
            "${quote(key)}:$rendered"
        }
        return "{${pairs.joinToString(",")}}"
    }

    private fun quote(s: String): String {
        val sb = StringBuilder(s.length + 2)
        sb.append('"')
        for (ch in s) {
            when (ch) {
                '\\' -> sb.append("\\\\")
                '"' -> sb.append("\\\"")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> if (ch.code < 0x20) sb.append("\\u%04x".format(ch.code)) else sb.append(ch)
            }
        }
        sb.append('"')
        return sb.toString()
    }

    fun createOnboardingUri(
        peerId: String,
        publicKeyHex: String,
        protocolVersion: String
    ): String {
        val payload = createOnboardingPayload(peerId, publicKeyHex, protocolVersion)
        val encoded = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payload.toByteArray(Charsets.UTF_8))
        return ONBOARDING_URI_PREFIX + encoded
    }

    fun parseOnboardingPayload(payloadOrUri: String, nowEpochMs: Long = System.currentTimeMillis()): PeerPin {
        val payload = if (payloadOrUri.startsWith(ONBOARDING_URI_PREFIX)) {
            val encoded = payloadOrUri.removePrefix(ONBOARDING_URI_PREFIX)
            String(Base64.getUrlDecoder().decode(encoded), Charsets.UTF_8)
        } else {
            payloadOrUri
        }

        val json = JSONObject(payload)
        require(json.getString("scheme") == ONBOARDING_SCHEME) { "Unsupported onboarding scheme" }

        val peerId = json.getString("peer_id")
        val publicKeyHex = json.getString("public_key_hex").lowercase()
        val expectedFingerprint = json.getString("public_key_sha256").lowercase()
        val protocolVersion = json.optString("protocol_version", "")
        val fingerprint = fingerprintHex(hexToBytes(publicKeyHex))
        require(fingerprint == expectedFingerprint) { "Onboarding payload fingerprint mismatch" }

        return PeerPin(
            peerId = peerId,
            publicKeyHex = publicKeyHex,
            publicKeySha256 = fingerprint,
            protocolVersion = protocolVersion,
            trustMode = PeerTrustMode.QR_PINNED,
            addedAtEpochMs = nowEpochMs,
            lastValidatedAtEpochMs = nowEpochMs
        )
    }

    fun evaluateHandshake(
        peerId: String,
        publicKeyHex: String,
        protocolVersion: String,
        existingPin: PeerPin?,
        trustOnFirstUse: Boolean,
        nowEpochMs: Long = System.currentTimeMillis()
    ): PeerTrustDecision {
        val normalizedKeyHex = publicKeyHex.lowercase()
        val fingerprint = fingerprintHex(hexToBytes(normalizedKeyHex))
        val currentProtocol = protocolVersion.ifBlank { existingPin?.protocolVersion.orEmpty() }

        if (existingPin != null) {
            require(existingPin.peerId == peerId) { "Pinned peer ID mismatch" }
            require(existingPin.publicKeySha256 == fingerprint) { "Pinned peer fingerprint mismatch" }
            require(existingPin.publicKeyHex == normalizedKeyHex) { "Pinned peer public key mismatch" }
            return PeerTrustDecision(
                pin = existingPin.copy(
                    protocolVersion = currentProtocol,
                    lastValidatedAtEpochMs = nowEpochMs
                ),
                trustEstablishedNow = false
            )
        }

        require(trustOnFirstUse) { "Peer is not pinned; disable TOFU only after QR onboarding" }
        return PeerTrustDecision(
            pin = PeerPin(
                peerId = peerId,
                publicKeyHex = normalizedKeyHex,
                publicKeySha256 = fingerprint,
                protocolVersion = currentProtocol,
                trustMode = PeerTrustMode.TOFU,
                addedAtEpochMs = nowEpochMs,
                lastValidatedAtEpochMs = nowEpochMs
            ),
            trustEstablishedNow = true
        )
    }

    fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Hex string must have even length" }
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}

class PeerPinStore(context: Context) {
    // ADR-008: EncryptedSharedPreferences replaces plaintext SharedPreferences.
    // Implements the same SharedPreferences interface — read/write code unchanged.
    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        "aether_peer_pins_encrypted",
        MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
        context,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    init {
        // One-time migration: copy pins from old plaintext SharedPreferences
        // into the new encrypted store, then delete the old file.
        migrateFromPlaintext(context)
    }

    fun get(peerId: String): PeerPin? {
        val raw = prefs.getString(key(peerId), null) ?: return null
        return runCatching { decode(raw) }.getOrNull()
    }

    fun save(pin: PeerPin) {
        prefs.edit().putString(key(pin.peerId), encode(pin)).apply()
    }

    fun remove(peerId: String) {
        prefs.edit().remove(key(peerId)).apply()
    }

    private fun key(peerId: String) = "peer_pin:$peerId"

    private fun encode(pin: PeerPin): String =
        JSONObject()
            .put("peer_id", pin.peerId)
            .put("public_key_hex", pin.publicKeyHex)
            .put("public_key_sha256", pin.publicKeySha256)
            .put("protocol_version", pin.protocolVersion)
            .put("trust_mode", pin.trustMode.name)
            .put("added_at_epoch_ms", pin.addedAtEpochMs)
            .put("last_validated_at_epoch_ms", pin.lastValidatedAtEpochMs)
            .toString()

    private fun decode(raw: String): PeerPin {
        val json = JSONObject(raw)
        val peerId = json.getString("peer_id")
        val publicKeyHex = json.getString("public_key_hex")
        val publicKeySha256 = json.getString("public_key_sha256")
        val protocolVersion = json.optString("protocol_version", "")
        val trustModeStr = json.getString("trust_mode")
        val addedAtEpochMs = json.getLong("added_at_epoch_ms")
        val lastValidatedAtEpochMs = json.getLong("last_validated_at_epoch_ms")

        // Validation: bounds check on timestamps (must be reasonable epoch ms)
        val now = System.currentTimeMillis()
        val year2020 = 1577836800000L // 2020-01-01 in epoch ms
        require(addedAtEpochMs in year2020..now + 86400000L) { "Invalid added_at_epoch_ms: $addedAtEpochMs" }
        require(lastValidatedAtEpochMs in year2020..now + 86400000L) { "Invalid last_validated_at_epoch_ms: $lastValidatedAtEpochMs" }

        // Validation: public key hex must be 130 chars (65 bytes = 130 hex chars for P-256 uncompressed)
        require(publicKeyHex.length == 130 && publicKeyHex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
            "Invalid publicKeyHex format"
        }
        // Validation: SHA-256 must be 64 hex chars
        require(publicKeySha256.length == 64 && publicKeySha256.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
            "Invalid publicKeySha256 format"
        }

        return PeerPin(
            peerId = peerId,
            publicKeyHex = publicKeyHex,
            publicKeySha256 = publicKeySha256,
            protocolVersion = protocolVersion,
            trustMode = PeerTrustMode.valueOf(trustModeStr),
            addedAtEpochMs = addedAtEpochMs,
            lastValidatedAtEpochMs = lastValidatedAtEpochMs
        )
    }

    private fun migrateFromPlaintext(context: Context) {
        val oldPrefs = context.getSharedPreferences("aether_peer_pins", Context.MODE_PRIVATE)
        if (oldPrefs.all.isEmpty()) return  // nothing to migrate

        val editor = prefs.edit()
        for ((k, v) in oldPrefs.all) {
            if (k.startsWith("peer_pin:") && v is String) {
                editor.putString(k, v)
            }
        }
        editor.apply()

        // Delete old plaintext data
        oldPrefs.edit().clear().apply()
    }
}
