// android/app/src/main/java/com/b_one/aether/security/SecureVault.kt
package com.b_one.aether.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement

/**
 * Hardware-backed cryptographic vault using Android Keystore (TEE / StrongBox).
 *
 * Capabilities:
 *  1. ECDH identity key pair for peer-to-peer handshake.
 *  2. ECDSA-P256-SHA256 manifest signature verification
 *     (verifies packages published by forge.py with the admin private key).
 */
object SecureVault {

    private const val KEY_ALIAS        = "AetherIdentityKeyV2"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val EC_ALGORITHM     = KeyProperties.KEY_ALGORITHM_EC
    private const val ECDH_ALGORITHM   = "ECDH"

    // ── ECDH Identity ─────────────────────────────────────────────────────────

    fun getPublicKey(): PublicKey {
        val ks = loadKeyStore()
        if (!ks.containsAlias(KEY_ALIAS)) generateKeyPair()
        return ks.getCertificate(KEY_ALIAS).publicKey
    }

    fun getPublicKeyBytes(): ByteArray = getPublicKey().encoded

    /**
     * ADR-003: Return the public key in X9.62 uncompressed format (65 bytes).
     * This is the wire format shared with iOS (SecKeyCopyExternalRepresentation).
     * Use this instead of [getPublicKeyBytes] for peer-to-peer handshakes.
     */
    fun getPublicKeyX962Bytes(): ByteArray {
        val ecPub = getPublicKey() as ECPublicKey
        val point = ecPub.w
        // toFixedBytes() validates the BigInteger sign byte and pads correctly.
        val x = point.affineX.toFixedBytes(32)
        val y = point.affineY.toFixedBytes(32)
        return byteArrayOf(0x04) + x + y
    }

    /**
     * ADR-003: ECDH key agreement with a remote peer.
     *
     * @param peerPublicKeyBytes X9.62 uncompressed EC public key (65 bytes) from the peer.
     *   The wire format is now standardized on X9.62 for Android↔iOS interop.
     * @return 32-byte shared secret.
     */
    fun performHandshake(peerPublicKeyBytes: ByteArray): ByteArray {
        val ks         = loadKeyStore()
        val privateKey = ks.getKey(KEY_ALIAS, null) as PrivateKey

        // ADR-003: wrap the inbound X9.62 (65-byte) key in a DER SubjectPublicKeyInfo
        // header before feeding to KeyFactory, which expects X509EncodedKeySpec (DER).
        val derBytes   = encodeX962ToDer(peerPublicKeyBytes)
        val keyFactory = KeyFactory.getInstance(EC_ALGORITHM)
        val peerKey    = keyFactory.generatePublic(X509EncodedKeySpec(derBytes))

        return KeyAgreement.getInstance(ECDH_ALGORITHM).run {
            init(privateKey)
            doPhase(peerKey, true)
            generateSecret()   // 32 bytes for P-256
        }
    }

    // ── Manifest ECDSA Verification ───────────────────────────────────────────

    /**
     * Verify the ECDSA-P256-SHA256 signature on a manifest produced by forge.py.
     *
     * Should be called before applying any patch or trusting any manifest field.
     *
     * @param canonicalJson  Sorted-keys, no-space JSON of the `payload` object.
     * @param signatureHex   Hex-encoded DER ECDSA signature from `manifest.json`.
     * @param publicKeyBytes DER-encoded X.509 SubjectPublicKeyInfo bytes of
     *                       `app_public.pem` (bundled in the APK as a raw resource).
     * @return true if valid, false if invalid (never throws on invalid sig).
     */
    fun verifyManifestSignature(
        canonicalJson: String,
        signatureHex: String,
        publicKeyBytes: ByteArray
    ): Boolean {
        return try {
            val keyFactory = KeyFactory.getInstance(EC_ALGORITHM)
            val publicKey  = keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))
            val sigBytes   = hexToBytes(signatureHex)

            Signature.getInstance("SHA256withECDSA").run {
                initVerify(publicKey)
                update(canonicalJson.toByteArray(Charsets.UTF_8))
                verify(sigBytes)
            }
        } catch (e: Exception) {
            android.util.Log.e("SecureVault", "Manifest verification error: ${e.message}")
            false
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    private fun loadKeyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun generateKeyPair() {
        // ADR-004: explicitly specify P-256 curve; Android Keystore does not guarantee
        // a default curve, so omitting this can produce a key on an unexpected curve.
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_AGREE_KEY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .build()

        KeyPairGenerator.getInstance(EC_ALGORITHM, ANDROID_KEYSTORE).run {
            initialize(spec)
            generateKeyPair()
        }
    }

    private fun hexToBytes(hex: String): ByteArray {
        check(hex.length % 2 == 0) { "Hex string must have even length" }
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    /**
     * Convert a BigInteger to a fixed-size big-endian byte array.
     *
     * `BigInteger.toByteArray()` may return:
     *   - `size` bytes        → straight copy
     *   - `size + 1` bytes    → has a leading 0x00 sign byte (for positive values
     *                           whose MSB is set). The sign byte is verified to be
     *                           0x00 and stripped.
     *   - `< size` bytes      → left-padded with 0x00.
     *
     * Throws `IllegalArgumentException` if the value is too large for [size] bytes,
     * which would indicate a curve implementation bug (P-256 coordinates are always
     * ≤ 32 bytes for the x/y fields).
     */
    private fun java.math.BigInteger.toFixedBytes(size: Int): ByteArray {
        val raw = toByteArray()
        require(raw.size <= size + 1) {
            "BigInteger too large for $size bytes: got ${raw.size} bytes"
        }
        if (raw.size == size + 1) {
            require(raw[0] == 0.toByte()) {
                "BigInteger sign byte is non-zero (${raw[0]}); value does not fit in $size bytes"
            }
            return raw.copyOfRange(1, raw.size)
        }
        if (raw.size == size) return raw
        // Left-pad with zeroes to reach target size.
        return ByteArray(size - raw.size) + raw
    }

    /**
     * ADR-003: Wrap a raw X9.62 uncompressed point (0x04 || X || Y, 65 bytes)
     * in a DER SubjectPublicKeyInfo structure so that Java's KeyFactory can parse it.
     *
     * DER layout:
     *   SEQUENCE {
     *     SEQUENCE { OID ecPublicKey, OID secp256r1 }
     *     BIT STRING { 0x00, <65 bytes> }
     *   }
     */
    private fun encodeX962ToDer(x962: ByteArray): ByteArray {
        require(x962.size == 65 && x962[0] == 0x04.toByte()) {
            "Expected 65-byte X9.62 uncompressed point"
        }
        // OID for id-ecPublicKey (1.2.840.10045.2.1)
        val ecOid      = byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x02, 0x01)
        // OID for secp256r1 (1.2.840.10045.3.1.7)
        val curveOid   = byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x03, 0x01, 0x07)

        // DER short-form length: valid for values 0–127.
        // All components here are well under 127 bytes (outer SEQUENCE = 91 bytes for P-256),
        // so single-byte length encoding is correct. This function is intentionally scoped
        // to 65-byte P-256 X9.62 keys — do not generalise without adding multi-byte length support.
        fun tlv(tag: Byte, content: ByteArray): ByteArray {
            require(content.size <= 127) {
                "DER short-form length overflow: ${content.size} bytes (max 127). " +
                "Extend to multi-byte BER/DER length encoding for larger payloads."
            }
            return byteArrayOf(tag, content.size.toByte()) + content
        }

        val algId  = tlv(0x30, tlv(0x06, ecOid) + tlv(0x06, curveOid))
        val bitStr = tlv(0x03, byteArrayOf(0x00) + x962)
        return tlv(0x30, algId + bitStr)
    }
}
