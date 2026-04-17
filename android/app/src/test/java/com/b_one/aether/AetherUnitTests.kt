package com.b_one.aether

import com.b_one.aether.service.ManifestSequenceStore
import com.b_one.aether.service.ManifestVerification
import com.b_one.aether.service.ManifestVerificationEngine
import com.b_one.aether.security.PeerTrust
import com.b_one.aether.security.PeerTrustMode
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import java.math.BigInteger
import java.security.MessageDigest

@RunWith(JUnit4::class)
class AetherUnitTests {

    private class FakeManifestVerificationEngine : ManifestVerificationEngine {
        val seeded = mutableListOf<Pair<String, ULong>>()
        val verified = mutableListOf<Pair<String, ULong>>()
        var canonicalResult = "{}"
        var verifyError: Exception? = null

        override fun canonicalizeJson(json: String): String = canonicalResult

        override fun seedManifestSequence(modelId: String, sequence: ULong) {
            seeded += modelId to sequence
        }

        override fun verifyManifestWithSequence(
            modelId: String,
            sequence: ULong,
            canonicalJson: String,
            sigHex: String,
            publicKeyDer: ByteArray
        ) {
            verifyError?.let { throw it }
            verified += modelId to sequence
        }
    }

    private class FakeManifestSequenceStore(
        private val values: MutableMap<String, Long> = mutableMapOf()
    ) : ManifestSequenceStore {
        override fun getLastAccepted(modelId: String): Long = values[modelId] ?: 0L

        override fun persistAccepted(modelId: String, sequence: Long) {
            values[modelId] = sequence
        }

        fun persisted(modelId: String): Long? = values[modelId]
    }

    private fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0)
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun sha256Hex(data: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data).joinToString("") { "%02x".format(it) }
    }

    private fun BigInteger.toFixedBytes(size: Int): ByteArray {
        val raw = toByteArray()
        require(raw.size <= size + 1) { "BigInteger too large for $size bytes: got ${raw.size}" }
        if (raw.size == size + 1) {
            require(raw[0] == 0.toByte()) { "BigInteger sign byte is non-zero" }
            return raw.copyOfRange(1, raw.size)
        }
        if (raw.size == size) return raw
        return ByteArray(size - raw.size) + raw
    }

    @Test
    fun `hex conversion roundtrip`() {
        val original = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
        val hex = original.joinToString("") { "%02x".format(it) }
        assertArrayEquals(original, hexToBytes(hex))
    }

    @Test
    fun `hex conversion all zeros`() {
        assertArrayEquals(ByteArray(3) { 0 }, hexToBytes("000000"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `hex conversion odd length throws`() {
        hexToBytes("abc")
    }

    @Test
    fun `sha256 known vector`() {
        val empty = sha256Hex(ByteArray(0))
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", empty)
    }

    @Test
    fun `sha256 different data produces different digests`() {
        val a = sha256Hex("data_v1".toByteArray())
        val b = sha256Hex("data_v2".toByteArray())
        assertNotEquals(a, b)
    }

    @Test
    fun `onboarding payload roundtrip preserves pin`() {
        val publicKeyHex = "04" + "11".repeat(64)
        val uri = PeerTrust.createOnboardingUri(
            peerId = "peer-a",
            publicKeyHex = publicKeyHex,
            protocolVersion = "v2.3-swarm-fixed"
        )

        val pin = PeerTrust.parseOnboardingPayload(uri, nowEpochMs = 1234L)
        assertEquals("peer-a", pin.peerId)
        assertEquals(publicKeyHex, pin.publicKeyHex)
        assertEquals(PeerTrustMode.QR_PINNED, pin.trustMode)
        assertEquals(1234L, pin.addedAtEpochMs)
        assertEquals(sha256Hex(hexToBytes(publicKeyHex)), pin.publicKeySha256)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `onboarding payload rejects tampered fingerprint`() {
        val payload = """
            {"peer_id":"peer-a","protocol_version":"v2","public_key_hex":"04${"22".repeat(64)}","public_key_sha256":"deadbeef","scheme":"aether-peer-pin-v1"}
        """.trimIndent()
        PeerTrust.parseOnboardingPayload(payload)
    }

    @Test
    fun `handshake with pinned peer updates timestamp without retrusting`() {
        val publicKeyHex = "04" + "33".repeat(64)
        val existing = PeerTrust.parseOnboardingPayload(
            PeerTrust.createOnboardingPayload("peer-a", publicKeyHex, "v2"),
            nowEpochMs = 100L
        )

        val decision = PeerTrust.evaluateHandshake(
            peerId = "peer-a",
            publicKeyHex = publicKeyHex,
            protocolVersion = "v3",
            existingPin = existing,
            trustOnFirstUse = false,
            nowEpochMs = 500L
        )

        assertFalse(decision.trustEstablishedNow)
        assertEquals(PeerTrustMode.QR_PINNED, decision.pin.trustMode)
        assertEquals(100L, decision.pin.addedAtEpochMs)
        assertEquals(500L, decision.pin.lastValidatedAtEpochMs)
        assertEquals("v3", decision.pin.protocolVersion)
    }

    @Test
    fun `handshake creates TOFU pin on first use when allowed`() {
        val publicKeyHex = "04" + "44".repeat(64)
        val decision = PeerTrust.evaluateHandshake(
            peerId = "peer-tofu",
            publicKeyHex = publicKeyHex,
            protocolVersion = "v2",
            existingPin = null,
            trustOnFirstUse = true,
            nowEpochMs = 250L
        )

        assertTrue(decision.trustEstablishedNow)
        assertEquals(PeerTrustMode.TOFU, decision.pin.trustMode)
        assertEquals("peer-tofu", decision.pin.peerId)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `handshake rejects first use when TOFU disabled`() {
        PeerTrust.evaluateHandshake(
            peerId = "peer-strict",
            publicKeyHex = "04" + "55".repeat(64),
            protocolVersion = "v2",
            existingPin = null,
            trustOnFirstUse = false
        )
    }

    @Test
    fun `MODE_WRITE_ONLY is not MODE_READ_WRITE`() {
        val writeOnly = android.os.ParcelFileDescriptor.MODE_WRITE_ONLY
        val readWrite = android.os.ParcelFileDescriptor.MODE_READ_WRITE
        assertNotEquals(writeOnly, readWrite)
    }

    @Test
    fun `exponential backoff stays within bounds`() {
        var delay = 5_000L
        val maxDelay = 30_000L
        repeat(10) {
            delay = minOf(delay * 2, maxDelay)
        }
        assertEquals(maxDelay, delay)
    }

    @Test
    fun `backoff doubles correctly`() {
        val delays = mutableListOf<Long>()
        var d = 5_000L
        repeat(4) {
            d = minOf(d * 2, 30_000L)
            delays.add(d)
        }
        assertEquals(listOf(10_000L, 20_000L, 30_000L, 30_000L), delays)
    }

    @Test
    fun `toFixedBytes pads small BigInteger correctly`() {
        val bytes = BigInteger.ONE.toFixedBytes(32)
        assertEquals(32, bytes.size)
        assertEquals(0.toByte(), bytes[0])
        assertEquals(1.toByte(), bytes[31])
    }

    @Test
    fun `toFixedBytes handles exact-size BigInteger`() {
        val big = BigInteger("1".repeat(64), 16)
        assertEquals(32, big.toFixedBytes(32).size)
    }

    @Test
    fun `toFixedBytes strips valid sign byte`() {
        val raw = byteArrayOf(0) + ByteArray(32) { 0xFF.toByte() }
        val value = BigInteger(raw)
        val bytes = value.toFixedBytes(32)
        assertEquals(32, bytes.size)
        assertTrue(bytes.all { it == 0xFF.toByte() })
    }

    @Test(expected = IllegalArgumentException::class)
    fun `toFixedBytes throws for oversized value`() {
        val tooBig = BigInteger(ByteArray(33) { 0x01.toByte() })
        tooBig.toFixedBytes(32)
    }

    @Test
    fun `manifest verification seeds previous sequence and persists newer accepted sequence`() {
        val engine = FakeManifestVerificationEngine().apply {
            canonicalResult = """{"id":"llm-mini","sequence":7}"""
        }
        val store = FakeManifestSequenceStore(mutableMapOf("llm-mini" to 6L))
        val manifestJson = """
            {"payload":{"id":"llm-mini","sequence":7},"signature":"abcd"}
        """.trimIndent()

        val parsed = ManifestVerification.parseAndVerifyForUpdate(
            manifestJson = manifestJson,
            adminPublicKey = byteArrayOf(1, 2, 3),
            engine = engine,
            sequenceStore = store
        )

        assertEquals("llm-mini", parsed.modelId)
        assertEquals(7L, parsed.sequence)
        assertEquals(listOf("llm-mini" to 6uL), engine.seeded)
        assertEquals(listOf("llm-mini" to 7uL), engine.verified)
        assertEquals(7L, store.persisted("llm-mini"))
    }

    @Test
    fun `manifest rollback rejection does not persist downgraded sequence`() {
        val engine = FakeManifestVerificationEngine().apply {
            canonicalResult = """{"id":"llm-mini","sequence":5}"""
            verifyError = SecurityException(
                "Manifest sequence 5 is not greater than last accepted 6 (ADR-016)"
            )
        }
        val store = FakeManifestSequenceStore(mutableMapOf("llm-mini" to 6L))
        val manifestJson = """
            {"payload":{"id":"llm-mini","sequence":5},"signature":"abcd"}
        """.trimIndent()

        val error = assertThrows(SecurityException::class.java) {
            ManifestVerification.parseAndVerifyForUpdate(
                manifestJson = manifestJson,
                adminPublicKey = byteArrayOf(1, 2, 3),
                engine = engine,
                sequenceStore = store
            )
        }

        assertTrue(error.message!!.contains("not greater than last accepted 6"))
        assertEquals(listOf("llm-mini" to 6uL), engine.seeded)
        assertEquals(6L, store.persisted("llm-mini"))
    }
}
