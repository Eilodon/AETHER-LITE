package com.b_one.aether

import com.b_one.aether.util.CanonicalJson
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.json.JSONArray
import java.math.BigInteger
import java.security.MessageDigest

@RunWith(JUnit4::class)
class AetherUnitTests {

    private fun toCanonicalJson(map: Map<String, Any?>): String = CanonicalJson.fromMap(map)

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
    fun `canonical JSON sorts keys`() {
        val json = toCanonicalJson(mapOf("z" to "last", "a" to "first", "m" to "middle"))
        assertEquals("""{"a":"first","m":"middle","z":"last"}""", json)
    }

    @Test
    fun `canonical JSON matches forge py output format`() {
        val payload = mapOf(
            "id" to "llm-mini",
            "version" to "2.0",
            "timestamp" to 1713000000
        )
        assertEquals(
            """{"id":"llm-mini","timestamp":1713000000,"version":"2.0"}""",
            toCanonicalJson(payload)
        )
    }

    @Test
    fun `canonical JSON handles nested objects`() {
        val payload = mapOf(
            "full" to mapOf("size" to 1024, "url" to "https://cdn/model.zst"),
            "id" to "m"
        )
        assertEquals(
            """{"full":{"size":1024,"url":"https://cdn/model.zst"},"id":"m"}""",
            toCanonicalJson(payload)
        )
    }

    @Test
    fun `canonical JSON handles arrays`() {
        val payload = mapOf(
            "arches" to JSONArray(listOf("arm64", "x86_64")),
            "id" to "m"
        )
        assertEquals(
            """{"arches":["arm64","x86_64"],"id":"m"}""",
            toCanonicalJson(payload)
        )
    }

    @Test
    fun `canonical JSON escapes key characters`() {
        val json = toCanonicalJson(mapOf("quo\"te" to "value"))
        assertEquals("""{"quo\"te":"value"}""", json)
    }

    @Test
    fun `canonical JSON escapes string values`() {
        val json = toCanonicalJson(mapOf("path" to "C:\\Users\\admin", "quote" to "say \"hi\""))
        assertEquals(
            """{"path":"C:\\Users\\admin","quote":"say \"hi\""}""",
            json
        )
    }

    @Test
    fun `canonical JSON handles null values`() {
        assertEquals("""{"patch":null}""", toCanonicalJson(mapOf("patch" to null)))
    }

    @Test
    fun `canonical JSON empty object`() {
        assertEquals("{}", toCanonicalJson(emptyMap()))
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
}
