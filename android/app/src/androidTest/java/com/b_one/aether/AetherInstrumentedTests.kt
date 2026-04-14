// android/app/src/androidTest/java/com/b_one/aether/AetherInstrumentedTests.kt
package com.b_one.aether

import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.b_one.aether.security.SecureVault
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest

/**
 * Instrumented tests – require a real Android device or emulator (minSdk 26).
 *
 * Run with:
 *   ./gradlew connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class AetherInstrumentedTests {

    private val ctx by lazy {
        InstrumentationRegistry.getInstrumentation().targetContext
    }

    // ── SecureVault ───────────────────────────────────────────────────────────

    @Test
    fun secureVault_publicKey_notNull() {
        val key = SecureVault.getPublicKeyBytes()
        assertNotNull(key)
        assertTrue("Key must be non-empty", key.isNotEmpty())
    }

    @Test
    fun secureVault_publicKey_isDeterministic() {
        // Same key should be returned on repeated calls (persisted in Keystore)
        val k1 = SecureVault.getPublicKeyBytes()
        val k2 = SecureVault.getPublicKeyBytes()
        assertArrayEquals(k1, k2)
    }

    @Test
    fun secureVault_handshake_sameKeyPairProducesConsistentSecret() {
        // Simulate a loopback: use our own public key as "peer" key.
        // In ECDH, handshake(ownPub) with own private is mathematically valid,
        // though in production you'd use a different peer's key.
        val ownPub = SecureVault.getPublicKeyBytes()
        val s1 = SecureVault.performHandshake(ownPub)
        val s2 = SecureVault.performHandshake(ownPub)
        assertArrayEquals("Same peer key must produce same secret", s1, s2)
        assertEquals(32, s1.size)
    }

    // ── File Descriptor mode ──────────────────────────────────────────────────

    @Test
    fun parcelFd_writeOnly_isCorrectMode() {
        val file = File(ctx.cacheDir, "test_fd_mode.bin")
        file.createNewFile()

        val pfd = ParcelFileDescriptor.open(
            file,
            ParcelFileDescriptor.MODE_WRITE_ONLY or ParcelFileDescriptor.MODE_CREATE
        )
        assertTrue("FD must be valid (≥ 0)", pfd.fd >= 0)
        pfd.close()
        file.delete()
    }

    @Test
    fun parcelFd_detachFd_closesParcelDescriptorOnly() {
        val file = File(ctx.cacheDir, "test_detach.bin")
        file.createNewFile()

        val pfd   = ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_WRITE_ONLY)
        val rawFd = pfd.detachFd()
        // After detach, pfd should be in a detached state (fd == -1)
        assertEquals(-1, pfd.fd)
        assertTrue("Raw fd must remain valid", rawFd >= 0)
        // Close the raw fd manually since we detached it
        android.system.Os.close(android.system.Os.open(
            file.path,
            android.system.OsConstants.O_RDONLY, 0)
        )
        file.delete()
    }

    // ── SHA-256 ───────────────────────────────────────────────────────────────

    @Test
    fun sha256_writtenFile_matchesExpected() {
        val data = "Aether test payload for SHA-256 verification".toByteArray()
        val file = File(ctx.cacheDir, "sha256_test.bin")
        file.writeBytes(data)

        val digest = MessageDigest.getInstance("SHA-256")
        val actual = digest.digest(file.readBytes()).joinToString("") { "%02x".format(it) }

        val expected = digest.digest(data).joinToString("") { "%02x".format(it) }

        // Reset and recompute expected from raw bytes
        val recomputed = MessageDigest.getInstance("SHA-256")
            .digest(data).joinToString("") { "%02x".format(it) }

        assertEquals(recomputed, actual)
        file.delete()
    }
}
