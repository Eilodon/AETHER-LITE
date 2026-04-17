package com.b_one.aether.service

import org.json.JSONObject
import uniffi.aether_core.AetherEngine

internal data class ParsedManifestForUpdate(
    val modelId: String,
    val sequence: Long,
    val canonicalJson: String,
    val signatureHex: String,
)

internal interface ManifestSequenceStore {
    fun getLastAccepted(modelId: String): Long
    fun persistAccepted(modelId: String, sequence: Long)
}

internal interface ManifestVerificationEngine {
    fun canonicalizeJson(json: String): String
    fun seedManifestSequence(modelId: String, sequence: ULong)
    fun verifyManifestWithSequence(
        modelId: String,
        sequence: ULong,
        canonicalJson: String,
        sigHex: String,
        publicKeyDer: ByteArray,
    )
}

internal class RustManifestVerificationEngine(
    private val engine: AetherEngine,
) : ManifestVerificationEngine {
    override fun canonicalizeJson(json: String): String = engine.canonicalizeJson(json)

    override fun seedManifestSequence(modelId: String, sequence: ULong) {
        engine.seedManifestSequence(modelId, sequence)
    }

    override fun verifyManifestWithSequence(
        modelId: String,
        sequence: ULong,
        canonicalJson: String,
        sigHex: String,
        publicKeyDer: ByteArray,
    ) {
        engine.verifyManifestWithSequence(modelId, sequence, canonicalJson, sigHex, publicKeyDer)
    }
}

internal object ManifestVerification {
    fun parseAndVerifyForUpdate(
        manifestJson: String,
        adminPublicKey: ByteArray,
        engine: ManifestVerificationEngine,
        sequenceStore: ManifestSequenceStore,
    ): ParsedManifestForUpdate {
        val manifest = JSONObject(manifestJson)
        val payload = manifest.getJSONObject("payload")
        val signatureHex = manifest.getString("signature")
        val modelId = payload.getString("id")
        val sequence = if (payload.has("sequence") && !payload.isNull("sequence")) {
            payload.getLong("sequence")
        } else {
            throw SecurityException("Manifest sequence missing (ADR-016)")
        }
        require(sequence > 0L) { "Manifest sequence must be > 0 (ADR-016)" }

        val canonicalJson = engine.canonicalizeJson(payload.toString())
        val lastAccepted = sequenceStore.getLastAccepted(modelId)
        if (lastAccepted > 0L) {
            engine.seedManifestSequence(modelId, lastAccepted.toULong())
        }
        engine.verifyManifestWithSequence(
            modelId = modelId,
            sequence = sequence.toULong(),
            canonicalJson = canonicalJson,
            sigHex = signatureHex,
            publicKeyDer = adminPublicKey,
        )
        sequenceStore.persistAccepted(modelId, sequence)

        return ParsedManifestForUpdate(
            modelId = modelId,
            sequence = sequence,
            canonicalJson = canonicalJson,
            signatureHex = signatureHex,
        )
    }
}
