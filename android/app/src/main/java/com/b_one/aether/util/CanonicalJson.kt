package com.b_one.aether.util

import org.json.JSONObject
import org.json.JSONArray

object CanonicalJson {
    fun fromMap(map: Map<String, Any?>): String = buildCanonicalObject(map)

    fun fromJsonObject(obj: JSONObject): String {
        val map = obj.keys().asSequence().associateWith { key ->
            val value = obj.get(key)
            if (value == JSONObject.NULL) null else value
        }
        return buildCanonicalObject(map)
    }

    private fun buildCanonicalObject(map: Map<String, Any?>): String {
        val sb = StringBuilder("{")
        map.keys.sorted().forEachIndexed { index, key ->
            if (index > 0) sb.append(',')
            sb.append(quote(key)).append(':').append(renderValue(map.getValue(key)))
        }
        return sb.append('}').toString()
    }

    private fun renderValue(value: Any?): String = when (value) {
        null -> "null"
        is String -> quote(value)
        is Number, is Boolean -> value.toString()
        is JSONObject -> fromJsonObject(value)
        is JSONArray -> buildCanonicalArray((0 until value.length()).map { idx ->
            val item = value.get(idx)
            if (item == JSONObject.NULL) null else item
        })
        is List<*> -> buildCanonicalArray(value)
        is Map<*, *> -> {
            @Suppress("UNCHECKED_CAST")
            buildCanonicalObject(value as Map<String, Any?>)
        }
        else -> throw IllegalArgumentException("Unsupported canonical JSON value type: ${value::class.java.name}")
    }

    private fun buildCanonicalArray(values: List<*>): String =
        values.joinToString(prefix = "[", postfix = "]", separator = ",") { renderValue(it) }

    private fun quote(value: String): String {
        val sb = StringBuilder(value.length + 2)
        sb.append('"')
        value.forEach { ch ->
            when (ch) {
                '\\' -> sb.append("\\\\")
                '"' -> sb.append("\\\"")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\u2028', '\u2029' -> sb.append("\\u%04x".format(ch.code))
                else -> {
                    if (ch.code < 0x20) {
                        sb.append("\\u%04x".format(ch.code))
                    } else {
                        sb.append(ch)
                    }
                }
            }
        }
        sb.append('"')
        return sb.toString()
    }
}
