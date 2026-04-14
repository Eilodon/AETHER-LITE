# proguard-rules.pro

# ── UniFFI / JNA ──────────────────────────────────────────────────────────────
-keep class uniffi.** { *; }
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-dontwarn com.sun.jna.**

# ── Aether classes ────────────────────────────────────────────────────────────
-keep class com.b_one.aether.** { *; }
-keepclassmembers class com.b_one.aether.** { *; }

# ── Kotlin coroutines ─────────────────────────────────────────────────────────
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembers class kotlin.coroutines.** { *; }

# ── Serialization ─────────────────────────────────────────────────────────────
-keep class kotlinx.serialization.** { *; }
