// android/app/build.gradle.kts
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.mozilla.rust-android-gradle.rust-android")
}

android {
    namespace   = "com.b_one.aether"
    compileSdk  = 34

    defaultConfig {
        applicationId = "com.b_one.aether"
        minSdk        = 26    // Android 8.0 — required for File Descriptor APIs
        targetSdk     = 34
        versionCode   = 1
        versionName   = "2.3.2"

        ndk {
            abiFilters.add("arm64-v8a")   // Modern physical devices
            abiFilters.add("x86_64")      // Emulator / x86 tablets
            // abiFilters.add("armeabi-v7a") // Uncomment for legacy 32-bit support
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isDebuggable = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = "1.8"
    }

    buildFeatures {
        viewBinding = true
    }
}

// ── Rust Cargo configuration ──────────────────────────────────────────────────
cargo {
    module  = "../../rust_core"    // Path to Cargo workspace
    libname = "aether_core"        // Builds → libaether_core.so
    targets = listOf("arm64", "x86_64")
    profile = "release"            // Always release for production perf
}

dependencies {
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.11.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")

    // Lifecycle
    implementation("androidx.lifecycle:lifecycle-service:2.7.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")

    // JNA – required by UniFFI on Android
    implementation("net.java.dev.jna:jna:5.14.0@aar")

    // ADR-008: EncryptedSharedPreferences for peer pin storage
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // Testing
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
}
