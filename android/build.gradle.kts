// android/build.gradle.kts
buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath("com.android.tools.build:gradle:8.2.2")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.22")
        // Mozilla's Rust-Android Gradle plugin: auto-compiles Rust on every build
        classpath("org.mozilla.rust-android-gradle:plugin:0.9.3")
    }
}

plugins {
    id("com.android.application")          version "8.2.2"  apply false
    id("org.jetbrains.kotlin.android")     version "1.9.22" apply false
    id("org.mozilla.rust-android-gradle.rust-android") version "0.9.3" apply false
}
