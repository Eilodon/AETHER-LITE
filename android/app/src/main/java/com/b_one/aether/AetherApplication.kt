// android/app/src/main/java/com/b_one/aether/AetherApplication.kt
package com.b_one.aether

import android.app.Application
import android.content.Intent
import android.os.Build
import android.util.Log
import com.b_one.aether.service.AetherService

/**
 * Application entry point.
 *
 * Responsible for bootstrapping the AetherService on launch.
 * On Android 8+ we use startForegroundService() so the service can
 * immediately call startForeground() within the 5-second ANR window.
 */
class AetherApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        Log.i("AetherApp", "Application started – launching Aether service")
        launchService()
    }

    private fun launchService() {
        val intent = Intent(this, AetherService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }
}
