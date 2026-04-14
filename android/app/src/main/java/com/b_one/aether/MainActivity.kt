// android/app/src/main/java/com/b_one/aether/MainActivity.kt
package com.b_one.aether

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.b_one.aether.service.AetherService

/**
 * Minimal launcher activity.
 *
 * In a real app this would host your UI (Compose or View-based).
 * Here it simply shows the current node port received from the service.
 */
class MainActivity : AppCompatActivity() {

    private val portReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val port = intent.getIntExtra(AetherService.EXTRA_PORT, -1)
            Log.i("MainActivity", "Swarm node port: $port")
            // Update UI with the received port
            findViewById<TextView>(android.R.id.text1)?.text =
                "Aether node active on :$port"
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Replace with your actual layout
        setContentView(android.R.layout.simple_list_item_1)
        registerReceiver(
            portReceiver,
            IntentFilter(AetherService.ACTION_SERVER_STARTED),
            RECEIVER_NOT_EXPORTED
        )
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(portReceiver)
    }
}
