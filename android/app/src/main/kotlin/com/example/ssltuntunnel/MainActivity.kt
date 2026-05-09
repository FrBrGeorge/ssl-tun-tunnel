package com.example.ssltuntunnel

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.RadioGroup
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val hostEdit = findViewById<EditText>(R.id.editHost)
        val portEdit = findViewById<EditText>(R.id.editPort)
        val tunIpEdit = findViewById<EditText>(R.id.editTunIp)
        val fingerprintEdit = findViewById<EditText>(R.id.editFingerprint)
        val bufferCheck = findViewById<CheckBox>(R.id.checkBuffered)
        val flushTimeoutEdit = findViewById<EditText>(R.id.editFlushTimeout)
        val fillGroup = findViewById<RadioGroup>(R.id.groupFill)
        val startBtn = findViewById<Button>(R.id.btnStart)
        val stopBtn = findViewById<Button>(R.id.btnStop)

        startBtn.setOnClickListener {
            val intent = VpnService.prepare(this)
            if (intent != null) {
                startActivityForResult(intent, 0)
            } else {
                onActivityResult(0, RESULT_OK, null)
            }
        }

        stopBtn.setOnClickListener {
            val intent = Intent(this, VpnTunnelService::class.java).apply {
                action = "STOP"
            }
            startService(intent)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode == RESULT_OK) {
            val host = findViewById<EditText>(R.id.editHost).text.toString()
            val port = findViewById<EditText>(R.id.editPort).text.toString().toIntOrNull() ?: 443
            val tunIp = findViewById<EditText>(R.id.editTunIp).text.toString()
            val fingerprint = findViewById<EditText>(R.id.editFingerprint).text.toString().takeIf { it.isNotEmpty() }
            val buffered = findViewById<CheckBox>(R.id.checkBuffered).isChecked
            val flushTimeout = findViewById<EditText>(R.id.editFlushTimeout).text.toString().toLongOrNull() ?: 1000L
            
            val fillMode = when (findViewById<RadioGroup>(R.id.groupFill).checkedRadioButtonId) {
                R.id.radioFillAll -> "all"
                R.id.radioFillThroughput -> "throughput"
                else -> "none"
            }

            val intent = Intent(this, VpnTunnelService::class.java).apply {
                putExtra("HOST", host)
                putExtra("PORT", port)
                putExtra("TUN_IP", tunIp)
                putExtra("FINGERPRINT", fingerprint)
                putExtra("BUFFERED", buffered)
                putExtra("FLUSH_TIMEOUT", flushTimeout)
                putExtra("FILL_MODE", fillMode)
            }
            startService(intent)
        }
    }
}
