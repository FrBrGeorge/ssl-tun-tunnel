package com.example.ssltuntunnel

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import android.content.ClipboardManager
import android.content.ClipData
import java.text.SimpleDateFormat
import java.util.*

class MainActivity : AppCompatActivity() {

    private lateinit var txtLogs: TextView
    private lateinit var logScroll: ScrollView
    private val logBuilder = StringBuilder()

    private val logReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val level = intent?.getIntExtra("LEVEL", 1) ?: 1
            val message = intent?.getStringExtra("MESSAGE") ?: ""
            appendLog(level, message)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        txtLogs = findViewById(R.id.txtLogs)
        logScroll = findViewById(R.id.logScroll)
        val hostEdit = findViewById<EditText>(R.id.editHost)
        val portEdit = findViewById<EditText>(R.id.editPort)
        val tunIpEdit = findViewById<EditText>(R.id.editTunIp)
        val fingerprintEdit = findViewById<EditText>(R.id.editFingerprint)
        val bufferCheck = findViewById<CheckBox>(R.id.checkBuffered)
        val flushTimeoutEdit = findViewById<EditText>(R.id.editFlushTimeout)
        val fillGroup = findViewById<RadioGroup>(R.id.groupFill)
        val verbositySpinner = findViewById<Spinner>(R.id.spinnerVerbosity)
        
        val startBtn = findViewById<Button>(R.id.btnStart)
        val stopBtn = findViewById<Button>(R.id.btnStop)
        val clearLogsBtn = findViewById<Button>(R.id.btnClearLogs)
        val copyLogsBtn = findViewById<Button>(R.id.btnCopyLogs)

        loadConfig()

        startBtn.setOnClickListener {
            saveConfig()
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

        clearLogsBtn.setOnClickListener {
            logBuilder.clear()
            txtLogs.text = ""
        }

        copyLogsBtn.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("SslTun Logs", logBuilder.toString())
            clipboard.setPrimaryClip(clip)
            Toast.makeText(this, "Logs copied to clipboard", Toast.LENGTH_SHORT).show()
        }

        LocalBroadcastManager.getInstance(this).registerReceiver(
            logReceiver, IntentFilter(VpnTunnelService.LOG_EVENT)
        )
        
        appendLog(1, "App started. Ready to connect.")
    }

    private fun appendLog(level: Int, message: String) {
        val time = SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault()).format(Date())
        val levelTag = when(level) {
            0 -> "[ERROR]"
            1 -> "[INFO]"
            2 -> "[DEBUG]"
            3 -> "[FRAME]"
            4 -> "[PKT]"
            else -> "[?]"
        }
        val line = "$time $levelTag $message\n"
        logBuilder.append(line)
        runOnUiThread {
            txtLogs.append(line)
            logScroll.post {
                logScroll.fullScroll(ScrollView.FOCUS_DOWN)
            }
        }
    }

    private fun saveConfig() {
        val prefs = getSharedPreferences("config", Context.MODE_PRIVATE)
        prefs.edit().apply {
            putString("host", findViewById<EditText>(R.id.editHost).text.toString())
            putInt("port", findViewById<EditText>(R.id.editPort).text.toString().toIntOrNull() ?: 443)
            putString("tunIp", findViewById<EditText>(R.id.editTunIp).text.toString())
            putString("fingerprint", findViewById<EditText>(R.id.editFingerprint).text.toString())
            putBoolean("buffered", findViewById<CheckBox>(R.id.checkBuffered).isChecked)
            putLong("flushTimeout", findViewById<EditText>(R.id.editFlushTimeout).text.toString().toLongOrNull() ?: 1000L)
            putInt("fillModeId", findViewById<RadioGroup>(R.id.groupFill).checkedRadioButtonId)
            putInt("verbosity", findViewById<Spinner>(R.id.spinnerVerbosity).selectedItemPosition)
            apply()
        }
    }

    private fun loadConfig() {
        val prefs = getSharedPreferences("config", Context.MODE_PRIVATE)
        findViewById<EditText>(R.id.editHost).setText(prefs.getString("host", "127.0.0.1"))
        findViewById<EditText>(R.id.editPort).setText(prefs.getInt("port", 443).toString())
        findViewById<EditText>(R.id.editTunIp).setText(prefs.getString("tunIp", "10.0.1.2/24"))
        findViewById<EditText>(R.id.editFingerprint).setText(prefs.getString("fingerprint", ""))
        findViewById<CheckBox>(R.id.checkBuffered).isChecked = prefs.getBoolean("buffered", true)
        findViewById<EditText>(R.id.editFlushTimeout).setText(prefs.getLong("flushTimeout", 1000L).toString())
        val fillModeId = prefs.getInt("fillModeId", R.id.radioFillThroughput)
        if (fillModeId != -1) {
            findViewById<RadioGroup>(R.id.groupFill).check(fillModeId)
        }
        findViewById<Spinner>(R.id.spinnerVerbosity).setSelection(prefs.getInt("verbosity", 1))
    }

    override fun onDestroy() {
        LocalBroadcastManager.getInstance(this).unregisterReceiver(logReceiver)
        super.onDestroy()
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
            
            val verbosity = findViewById<Spinner>(R.id.spinnerVerbosity).selectedItemPosition

            val intent = Intent(this, VpnTunnelService::class.java).apply {
                putExtra("HOST", host)
                putExtra("PORT", port)
                putExtra("TUN_IP", tunIp)
                putExtra("FINGERPRINT", fingerprint)
                putExtra("BUFFERED", buffered)
                putExtra("FLUSH_TIMEOUT", flushTimeout)
                putExtra("FILL_MODE", fillMode)
                putExtra("VERBOSITY", verbosity)
            }
            startService(intent)
        }
    }
}
