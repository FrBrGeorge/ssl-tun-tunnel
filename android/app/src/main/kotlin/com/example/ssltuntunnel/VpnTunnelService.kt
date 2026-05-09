package com.example.ssltuntunnel

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.Socket
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicBoolean

class VpnTunnelService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private val isRunning = AtomicBoolean(false)
    private var tunnelThread: Thread? = null

    companion object {
        const val LOG_EVENT = "com.example.ssltuntunnel.LOG_EVENT"
        private var instance: VpnTunnelService? = null

        fun broadcastLog(level: Int, message: String) {
            instance?.let {
                val intent = Intent(LOG_EVENT).apply {
                    putExtra("LEVEL", level)
                    putExtra("MESSAGE", message)
                }
                LocalBroadcastManager.getInstance(it).sendBroadcast(intent)
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            stopVpn()
            return START_NOT_STICKY
        }

        val serverHost = intent?.getStringExtra("HOST") ?: ""
        val serverPort = intent?.getIntExtra("PORT", 443) ?: 443
        val tunIp = intent?.getStringExtra("TUN_IP") ?: "10.0.0.2/24"
        val fingerprint = intent?.getStringExtra("FINGERPRINT")
        val buffered = intent?.getBooleanExtra("BUFFERED", true) ?: true
        val flushTimeout = intent?.getLongExtra("FLUSH_TIMEOUT", 1000L) ?: 1000L
        val fillMode = intent?.getStringExtra("FILL_MODE") ?: "throughput"
        val verbosity = intent?.getIntExtra("VERBOSITY", 1) ?: 1

        startVpn(serverHost, serverPort, tunIp, fingerprint, buffered, flushTimeout, fillMode, verbosity)
        return START_STICKY
    }

    private fun startVpn(host: String, port: Int, tunIp: String, fingerprint: String?, 
                         buffered: Boolean, flushTimeout: Long, fillMode: String, verbosity: Int) {
        if (isRunning.get()) return
        isRunning.set(true)

        broadcastLog(1, "Starting VPN service...")
        tunnelThread = Thread {
            var retryCount = 0
            while (isRunning.get()) {
                try {
                    runTunnel(host, port, tunIp, fingerprint, buffered, flushTimeout, fillMode, verbosity)
                    // If runTunnel returns normally while isRunning is true, it means it finished its loop (maybe EOF)
                } catch (e: Exception) {
                    Log.e("SslTun", "Tunnel error", e)
                    broadcastLog(0, "Tunnel error: ${e.message}")
                }
                
                if (!isRunning.get()) break
                
                retryCount++
                val sleepTime = minOf(30000L, 1000L * retryCount)
                broadcastLog(1, "Reconnecting in ${sleepTime/1000}s... (Attempt $retryCount)")
                try {
                    Thread.sleep(sleepTime)
                } catch (ie: InterruptedException) {
                    break
                }
            }
            stopVpn()
        }.apply { start() }
    }

    private fun stopVpn() {
        if (isRunning.get()) {
            broadcastLog(1, "Stopping VPN service...")
            isRunning.set(false)
        }
        vpnInterface?.close()
        vpnInterface = null
        stopSelf()
    }

    private fun runTunnel(host: String, port: Int, tunIp: String, fingerprint: String?,
                           buffered: Boolean, flushTimeout: Long, fillMode: String, verbosity: Int) {
        
        broadcastLog(1, "Connecting to $host:$port...")
        // 1. Setup SSL
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(p0: Array<out X509Certificate>?, p1: String?) {}
            override fun checkServerTrusted(p0: Array<out X509Certificate>?, p1: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }), null)

        val socket = Socket(host, port)
        if (!protect(socket)) {
            broadcastLog(0, "Could not protect socket")
            socket.close()
            return
        }

        val sslSocket = sslContext.socketFactory.createSocket(socket, host, port, true) as javax.net.ssl.SSLSocket
        sslSocket.startHandshake()
        broadcastLog(1, "SSL Handshake completed")

        val engine = ProtocolEngine(sslSocket, buffered, flushTimeout, fillMode, fingerprint, verbosity)
        if (fingerprint != null && !engine.verifyFingerprint()) {
            broadcastLog(0, "Fingerprint verification failed")
            sslSocket.close()
            return
        }

        // 2. Setup VPN Interface
        vpnInterface?.close()
        val ipParts = tunIp.split("/")
        val ip = ipParts[0]
        val prefix = if (ipParts.size > 1) ipParts[1].toInt() else 24
        
        val builder = Builder()
            .setMtu(1500)
            .addAddress(ip, prefix)
            .addRoute("0.0.0.0", 0)
            .setSession("SslTunTunnel")
            
        vpnInterface = builder.establish()
        if (vpnInterface == null) {
            broadcastLog(0, "Failed to establish VPN interface")
            return
        }
        broadcastLog(1, "VPN interface established: $tunIp")

        val tunIn = FileInputStream(vpnInterface?.fileDescriptor)
        val tunOut = FileOutputStream(vpnInterface?.fileDescriptor)

        // 3. Bidirectional loops
        // Receiver Thread (SSL -> TUN)
        val rxThread = Thread {
            try {
                broadcastLog(2, "RX Thread started")
                while (isRunning.get()) {
                    val (payload, isJunk) = engine.receiveFrame()
                    if (payload == null) break
                    if (!isJunk) {
                        tunOut.write(payload)
                        if (verbosity >= 4) broadcastLog(4, "SSL -> TUN: ${payload.size} bytes")
                    }
                }
            } catch (e: Exception) {
                if (isRunning.get()) {
                    Log.e("SslTun", "RX error", e)
                    broadcastLog(1, "RX error: ${e.message}")
                }
            }
        }.apply { name = "SslTunRX"; start() }

        // Timer Thread for flushes
        val timerThread = Thread {
            try {
                while (isRunning.get()) {
                    engine.checkTimeout()
                    Thread.sleep(flushTimeout / 2)
                }
            } catch (e: Exception) {
                // ignore
            }
        }.apply { name = "SslTunTimer"; start() }

        // Transmitter Loop (TUN -> SSL)
        val buf = ByteArray(2048)
        broadcastLog(2, "TX Loop started")
        try {
            while (isRunning.get()) {
                val read = tunIn.read(buf)
                if (read > 0) {
                    val packet = buf.copyOfRange(0, read)
                    engine.sendPacket(packet)
                    if (verbosity >= 4) broadcastLog(4, "TUN -> SSL: $read bytes")
                } else if (read == -1) {
                    break
                }
            }
        } catch (e: Exception) {
            if (isRunning.get()) {
                Log.e("SslTun", "TX error", e)
                broadcastLog(1, "TX error: ${e.message}")
            }
        } finally {
            rxThread.join(200)
            timerThread.interrupt()
            try { 
                sslSocket.close() 
                socket.close()
            } catch (e: Exception) {}
            broadcastLog(1, "Tunnel session ended")
        }
    }

    override fun onDestroy() {
        stopVpn()
        instance = null
        super.onDestroy()
    }
}
