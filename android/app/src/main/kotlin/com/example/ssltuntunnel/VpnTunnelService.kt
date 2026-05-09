package com.example.ssltuntunnel

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
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

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            stopVpn()
            return START_NOT_STICKY
        }

        val serverHost = intent?.getStringExtra("HOST") ?: ""
        val serverPort = intent?.getIntExtra("PORT", 443) ?: 443
        val tunIp = intent?.getStringExtra("TUN_IP") ?: "10.0.0.2"
        val fingerprint = intent?.getStringExtra("FINGERPRINT")
        val buffered = intent?.getBooleanExtra("BUFFERED", true) ?: true
        val flushTimeout = intent?.getLongExtra("FLUSH_TIMEOUT", 1000L) ?: 1000L
        val fillMode = intent?.getStringExtra("FILL_MODE") ?: "throughput"

        startVpn(serverHost, serverPort, tunIp, fingerprint, buffered, flushTimeout, fillMode)
        return START_STICKY
    }

    private fun startVpn(host: String, port: Int, tunIp: String, fingerprint: String?, 
                         buffered: Boolean, flushTimeout: Long, fillMode: String) {
        if (isRunning.get()) return
        isRunning.set(true)

        tunnelThread = Thread {
            try {
                runTunnel(host, port, tunIp, fingerprint, buffered, flushTimeout, fillMode)
            } catch (e: Exception) {
                Log.e("SslTun", "Tunnel error", e)
            } finally {
                stopVpn()
            }
        }.apply { start() }
    }

    private fun stopVpn() {
        isRunning.set(false)
        vpnInterface?.close()
        vpnInterface = null
        stopSelf()
    }

    private fun runTunnel(host: String, port: Int, tunIp: String, fingerprint: String?,
                          buffered: Boolean, flushTimeout: Long, fillMode: String) {
        
        // 1. Setup SSL
        val sslContext = SSLContext.getInstance("TLS")
        // No verification by default if no fingerprint, or full bypass if verification fails
        // In a real app, we should use a custom TrustManager that validates the fingerprint
        sslContext.init(null, arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(p0: Array<out X509Certificate>?, p1: String?) {}
            override fun checkServerTrusted(p0: Array<out X509Certificate>?, p1: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }), null)

        val socket = Socket(host, port)
        // Ensure socket is protected from the VPN itself to avoid loop
        if (!protect(socket)) {
            Log.e("SslTun", "Could not protect socket")
            socket.close()
            return
        }

        val sslSocket = sslContext.socketFactory.createSocket(socket, host, port, true) as javax.net.ssl.SSLSocket
        sslSocket.startHandshake()

        val engine = ProtocolEngine(sslSocket, buffered, flushTimeout, fillMode, fingerprint)
        if (fingerprint != null && !engine.verifyFingerprint()) {
            sslSocket.close()
            return
        }

        // 2. Setup VPN Interface
        val builder = Builder()
            .setMtu(1500)
            .addAddress(tunIp.split("/")[0], 24)
            .addRoute("0.0.0.0", 0)
            .setSession("SslTunTunnel")
            
        vpnInterface = builder.establish()
        val tunIn = FileInputStream(vpnInterface?.fileDescriptor)
        val tunOut = FileOutputStream(vpnInterface?.fileDescriptor)

        // 3. Bidirectional loops
        val rxThread = Thread {
            try {
                while (isRunning.get()) {
                    val (payload, isJunk) = engine.receiveFrame()
                    if (payload == null) break
                    if (!isJunk) {
                        tunOut.write(payload)
                    }
                }
            } catch (e: Exception) {
                Log.e("SslTun", "RX error", e)
            }
        }
        rxThread.start()

        val buf = ByteArray(2048)
        while (isRunning.get()) {
            // Non-blocking read or small timeout would be better, but standard Java 
            // FileInputStream on PFD is blocking. We'll use available() or just accept blocking.
            // For flush timeout, we need a way to pulse.
            
            if (tunIn.channel.position() < tunIn.channel.size() || true) {
                try {
                    // For non-root Android, we usually have to rely on blocking reads 
                    // or use a Selector with DatagramChannel if we could wrap the PFD.
                    // To keep it simple, we'll try a small read timeout if possible or just block.
                    val read = tunIn.read(buf)
                    if (read > 0) {
                        val packet = buf.copyOfRange(0, read)
                        engine.sendPacket(packet)
                    }
                } catch (e: Exception) {
                    if (isRunning.get()) Log.e("SslTun", "TX error", e)
                    break
                }
            }
            engine.checkTimeout()
        }
        rxThread.join(1000)
        sslSocket.close()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
