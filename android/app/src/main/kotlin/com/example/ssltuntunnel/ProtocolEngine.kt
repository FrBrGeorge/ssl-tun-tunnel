package com.example.ssltuntunnel

import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.net.ssl.SSLSocket
import android.util.Log

class ProtocolEngine(
    private val sslSocket: SSLSocket,
    private val buffered: Boolean,
    private val flushTimeoutMs: Long,
    private val fillMode: String,
    private val expectedFingerprint: String?,
    private val lowLatencyDscp: Set<Int> = setOf(0x48, 0xb8)
) {
    private val inputStream = sslSocket.inputStream
    private val outputStream = sslSocket.outputStream
    private val secureRandom = SecureRandom()
    private val JUNK_BIT = 0x8000
    private val TCP_MSS_FLUSH_THRESHOLD = 1450

    private val pktBuffer = mutableListOf<ByteArray>()
    private var bufferBytes = 0
    private var lastFlushTime = System.currentTimeMillis()

    fun verifyFingerprint(): Boolean {
        if (expectedFingerprint == null || expectedFingerprint.isEmpty()) return true
        
        try {
            val session = sslSocket.session
            val certs = session.peerCertificates
            if (certs.isEmpty()) return false
            
            val der = certs[0].encoded
            val md = MessageDigest.getInstance("SHA-256")
            val digest = md.digest(der)
            
            val hexFingerprint = digest.joinToString("") { "%02X".format(it) }
            val cleanExpected = expectedFingerprint.replace(":", "").replace("-", "").replace(" ", "").uppercase()
            
            // Basic HEX check. Z85 is harder in standard Java/Android without libs, 
            // so we'll stick to HEX for now or implement Z85 if needed.
            // But common fingerprints are HEX.
            
            if (hexFingerprint == cleanExpected) {
                Log.i("SslTun", "Fingerprint verified (HEX)")
                return true
            }
            
            Log.e("SslTun", "Fingerprint mismatch! Expected: $cleanExpected, Actual: $hexFingerprint")
            return false
        } catch (e: Exception) {
            Log.e("SslTun", "Error verifying fingerprint", e)
            return false
        }
    }

    fun sendPacket(packet: ByteArray) {
        if (!buffered) {
            writeFrame(packet, false)
            return
        }

        pktBuffer.add(packet)
        bufferBytes += packet.size
        
        val isLowLatency = checkLowLatency(packet)
        if (bufferBytes >= TCP_MSS_FLUSH_THRESHOLD || isLowLatency) {
            flushBuffer(isLowLatency)
        }
    }

    fun checkTimeout() {
        if (buffered && pktBuffer.isNotEmpty()) {
            if (System.currentTimeMillis() - lastFlushTime >= flushTimeoutMs) {
                flushBuffer(false)
            }
        }
    }

    private fun flushBuffer(isLowLatencyTriggered: Boolean) {
        if (pktBuffer.isEmpty()) return

        for (p in pktBuffer) {
            writeFrame(p, false, flush = false)
        }

        // Apply random fill
        val doFill = (fillMode == "all") || (fillMode == "throughput" && !isLowLatencyTriggered)
        if (doFill) {
            val wireBytes = bufferBytes + (pktBuffer.size * 2)
            val spaceLeft = TCP_MSS_FLUSH_THRESHOLD - wireBytes
            if (spaceLeft >= 2) {
                val junkLen = spaceLeft - 2
                val junkData = ByteArray(junkLen)
                secureRandom.nextBytes(junkData)
                writeFrame(junkData, true, flush = false)
            }
        }

        outputStream.flush()
        pktBuffer.clear()
        bufferBytes = 0
        lastFlushTime = System.currentTimeMillis()
    }

    private fun writeFrame(data: ByteArray, isJunk: Boolean, flush: Boolean = true) {
        var lenHeader = data.size
        if (isJunk) {
            lenHeader = lenHeader or JUNK_BIT
        }
        
        val header = ByteBuffer.allocate(2).putShort(lenHeader.toShort()).array()
        outputStream.write(header)
        outputStream.write(data)
        if (flush) outputStream.flush()
    }

    fun receiveFrame(): Pair<ByteArray?, Boolean> {
        val header = readExactly(2) ?: return null to false
        val valHeader = ByteBuffer.wrap(header).short.toInt() and 0xFFFF
        val isJunk = (valHeader and JUNK_BIT) != 0
        val length = valHeader and JUNK_BIT.inv()
        
        val payload = readExactly(length) ?: return null to false
        return payload to isJunk
    }

    private fun readExactly(size: Int): ByteArray? {
        val buffer = ByteArray(size)
        var offset = 0
        while (offset < size) {
            val read = inputStream.read(buffer, offset, size - offset)
            if (read == -1) return null
            offset += read
        }
        return buffer
    }

    private fun checkLowLatency(packet: ByteArray): Boolean {
        if (packet.size < 2) return false
        val version = (packet[0].toInt() shr 4) and 0x0F
        return when (version) {
            4 -> {
                val tos = packet[1].toInt() and 0xFF
                lowLatencyDscp.contains(tos)
            }
            6 -> {
                val tc = ((packet[0].toInt() and 0x0F) shl 4) or ((packet[1].toInt() and 0xF0) shr 4)
                lowLatencyDscp.contains(tc)
            }
            else -> false
        }
    }
}
