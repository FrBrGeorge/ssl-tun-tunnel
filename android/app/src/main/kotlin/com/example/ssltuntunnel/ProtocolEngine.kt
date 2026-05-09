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
    private val verbosity: Int = 1,
    private val lowLatencyDscp: Set<Int> = setOf(0x48, 0xb8)
) {
    private val inputStream: InputStream = sslSocket.inputStream
    private val outputStream: OutputStream = sslSocket.outputStream
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
            
            if (hexFingerprint == cleanExpected) {
                log(1, "Fingerprint verified (HEX)")
                return true
            }
            
            // Try Z85 if expected is long enough
            if (cleanExpected.length == 40) {
                try {
                    val expectedRaw = Z85.decode(expectedFingerprint)
                    if (expectedRaw.contentEquals(digest)) {
                        log(1, "Fingerprint verified (Z85)")
                        return true
                    }
                } catch (e: Exception) {
                    log(2, "Z85 decode failed: ${e.message}")
                }
            }
            
            log(0, "Fingerprint mismatch! Actual HEX: $hexFingerprint")
            return false
        } catch (e: Exception) {
            log(0, "Error verifying fingerprint: ${e.message}")
            return false
        }
    }

    @Synchronized
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

    @Synchronized
    fun checkTimeout() {
        if (buffered && pktBuffer.isNotEmpty()) {
            if (System.currentTimeMillis() - lastFlushTime >= flushTimeoutMs) {
                log(2, "Flush timeout triggered")
                flushBuffer(false)
            }
        }
    }

    @Synchronized
    private fun flushBuffer(isLowLatencyTriggered: Boolean) {
        if (pktBuffer.isEmpty()) return

        log(2, "Flushing buffer: ${pktBuffer.size} packets, $bufferBytes bytes")

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
                log(3, "Added $junkLen bytes of junk")
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
        
        if (verbosity >= 3) {
            val type = if (isJunk) "JUNK" else "DATA"
            log(3, "Sent frame: $type, size=${data.size}")
        }
    }

    fun receiveFrame(): Pair<ByteArray?, Boolean> {
        val header = readExactly(2) ?: return null to false
        val valHeader = ByteBuffer.wrap(header).short.toInt() and 0xFFFF
        val isJunk = (valHeader and JUNK_BIT) != 0
        val length = valHeader and JUNK_BIT.inv()
        
        val payload = readExactly(length) ?: return null to false
        
        if (verbosity >= 3) {
            val type = if (isJunk) "JUNK" else "DATA"
            log(3, "Received frame: $type, size=$length")
        }
        
        return payload to isJunk
    }

    private fun readExactly(size: Int): ByteArray? {
        val buffer = ByteArray(size)
        var offset = 0
        while (offset < size) {
            try {
                val read = inputStream.read(buffer, offset, size - offset)
                if (read == -1) return null
                offset += read
            } catch (e: Exception) {
                log(1, "Read error: ${e.message}")
                return null
            }
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

    private fun log(level: Int, msg: String) {
        if (verbosity >= level) {
            Log.d("SslTun", msg)
            VpnTunnelService.broadcastLog(level, msg)
        }
    }

    object Z85 {
        private val decoderTable = IntArray(256) { -1 }
        private const val encoderString = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"

        init {
            for (i in encoderString.indices) {
                decoderTable[encoderString[i].toInt()] = i
            }
        }

        fun decode(input: String): ByteArray {
            val cleanInput = input.trim()
            if (cleanInput.length % 5 != 0) throw IllegalArgumentException("Z85 length must be multiple of 5")
            val length = cleanInput.length / 5 * 4
            val result = ByteArray(length)
            var byteIdx = 0
            var charIdx = 0
            while (charIdx < cleanInput.length) {
                var value = 0L
                for (i in 0..4) {
                    val c = cleanInput[charIdx++].toInt()
                    if (c >= 256 || decoderTable[c] == -1) throw IllegalArgumentException("Invalid Z85 char")
                    value = value * 85 + decoderTable[c]
                }
                for (i in 0..3) {
                    result[byteIdx + 3 - i] = (value shr (i * 8)).toByte()
                }
                byteIdx += 4
            }
            return result
        }
    }
}
