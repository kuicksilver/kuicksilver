// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeFully
import io.kuicksilver.ktor.network.TlsSocket
import io.kuicksilver.ktor.network.connectTcp
import io.kuicksilver.ktor.network.tls
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withTimeout
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** One HTTP/2 frame as the raw client read it (RFC 9113 section 4.1). */
internal class RawFrame(
    val type: Int,
    val flags: Int,
    val stream: Int,
    val payload: ByteArray,
) {
    val endStream: Boolean get() = flags and 0x1 != 0

    /** RST_STREAM and GOAWAY: the error code. */
    val errorCode: Long
        get() =
            when (type) {
                RST_STREAM -> u32(payload, 0)
                GOAWAY -> u32(payload, 4)
                else -> error("no error code in frame type $type")
            }

    /** GOAWAY: the last stream identifier. */
    val lastStreamId: Int get() = (u32(payload, 0) and 0x7fff_ffff).toInt()

    /** SETTINGS: identifier to value. */
    val settings: Map<Int, Long>
        get() = (0 until payload.size / 6).associate { i -> u16(payload, i * 6) to u32(payload, i * 6 + 2) }

    override fun toString(): String = "RawFrame(type=$type, flags=$flags, stream=$stream, ${payload.size} bytes)"

    companion object {
        const val DATA = 0
        const val HEADERS = 1
        const val RST_STREAM = 3
        const val SETTINGS = 4
        const val PING = 6
        const val GOAWAY = 7
        const val WINDOW_UPDATE = 8
        const val CONTINUATION = 9

        private fun u16(
            b: ByteArray,
            at: Int,
        ): Int = ((b[at].toInt() and 0xff) shl 8) or (b[at + 1].toInt() and 0xff)

        private fun u32(
            b: ByteArray,
            at: Int,
        ): Long =
            ((b[at].toLong() and 0xff) shl 24) or ((b[at + 1].toLong() and 0xff) shl 16) or ((b[at + 2].toLong() and 0xff) shl 8) or
                (b[at + 3].toLong() and 0xff)
    }
}

/**
 * An HTTP/2 client written by hand over TLS with ALPN `h2`, for requests no real client sends (RFC 9113 sections 8.2, 8.3):
 * it writes any frame, and field blocks as HPACK literals without indexing (RFC 7541 section 6.2.2, no Huffman), so its
 * encoder state never matters. It reads the server's frames one at a time and acknowledges the server's SETTINGS once
 * its own preface went out.
 */
internal class RawH2Client private constructor(
    private val selector: SelectorManager,
    private val socket: Socket,
    private val input: ByteReadChannel,
    private val output: ByteWriteChannel,
    /** The ALPN protocol the handshake agreed on. */
    val alpn: String?,
) : AutoCloseable {
    /** The server's first SETTINGS (its preface), once [readFrame] saw it. */
    var serverSettings: Map<Int, Long>? = null
        private set

    suspend fun write(bytes: ByteArray) {
        output.writeFully(bytes)
        output.flush()
    }

    private var prefaceSent = false

    /** The client connection preface (section 3.4): the fixed octets and an empty SETTINGS frame. */
    suspend fun preface() {
        write(PREFACE + frame(RawFrame.SETTINGS, 0, 0))
        prefaceSent = true
    }

    suspend fun headers(
        stream: Int,
        fields: List<Pair<String, String>>,
        endStream: Boolean = true,
        endHeaders: Boolean = true,
    ) = write(frame(RawFrame.HEADERS, (if (endStream) 0x1 else 0) or (if (endHeaders) 0x4 else 0), stream, block(fields)))

    suspend fun data(
        stream: Int,
        bytes: ByteArray,
        endStream: Boolean,
    ) = write(frame(RawFrame.DATA, if (endStream) 0x1 else 0, stream, bytes))

    suspend fun rstStream(
        stream: Int,
        code: Int,
    ) = write(frame(RawFrame.RST_STREAM, 0, stream, int32(code)))

    /** The next frame, or null once the server closed the connection; SETTINGS from the server are acknowledged. */
    suspend fun readFrame(): RawFrame? {
        val head =
            try {
                input.readByteArray(9)
            } catch (_: Throwable) {
                return null
            }
        val len = ((head[0].toInt() and 0xff) shl 16) or ((head[1].toInt() and 0xff) shl 8) or (head[2].toInt() and 0xff)
        val payload =
            try {
                input.readByteArray(len)
            } catch (_: Throwable) {
                return null
            }
        val f =
            RawFrame(
                head[3].toInt() and 0xff,
                head[4].toInt() and 0xff,
                ((head[5].toInt() and 0x7f) shl 24) or ((head[6].toInt() and 0xff) shl 16) or ((head[7].toInt() and 0xff) shl 8) or
                    (head[8].toInt() and 0xff),
                payload,
            )
        if (f.type == RawFrame.SETTINGS && f.flags and 0x1 == 0) {
            if (serverSettings == null) serverSettings = f.settings
            if (prefaceSent) write(frame(RawFrame.SETTINGS, 0x1, 0)) // never ahead of our own preface
        }
        return f
    }

    /** Reads until a frame matches [predicate] (null: the connection ended first), within [within]. */
    suspend fun await(
        within: Duration = 10.seconds,
        predicate: (RawFrame) -> Boolean,
    ): RawFrame? =
        withTimeout(within) {
            while (true) {
                val f = readFrame() ?: return@withTimeout null
                if (predicate(f)) return@withTimeout f
            }
            @Suppress("UNREACHABLE_CODE")
            null
        }

    /** Reads to the end of the connection within [within] and returns everything read. */
    suspend fun readToEnd(within: Duration = 10.seconds): List<RawFrame> =
        withTimeout(within) {
            val out = ArrayList<RawFrame>()
            while (true) out += readFrame() ?: break
            out
        }

    override fun close() {
        socket.close()
        selector.close()
    }

    companion object {
        val PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".encodeToByteArray()

        /** Connects to 127.0.0.1:[port] over TLS offering [alpn]. */
        suspend fun connect(
            port: Int,
            alpn: List<String> = listOf("h2"),
        ): RawH2Client {
            val selector = SelectorManager(Dispatchers.Default)
            try {
                val tcp = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                val t: TlsSocket = tcp.tls(ServerFixtures.clientTls(alpn = alpn))
                return RawH2Client(selector, t, t.openReadChannel(), t.openWriteChannel(), t.negotiatedAlpn)
            } catch (e: Throwable) {
                selector.close()
                throw e
            }
        }

        fun frame(
            type: Int,
            flags: Int,
            stream: Int,
            payload: ByteArray = ByteArray(0),
        ): ByteArray =
            byteArrayOf(
                (payload.size shr 16).toByte(),
                (payload.size shr 8).toByte(),
                payload.size.toByte(),
                type.toByte(),
                flags.toByte(),
                (stream ushr 24).toByte(),
                (stream shr 16).toByte(),
                (stream shr 8).toByte(),
                stream.toByte(),
            ) + payload

        private fun int32(v: Int): ByteArray = byteArrayOf((v ushr 24).toByte(), (v shr 16).toByte(), (v shr 8).toByte(), v.toByte())

        /** A field block of literals without indexing, new names (RFC 7541 section 6.2.2), no Huffman coding. */
        fun block(fields: List<Pair<String, String>>): ByteArray {
            val out = ArrayList<Byte>()
            for ((n, v) in fields) {
                out += 0
                string(out, n)
                string(out, v)
            }
            return out.toByteArray()
        }

        /** An RFC 7541 string literal: a 7-bit prefixed length (section 5.1) with H = 0, then the octets. */
        private fun string(
            out: MutableList<Byte>,
            s: String,
        ) {
            val b = s.encodeToByteArray()
            var n = b.size
            if (n < 127) {
                out += n.toByte()
            } else {
                out += 127
                n -= 127
                while (n >= 128) {
                    out += ((n and 0x7f) or 0x80).toByte()
                    n = n ushr 7
                }
                out += n.toByte()
            }
            for (x in b) out += x
        }

        /** The request control data of a GET of [path] (section 8.3.1). */
        fun get(path: String = "/"): List<Pair<String, String>> =
            listOf(":method" to "GET", ":scheme" to "https", ":authority" to "server.test", ":path" to path)
    }
}
