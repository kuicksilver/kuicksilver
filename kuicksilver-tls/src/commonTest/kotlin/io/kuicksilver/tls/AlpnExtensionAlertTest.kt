// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * The alert a TLS-over-TCP server answers a crafted ClientHello with, its ALPN extension rewritten: RFC 7301 section 3.1
 * ("ProtocolName protocol_name_list<2..2^16-1>", each "ProtocolName<1..2^8-1>") makes a malformed one `decode_error` (50),
 * whatever [TlsConfig.alpnFallback] or a list of `h3` alone would answer a well-formed one with (`no_application_protocol`, 120).
 */
class AlpnExtensionAlertTest {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private suspend fun readExactly(
        ch: ByteReadChannel,
        n: Int,
    ): ByteArray {
        val b = ByteArray(n)
        var o = 0
        while (o < n) {
            val r = ch.readAvailable(b, o, n - o)
            if (r < 0) error("EOF after $o bytes")
            o += r
        }
        return b
    }

    /** A Kuicksilver client's first record (its ClientHello, offering `x1`). */
    private fun clientHello(): ByteArray =
        runBlocking {
            val p = ChannelPair()
            val c =
                scope.async {
                    TlsConnection.client(
                        p.clientIn,
                        p.clientOut,
                        TcpFixtures.client { alpn = listOf("x1") },
                        EmptyCoroutineContext,
                        SessionCache.Default,
                    )
                }
            val h = withTimeout(10.seconds) { readExactly(p.serverIn, 5) }
            val body = withTimeout(10.seconds) { readExactly(p.serverIn, u16(h, 3)) }
            c.cancel()
            h + body
        }

    private fun u16(
        b: ByteArray,
        i: Int,
    ): Int = ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)

    private fun put16(
        b: ByteArray,
        i: Int,
        v: Int,
    ) {
        b[i] = (v shr 8).toByte()
        b[i + 1] = v.toByte()
    }

    /**
     * [record] with the data of its ALPN extension replaced by [data], or the extension removed for null; the record, handshake,
     * extensions and extension lengths follow.
     */
    private fun withAlpn(
        record: ByteArray,
        data: ByteArray?,
    ): ByteArray {
        var o = 5 + 4 + 2 + 32
        o += 1 + (record[o].toInt() and 0xff)
        o += 2 + u16(record, o)
        o += 1 + (record[o].toInt() and 0xff)
        val exts = o
        val end = o + 2 + u16(record, o)
        o += 2
        while (o < end) {
            val l = u16(record, o + 2)
            if (u16(record, o) == 0x10) {
                val replacement = if (data == null) ByteArray(0) else byteArrayOf((data.size shr 8).toByte(), data.size.toByte()) + data
                val out = record.copyOfRange(0, if (data == null) o else o + 2) + replacement + record.copyOfRange(o + 4 + l, record.size)
                val delta = out.size - record.size
                put16(out, 3, out.size - 5)
                val hs = out.size - 9
                out[6] = (hs shr 16).toByte()
                put16(out, 7, hs)
                put16(out, exts, u16(record, exts) + delta)
                return out
            }
            o += 4 + l
        }
        error("no ALPN extension")
    }

    /** The first record type and, for an alert, its description the server answers [record] with (22: it went on, handshake). */
    @OptIn(ExperimentalKuicksilverApi::class)
    private fun answer(
        record: ByteArray,
        server: TlsConfig,
    ): Pair<Int, Int> =
        runBlocking {
            val p = ChannelPair()
            val s = scope.async { runCatching { TlsConnection.server(p.serverIn, p.serverOut, server) } }
            p.clientOut.writeFully(record)
            p.clientOut.flush()
            val h = withTimeout(10.seconds) { readExactly(p.clientIn, 5) }
            val body = withTimeout(10.seconds) { readExactly(p.clientIn, u16(h, 3)) }
            s.cancel()
            (h[0].toInt() and 0xff) to (body[1].toInt() and 0xff)
        }

    @OptIn(ExperimentalKuicksilverApi::class)
    private fun server(
        fallback: String?,
        alpn: List<String> = listOf("x1"),
    ): TlsConfig =
        TcpFixtures.server {
            this.alpn = alpn
            expert { alpnFallback = fallback }
        }

    private val malformed =
        listOf(
            ByteArray(0) to "an empty extension",
            byteArrayOf(0) to "one byte",
            byteArrayOf(0, 0) to "an empty list",
            byteArrayOf(0, 1, 0) to "an empty name",
            byteArrayOf(0, 5, 2, 'x'.code.toByte(), '1'.code.toByte()) to "a list length past the end",
            byteArrayOf(0, 3, 5, 'x'.code.toByte(), '1'.code.toByte()) to "a name past the end",
            byteArrayOf(0, 4, 2, 'x'.code.toByte(), '1'.code.toByte()) to "a list length short of the end",
        )

    /** The reviewer's case: the extension's own bytes overwritten with 0xff, its length kept. */
    @Test fun negative_aMalformedAlpnExtensionIsDecodeErrorWithOrWithoutTheFallback() {
        val ch = clientHello()
        val bytesOverwritten = withAlpn(ch, ByteArray(5) { 0xff.toByte() })
        for (fallback in listOf(null, "fb")) {
            assertEquals(21 to 50, answer(bytesOverwritten, server(fallback)), "0xff bytes, fallback $fallback")
            for ((data, what) in malformed) {
                assertEquals(21 to 50, answer(withAlpn(ch, data), server(fallback)), "$what, fallback $fallback")
            }
        }
        for ((data, what) in malformed) {
            assertEquals(21 to 50, answer(withAlpn(ch, data), server(null, alpn = listOf("h3"))), "$what, a list of h3 alone")
        }
    }

    /** The controls: no extension, a well-formed one without overlap, and a well-formed one the server serves. */
    @Test fun aWellFormedOrAbsentAlpnExtensionGetsThePolicysAnswer() {
        val ch = clientHello()
        val zz = byteArrayOf(0, 3, 2, 'z'.code.toByte(), 'z'.code.toByte())
        assertEquals(21 to 120, answer(withAlpn(ch, null), server("fb")), "no extension, fallback not offered")
        assertEquals(22, answer(withAlpn(ch, null), server(null)).first, "no extension, no fallback: the handshake goes on")
        assertEquals(22, answer(withAlpn(ch, null), server("fb", alpn = listOf("x1", "fb"))).first, "no extension, fallback offered")
        assertEquals(21 to 120, answer(withAlpn(ch, zz), server("fb")), "no overlap")
        assertEquals(22, answer(ch, server("fb")).first, "x1 offered and served")
        assertEquals(21 to 120, answer(ch, server(null, alpn = listOf("h3"))), "a list of h3 alone serves nothing over TCP")
        assertEquals(21 to 120, answer(withAlpn(ch, null), server(null, alpn = listOf("h3"))), "h3 alone, no extension")
    }
}
