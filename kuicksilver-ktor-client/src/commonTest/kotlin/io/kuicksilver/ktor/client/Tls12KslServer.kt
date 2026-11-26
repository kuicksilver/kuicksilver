// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.ktor.network.bindTcp
import io.kuicksilver.ktor.network.connectTcp
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlin.time.Duration.Companion.seconds

/**
 * A TLS server capped at TLS 1.2, on every platform: a raw `ksl` context (`KSL_OPT_MIN_VERSION` and `KSL_OPT_MAX_VERSION`
 * TLS 1.2, the RSA leaf of [RsaTestCert] for `server.test`, so `h2` is allowed over TLS 1.2, RFC 9113 section 9.2.2; session
 * tickets on) that terminates TLS and relays the plaintext to [backendPort], a plain connector with h2c, so the HTTP/2 or
 * HTTP/1.1 the client chose in ALPN reaches a real server. [stripFromServerHello] removes that extension from its
 * ServerHello on the wire (a server without it, as the client sees it). Each handshake's outcome goes to [outcomes].
 */
internal class Tls12KslServer private constructor(
    val port: Int,
    private val ctx: Long,
    private val selector: SelectorManager,
    private val listener: io.ktor.network.sockets.ServerSocket,
    val outcomes: Channel<Outcome>,
) {
    /** One handshake: failed with [failure], or the version (`0x0303`), the ALPN chosen, EMS and whether it resumed. */
    class Outcome(
        val failure: Throwable?,
        val version: Int,
        val alpn: String?,
        val ems: Boolean,
        val reused: Boolean,
    )

    suspend fun next(): Outcome = withTimeout(10.seconds) { outcomes.receive() }

    fun close() {
        listener.close()
        selector.close()
        Ksl.ctxFree(ctx)
    }

    companion object {
        /** Runs [block] with a server in [scope]; the server stops when [block] returns. */
        suspend fun <T> with(
            backendPort: Int,
            alpn: List<String> = listOf("h2", "http/1.1"),
            stripFromServerHello: Int? = null,
            block: suspend (Tls12KslServer) -> T,
        ): T =
            coroutineScope {
                val ctx = Ksl.ctxNew(KslConst.SERVER)
                val selector = SelectorManager(Dispatchers.IO)
                val listener = bindTcp(selector, "127.0.0.1", 0)
                val server =
                    Tls12KslServer((listener.localAddress as InetSocketAddress).port, ctx, selector, listener, Channel(Channel.UNLIMITED))
                try {
                    Ksl.ctxSetIdentity(ctx, listOf(RsaTestCert.leaf), RsaTestCert.key.copyOf())
                    Ksl.ctxSetAlpn(ctx, alpn.flatMap { listOf(it.length.toByte()) + it.encodeToByteArray().toList() }.toByteArray())
                    Ksl.ctxSetOption(ctx, KslConst.OPT_MIN_VERSION, KslConst.TLS1_2)
                    Ksl.ctxSetOption(ctx, KslConst.OPT_MAX_VERSION, KslConst.TLS1_2)
                    Ksl.ctxSetOption(ctx, KslConst.OPT_NUM_TICKETS, 1)
                    Ksl.ctxUseDefaultTicketKeys(ctx, 3600)
                    Ksl.ctxSetSessionContext(ctx, "tls12-test".encodeToByteArray())
                    Ksl.ctxFreeze(ctx)
                    val accepting = launch { server.accept(this, backendPort, stripFromServerHello) }
                    try {
                        block(server)
                    } finally {
                        accepting.cancel()
                    }
                } finally {
                    server.close()
                }
            }
    }

    private suspend fun accept(
        scope: CoroutineScope,
        backendPort: Int,
        strip: Int?,
    ) {
        while (true) {
            val s = listener.accept()
            scope.launch {
                s.use {
                    val ssl = Ksl.sslNew(ctx, KslConst.MODE_TCP)
                    try {
                        serve(ssl, s.openReadChannel(), s.openWriteChannel(autoFlush = false), backendPort, strip)
                    } finally {
                        Ksl.sslFree(ssl)
                    }
                }
            }
        }
    }

    private suspend fun serve(
        ssl: Long,
        r: ByteReadChannel,
        w: ByteWriteChannel,
        backendPort: Int,
        strip: Int?,
    ) {
        var first = strip
        try {
            while (true) {
                val rc =
                    try {
                        Ksl.drive(ssl)
                    } catch (e: KslException) {
                        flush(ssl, w, null)
                        throw e
                    }
                if (rc == KslConst.WANT_SNI) {
                    Ksl.sslSniResume(ssl, 0L, 0)
                    continue
                }
                if (flush(ssl, w, first)) first = null
                if (rc == KslConst.OK) break
                check(rc == KslConst.WANT_READ) { "drive answered $rc" }
                check(feed(ssl, r)) { "the client closed the connection during the handshake" }
            }
        } catch (e: Throwable) {
            outcomes.send(Outcome(e, 0, null, false, false))
            return
        }
        val version = Ksl.sslGet(ssl, KslConst.GET_VERSION).let { ((it[0].toInt() and 0xff) shl 8) or (it[1].toInt() and 0xff) }
        outcomes.send(
            Outcome(
                null,
                version,
                Ksl.sslGet(ssl, KslConst.GET_ALPN).takeIf { it.isNotEmpty() }?.decodeToString(),
                Ksl.sslGet(ssl, KslConst.GET_EMS)[0].toInt() == 1,
                Ksl.sslGet(ssl, KslConst.GET_SESSION_REUSED)[0].toInt() == 1,
            ),
        )
        val lock = Mutex()
        connectTcp(selector, InetSocketAddress("127.0.0.1", backendPort)).use { b ->
            val bIn = b.openReadChannel()
            val bOut = b.openWriteChannel(autoFlush = true)
            coroutineScope {
                // backend to client: plaintext into TLS records
                val down =
                    launch {
                        runCatching {
                            val buf = ByteArray(16 * 1024)
                            while (true) {
                                val n = bIn.readAvailable(buf, 0, buf.size)
                                if (n < 0) break
                                lock.withLock {
                                    var off = 0
                                    while (off < n) off += Ksl.tcpWrite(ssl, buf, off, n - off).coerceAtLeast(0)
                                    flush(ssl, w, null)
                                }
                            }
                            lock.withLock {
                                runCatching { Ksl.tcpShutdown(ssl) }
                                flush(ssl, w, null)
                            }
                        }
                    }
                // client to backend: TLS records into plaintext. What ksl holds already goes first: a request that came in the
                // same read as the client's Finished (an abbreviated TLS 1.2 handshake ends with it) is buffered there
                runCatching {
                    val buf = ByteArray(16 * 1024)
                    while (true) {
                        val out = lock.withLock { readPlain(ssl, buf).also { flush(ssl, w, null) } } ?: break
                        if (out.isNotEmpty()) bOut.writeFully(out)
                        if (!feed(ssl, r, lock)) break
                    }
                }
                runCatching { bOut.flushAndClose() }
                down.join()
            }
        }
    }

    /** The plaintext ksl has now; null at the client's close_notify. */
    private fun readPlain(
        ssl: Long,
        buf: ByteArray,
    ): ByteArray? {
        var out = ByteArray(0)
        while (true) {
            val n = Ksl.tcpRead(ssl, buf, 0, buf.size)
            when {
                n > 0 -> out += buf.copyOf(n)
                n == -KslConst.EOF -> return if (out.isEmpty()) null else out
                else -> return out
            }
        }
    }

    private suspend fun feed(
        ssl: Long,
        r: ByteReadChannel,
        lock: Mutex? = null,
    ): Boolean {
        val buf = ByteArray(16 * 1024)
        val n = r.readAvailable(buf, 0, buf.size)
        if (n < 0) return false

        suspend fun take() {
            var off = 0
            while (off < n) {
                val used = Ksl.tcpFeed(ssl, buf, off, n - off)
                check(used > 0) { "ksl took none of the input" }
                off += used
            }
        }
        if (lock == null) take() else lock.withLock { take() }
        return true
    }

    /** Sends what ksl has for the client, with the extension [strip] taken out of a ServerHello there; false when it had nothing. */
    private suspend fun flush(
        ssl: Long,
        w: ByteWriteChannel,
        strip: Int?,
    ): Boolean {
        var all = ByteArray(0)
        val buf = ByteArray(16 * 1024)
        while (true) {
            val n = Ksl.tcpDrain(ssl, buf, 0, buf.size)
            if (n <= 0) break
            all += buf.copyOf(n)
        }
        if (all.isEmpty()) return false
        if (strip != null) all = withoutServerHelloExtension(all, strip)
        w.writeFully(all)
        w.flush()
        return true
    }
}

/**
 * [flight] with the extension [type] taken out of the ServerHello that opens it (its record, handshake and extensions
 * lengths fixed up); unchanged when it does not start with a ServerHello carrying it.
 */
internal fun withoutServerHelloExtension(
    flight: ByteArray,
    type: Int,
): ByteArray {
    fun u8(i: Int) = flight[i].toInt() and 0xff

    fun u16(i: Int) = (u8(i) shl 8) or u8(i + 1)
    if (flight.size < 5 + 4 + 2 + 32 + 1 || u8(0) != 22 || u8(5) != 2) return flight
    var p = 5 + 4 + 2 + 32
    p += 1 + u8(p) // session_id
    p += 2 + 1 // cipher_suite, compression_method
    val extAt = p
    val end = p + 2 + u16(p)
    p += 2
    while (p + 4 <= end) {
        val t = u16(p)
        val len = u16(p + 2)
        if (t == type) {
            val cut = 4 + len
            val out = flight.copyOfRange(0, p) + flight.copyOfRange(p + cut, flight.size)
            val record = u16(3) - cut
            out[3] = (record shr 8).toByte()
            out[4] = record.toByte()
            val hs = ((u8(6) shl 16) or (u8(7) shl 8) or u8(8)) - cut
            out[6] = (hs shr 16).toByte()
            out[7] = (hs shr 8).toByte()
            out[8] = hs.toByte()
            val ext = u16(extAt) - cut
            out[extAt] = (ext shr 8).toByte()
            out[extAt + 1] = ext.toByte()
            return out
        }
        p += 4 + len
    }
    return flight
}
