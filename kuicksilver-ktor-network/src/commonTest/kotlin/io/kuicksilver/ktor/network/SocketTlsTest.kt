// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.SocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.ReaderJob
import io.ktor.utils.io.WriterJob
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readUTF8Line
import io.ktor.utils.io.reader
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.ktor.utils.io.writer
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.SessionCache
import io.kuicksilver.tls.TestCerts
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsConnection
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyReason
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.CoroutineContext
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

internal val testCa = Certificate(TestCerts.testCa)

internal fun clientConfig(block: TlsConfig.Builder.() -> Unit = {}): TlsConfig =
    tlsConfig(TlsRole.Client) {
        serverName = "server.test"
        alpn =
            listOf("http/1.1")
        trust = TrustConfig.AnchoredCa(listOf(testCa))
        block()
    }

internal fun serverConfig(block: TlsConfig.Builder.() -> Unit = {}): TlsConfig =
    tlsConfig(TlsRole.Server) {
        alpn = listOf("http/1.1")
        identity =
            TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
        block()
    }

internal suspend fun ByteReadChannel.readExactly(n: Int): ByteArray {
    val out = ByteArray(n)
    var off = 0
    while (off <
        n
    ) {
        val r = readAvailable(out, off, n - off)
        if (r <
            0
        ) {
            throw closedCause ?: IllegalStateException("EOF after $off of $n")
        }
        off += r
    }
    return out
}

/** A loopback TLS server for the tests: accepts one connection and runs [handler] on it. */
internal class LoopbackServer private constructor(
    private val selector: SelectorManager,
    private val server: ServerSocket,
    config: TlsConfig,
    handler: suspend (TlsSocket) -> Unit,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val port: Int get() = (server.localAddress as InetSocketAddress).port
    val job =
        scope.async {
            val raw = server.accept()
            val tls = raw.tlsServer(config)
            try {
                handler(tls)
            } catch (
                t: Throwable,
            ) {
                println("SERVER HANDLER FAILED: $t / ${t.cause}")
                throw t
            } finally {
                tls.close()
            }
        }

    suspend fun client(
        cfg: TlsConfig = clientConfig(),
        reference: String = "127.0.0.1",
    ): TlsSocket = aSocket(selector).tcp().connect(reference, port).tls(cfg)

    fun close() {
        job.cancel()
        server.close()
        selector.close()
    }

    companion object {
        suspend fun start(
            config: TlsConfig = serverConfig(),
            handler: suspend (TlsSocket) -> Unit,
        ): LoopbackServer {
            val selector = SelectorManager(Dispatchers.Default)
            val server = aSocket(selector).tcp().bind("127.0.0.1", 0)
            return LoopbackServer(selector, server, config, handler)
        }
    }
}

class SocketTlsTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        runBlocking { SessionCache.Default.clear() }
    }

    @Test fun secondConnectionResumesOverSockets(): Unit =
        runBlocking {
            repeat(2) { round ->
                val srv =
                    LoopbackServer.start { s ->
                        val r = s.openReadChannel()
                        val w = s.openWriteChannel(autoFlush = true)
                        val d = r.readExactly(5000)
                        w.writeFully(d, 0, d.size)
                        w.flush()
                    }
                try {
                    val c = withTimeout(20.seconds) { srv.client() }
                    try {
                        val data = ByteArray(5000) { it.toByte() }
                        val w = c.openWriteChannel(autoFlush = true)
                        val r = c.openReadChannel()
                        w.writeFully(data, 0, data.size)
                        w.flush()
                        assertContentEquals(data, withTimeout(10.seconds) { r.readExactly(data.size) }, "round $round")
                    } finally {
                        c.close()
                    }
                    withTimeout(10.seconds) { srv.job.await() }
                } finally {
                    srv.close()
                }
            }
            // the ticket preceded the echo, so it is cached by the time the echo was read
            assertEquals(1, SessionCache.Default.size())
        }

    @Test fun clientServerEchoOverRealSockets(): Unit =
        runBlocking {
            val srv =
                LoopbackServer.start { s ->
                    val r = s.openReadChannel()
                    val w = s.openWriteChannel(autoFlush = true)
                    val data =
                        r.readExactly(1 shl 20)
                    ; w.writeFully(data, 0, data.size)
                    w.flush()
                }
            try {
                val c = withTimeout(20.seconds) { srv.client() }
                try {
                    assertEquals("http/1.1", c.negotiatedAlpn)
                    assertEquals(Certificate(TestCerts.server), c.peerCertificates[0])
                    val data = ByteArray(1 shl 20) { (it * 13).toByte() }
                    val w = c.openWriteChannel(autoFlush = true)
                    val r = c.openReadChannel()
                    w.writeFully(data, 0, data.size)
                    w.flush()
                    assertContentEquals(data, withTimeout(30.seconds) { r.readExactly(data.size) })
                } finally {
                    c.close()
                }
                withTimeout(10.seconds) { srv.job.await() }
            } finally {
                srv.close()
            }
        }

    @Test fun pinnedConnectAcceptsCorrectPinAndRejectsWrongPin(): Unit =
        runBlocking {
            val good = TrustConfig.Pinned(setOf(Certificate(TestCerts.server).spkiSha256), base = TrustConfig.AnchoredCa(listOf(testCa)))
            val srv = LoopbackServer.start { s -> s.openReadChannel().readExactly(1) }
            try {
                val c = withTimeout(20.seconds) { srv.client(clientConfig { trust = good }) }
                c.openWriteChannel(autoFlush = true).writeFully(byteArrayOf(1), 0, 1)
                c.close()
                withTimeout(10.seconds) { srv.job.await() }
            } finally {
                srv.close()
            }
            val bad = TrustConfig.Pinned(setOf(Certificate(TestCerts.proxy).spkiSha256), base = TrustConfig.AnchoredCa(listOf(testCa)))
            val srv2 = LoopbackServer.start { }
            try {
                val e = assertFailsWith<TlsException.Verify> { withTimeout(20.seconds) { srv2.client(clientConfig { trust = bad }) } }
                assertIs<VerifyReason.PinMismatch>(e.reason)
            } finally {
                srv2.close()
            }
        }

    @Test fun closePropagatesShutdown(): Unit =
        runBlocking {
            val srv =
                LoopbackServer.start { s ->
                    val r = s.openReadChannel()
                    val tail = ByteArray(4)
                    assertEquals(-1, withTimeout(10.seconds) { r.readAvailable(tail, 0, 4) }, "clean EOF after the client's close_notify")
                }
            try {
                val c = withTimeout(20.seconds) { srv.client() }
                c.tls.shutdown()
                c.close()
                withTimeout(10.seconds) { srv.job.await() }
            } finally {
                srv.close()
            }
        }

    /**
     * The server's application never reads: once its buffers are full, the client's flush, close_notify and the raw socket's
     * last write wait for good. close() must still release the raw socket within its bound instead of holding it, its
     * coroutines and the native session until the peer goes away. Over [MemorySocket] the buffers are known: the server takes
     * about 2 MiB (its transport and its plaintext channel), the client about 3 MiB more (the socket's write channel, the TLS
     * output and the raw write channel), so a 3.5 MiB write returns and leaves the rest stuck on the client.
     */
    @Test fun negative_closeIsBoundedWhenThePeerStopsReading(): Unit =
        runBlocking {
            val raw = MemorySocket()
            val server = async(Dispatchers.Default) { TlsConnection.server(raw.serverIn, raw.serverOut, serverConfig()) }
            val c = withTimeout(20.seconds) { raw.tls(clientConfig()) }
            val s = withTimeout(20.seconds) { server.await() }
            try {
                c.closeTimeout = 300.milliseconds
                val out = c.openWriteChannel(autoFlush = true)
                val data = ByteArray(7 shl 19)
                withTimeout(20.seconds) { out.writeFully(data, 0, data.size) }
                c.close()
                val closed = withTimeoutOrNull(20.seconds) { c.socketContext.join() }
                assertTrue(closed != null, "the raw socket is released within the close bound although the peer stopped reading")
            } finally {
                s.close()
            }
        }

    @Test fun serverRefusesWrongClientConfig(): Unit =
        runBlocking {
            val selector = SelectorManager(Dispatchers.Default)
            try {
                val server = aSocket(selector).tcp().bind("127.0.0.1", 0)
                val raw = aSocket(selector).tcp().connect("127.0.0.1", (server.localAddress as InetSocketAddress).port)
                assertFailsWith<TlsException.Config> { raw.tls(serverConfig()) }
                server.close()
            } finally {
                selector.close()
            }
        }
}

class HttpsGetTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** The TLS layer's acceptance check: HTTPS over our TLS on this platform with a pinned SPKI. */
    @Test fun httpsGetAgainstLocalServerWithPin(): Unit =
        runBlocking {
            val body = "ok"
            val srv =
                LoopbackServer.start { s ->
                    val r = s.openReadChannel()
                    val w = s.openWriteChannel(autoFlush = true)
                    val requestLine = r.readUTF8Line()
                    while (true) {
                        val l = r.readUTF8Line() ?: break
                        if (l.isEmpty()) break
                    }
                    assertEquals("GET /health HTTP/1.1", requestLine)
                    w.writeStringUtf8(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n$body",
                    )
                    w.flush()
                }
            try {
                val pinned =
                    clientConfig {
                        trust =
                            TrustConfig.Pinned(
                                setOf(Certificate(TestCerts.server).spkiSha256),
                                base = TrustConfig.AnchoredCa(listOf(testCa)),
                            )
                    }
                val c = withTimeout(20.seconds) { srv.client(pinned) }
                try {
                    val w = c.openWriteChannel(autoFlush = true)
                    val r = c.openReadChannel()
                    w.writeStringUtf8("GET /health HTTP/1.1\r\nHost: server.test\r\n\r\n")
                    w.flush()
                    val status = withTimeout(10.seconds) { r.readUTF8Line() }
                    assertEquals("HTTP/1.1 200 OK", status)
                    var contentLength = 0
                    while (true) {
                        val l =
                            r.readUTF8Line() ?: break
                        if (l.isEmpty()) break
                        if (l.startsWith("Content-Length:")) {
                            contentLength =
                                l.substringAfter(':').trim().toInt()
                        }
                    }
                    assertEquals(body, withTimeout(10.seconds) { r.readExactly(contentLength) }.decodeToString())
                } finally {
                    c.close()
                }
                withTimeout(10.seconds) { srv.job.await() }
            } finally {
                srv.close()
            }
        }
}

class WssTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** RFC 6455 upgrade over TLS plus one masked text frame echoed back: the "WSS on Native" acceptance check. */
    @Test fun wssHandshakeAndEchoFrame(): Unit =
        runBlocking {
            val srv =
                LoopbackServer.start { s ->
                    val r = s.openReadChannel()
                    val w = s.openWriteChannel(autoFlush = true)
                    var key = ""
                    r.readUTF8Line()
                    while (true) {
                        val l =
                            r.readUTF8Line() ?: break
                        if (l.isEmpty()) break
                        if (l.startsWith("Sec-WebSocket-Key:", ignoreCase = true)) {
                            key =
                                l.substringAfter(':').trim()
                        }
                    }
                    val accept =
                        kotlin.io.encoding.Base64.encode(
                            io.kuicksilver.tls.KslCrypto
                                .sha256((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encodeToByteArray()),
                        )
                    w.writeStringUtf8(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: $accept\r\n\r\n",
                    )
                    w.flush()
                    val hdr = r.readExactly(2)
                    val len = hdr[1].toInt() and 0x7f
                    val mask = r.readExactly(4)
                    val payload = r.readExactly(len)
                    for (i in payload.indices) payload[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
                    w.writeFully(byteArrayOf(0x81.toByte(), len.toByte()) + payload, 0, 2 + len)
                    w.flush() // unmasked server frame
                }
            try {
                val c = withTimeout(20.seconds) { srv.client() }
                try {
                    val w = c.openWriteChannel(autoFlush = true)
                    val r = c.openReadChannel()
                    val key =
                        kotlin.io.encoding.Base64
                            .encode(
                                io.kuicksilver.tls.KslCrypto
                                    .randomBytes(16),
                            )
                    w.writeStringUtf8(
                        "GET /ws HTTP/1.1\r\nHost: server.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: $key\r\nSec-WebSocket-Version: 13\r\n\r\n",
                    )
                    w.flush()
                    assertEquals("HTTP/1.1 101 Switching Protocols", withTimeout(10.seconds) { r.readUTF8Line() })
                    var acceptHeader = ""
                    while (true) {
                        val l =
                            r.readUTF8Line() ?: break
                        if (l.isEmpty()) break
                        if (l.startsWith("Sec-WebSocket-Accept:")) {
                            acceptHeader =
                                l.substringAfter(':').trim()
                        }
                    }
                    assertEquals(
                        kotlin.io.encoding.Base64.encode(
                            io.kuicksilver.tls.KslCrypto.sha256(
                                (
                                    key +
                                        "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                                ).encodeToByteArray(),
                            ),
                        ),
                        acceptHeader,
                    )
                    val text = "hello over wss".encodeToByteArray()
                    val mask = byteArrayOf(1, 2, 3, 4)
                    val masked = ByteArray(text.size) { (text[it].toInt() xor mask[it % 4].toInt()).toByte() }
                    w.writeFully(byteArrayOf(0x81.toByte(), (0x80 or text.size).toByte()) + mask + masked, 0, 6 + text.size)
                    w.flush()
                    val hdr = withTimeout(10.seconds) { r.readExactly(2) }
                    assertEquals(0x81, hdr[0].toInt() and 0xff)
                    assertEquals(
                        text.size,
                        hdr[1].toInt() and 0x7f,
                    )
                    assertContentEquals(text, r.readExactly(text.size))
                } finally {
                    c.close()
                }
                withTimeout(10.seconds) { srv.job.await() }
            } finally {
                srv.close()
            }
        }
}

/**
 * A [Socket] over in-memory channels, closed the way ktor's sockets close: [close] flushes and closes the write side, and the
 * socket's job completes only once the job that hands the written bytes to the peer has finished, so a peer that stops
 * reading keeps it open.
 */
internal class MemorySocket : Socket {
    private val toServer = ByteChannel(autoFlush = true)
    private val toClient = ByteChannel(autoFlush = true)
    val serverIn: ByteReadChannel get() = toServer
    val serverOut: ByteWriteChannel get() = toClient
    override val socketContext: CompletableJob = Job()
    override val coroutineContext: CoroutineContext get() = socketContext + Dispatchers.Default
    override val localAddress: SocketAddress = InetSocketAddress("127.0.0.1", 1)
    override val remoteAddress: SocketAddress = InetSocketAddress("127.0.0.1", 2)
    private var readerJob: ReaderJob? = null
    private var writerJob: WriterJob? = null
    private var closed = false

    override fun attachForReading(channel: ByteChannel): WriterJob =
        writer(coroutineContext, channel) { toClient.copyTo(channel) }.also {
            writerJob =
                it
        }

    override fun attachForWriting(channel: ByteChannel): ReaderJob =
        reader(coroutineContext, channel) { channel.copyTo(toServer) }.also {
            readerJob =
                it
        }

    override fun close() {
        if (closed) return
        closed = true
        launch {
            readerJob?.let {
                runCatching { it.channel.flushAndClose() }
                it.job.join()
            }
            writerJob?.job?.cancel()
            socketContext.complete()
        }
    }
}
