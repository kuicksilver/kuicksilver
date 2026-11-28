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
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.ReaderJob
import io.ktor.utils.io.WriterJob
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readLine
import io.ktor.utils.io.reader
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.ktor.utils.io.writer
import io.kuicksilver.io.ConnectionEndedException
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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
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
        context: CoroutineContext = kotlin.coroutines.EmptyCoroutineContext,
    ): TlsSocket = connectTcp(selector, InetSocketAddress(reference, port)).tls(cfg, context)

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
            val selector = SelectorManager(Dispatchers.IO)
            val server = bindTcp(selector, "127.0.0.1", 0)
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
            // the tickets preceded the echo, so they are cached by the time the echo was read (several per origin, RFC 9846 appendix C.4)
            val cached = SessionCache.Default.size()
            assertTrue(cached in 1..6, "$cached tickets cached")
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
     * A read channel opened after close() fails at once with a LocalClose: this side closed the socket, not the peer. The
     * channel is opened while the close is still under way here; [negative_aReadAfterTheCloseEndedIsALocalClose] opens it
     * once the socket's job has completed.
     */
    @Test fun negative_aReadAfterTheCloseIsALocalClose(): Unit = afterLocalEnd(delivering = false, end = { it.close() })

    /**
     * The same once the close has ended: the socket's job is complete, and a relay launched under it never ran (the channel
     * failed with "Parent job is Completed", a JobCancellationException, under load on Linux).
     */
    @Test fun negative_aReadAfterTheCloseEndedIsALocalClose(): Unit =
        afterLocalEnd(
            delivering = false,
            end = { it.close() },
            awaitEnd = true,
        )

    /** The same for the engines' read channel ([openDeliveringReadChannel]). */
    @Test fun negative_aDeliveringReadAfterTheCloseEndedIsALocalClose(): Unit =
        afterLocalEnd(delivering = true, end = { it.close() }, awaitEnd = true)

    /** An abort is this side's end too: a read channel opened after it fails with a LocalClose, not a cancellation. */
    @Test fun negative_aReadAfterTheAbortIsALocalClose(): Unit =
        afterLocalEnd(delivering = false, end = {
            it.abort()
        }, awaitEnd = true, aborted = true)

    /** The same for the engines' read channel. */
    @Test fun negative_aDeliveringReadAfterTheAbortIsALocalClose(): Unit =
        afterLocalEnd(
            delivering = true,
            end = { it.abort() },
            awaitEnd = true,
            aborted = true,
        )

    /**
     * A read waiting when the socket closes fails with a LocalClose as well: the close ends the relay, and the channel it
     * fed is failed with this side's end, not with the relay's cancellation (a CancellationException reaching a reader
     * that was not cancelled reads as its own cancellation).
     */
    @Test fun negative_aReadPendingAtTheCloseIsALocalClose(): Unit = pendingAtLocalEnd(delivering = false) { it.close() }

    /** The same for the engines' read channel. */
    @Test fun negative_aDeliveringReadPendingAtTheCloseIsALocalClose(): Unit = pendingAtLocalEnd(delivering = true) { it.close() }

    /** And at an abort. */
    @Test fun negative_aReadPendingAtTheAbortIsALocalClose(): Unit = pendingAtLocalEnd(delivering = false, aborted = true) { it.abort() }

    /**
     * A write channel opened after this side's end fails with a LocalClose too: no pump starts under the socket's job, which
     * may have completed (the write failed with a raw JobCancellationException), or while the close is under way (the pump
     * met the closed session output and failed the stream).
     */
    @Test fun negative_aWriteAfterTheCloseEndedIsALocalClose(): Unit = writeAfterLocalEnd(awaitEnd = true) { it.close() }

    /** The same while the close is still under way. */
    @Test fun negative_aWriteAfterTheCloseIsALocalClose(): Unit = writeAfterLocalEnd(awaitEnd = false) { it.close() }

    /** And after an abort. */
    @Test fun negative_aWriteAfterTheAbortIsALocalClose(): Unit = writeAfterLocalEnd(awaitEnd = true, aborted = true) { it.abort() }

    /**
     * A write waiting for room when the socket is aborted (the peer stopped reading) fails with the write side's
     * LocalClose, not with the pump's cancellation. Over [MemorySocket], whose buffers are known
     * ([negative_closeIsBoundedWhenThePeerStopsReading]): the server never reads, so the writes fill them and one waits.
     * One large write did not always wait: ktor's flush hands the bytes over before it checks for room, and a write pump
     * woken on another thread could take them all into its own buffer in between, so the write returned (a slow or a
     * different host). The writes go on until one is really suspended, which the writer's own coroutine tells.
     */
    @Test fun negative_aWritePendingAtTheAbortIsALocalClose(): Unit =
        runBlocking {
            val raw = MemorySocket()
            val server = async(Dispatchers.Default) { TlsConnection.server(raw.serverIn, raw.serverOut, serverConfig()) }
            val c = withTimeout(20.seconds) { raw.tls(clientConfig()) }
            val s = withTimeout(20.seconds) { server.await() }
            try {
                val out = c.openWriteChannel(autoFlush = true)
                val data = ByteArray(1 shl 20)
                // undispatched: each write runs here until it suspends, so a write not completed on return waits for room
                // (writeFully suspends only in its flush); one that returned is followed by the next. The buffers on the
                // way are some 5 MiB, so 64 writes are far more than ever return
                var waiting: Deferred<Result<Unit>>? = null
                for (i in 0 until 64) {
                    val w = async(start = CoroutineStart.UNDISPATCHED) { runCatching { out.writeFully(data, 0, data.size) } }
                    if (!w.isCompleted) {
                        waiting = w
                        break
                    }
                    w.await().getOrThrow()
                }
                val write = waiting
                assertTrue(write != null && !write.isCompleted, "the write waits for room before the abort")
                c.abort()
                val pending = withTimeout(20.seconds) { write.await() }.exceptionOrNull()
                // ktor's channel may take the rest of a waiting write into its buffer once it is woken: then the next write fails
                val e =
                    pending ?: runCatching {
                        withTimeout(10.seconds) {
                            out.writeFully(ByteArray(1), 0, 1)
                            out.flush()
                        }
                    }.exceptionOrNull()
                assertTrue(e != null && e !is CancellationException, "the waiting write failed with $e")
                val end = generateSequence(e) { it.cause }.filterIsInstance<ConnectionEndedException>().firstOrNull()
                assertIs<ConnectionEndedException.LocalClose>(end, "the waiting write failed with $e")
                assertEquals("the TLS socket is closed: nothing more is written", end.message)
            } finally {
                c.abort() // also when an assertion failed before the abort: the client's session is released
                s.close()
            }
        }

    /**
     * A close or an abort that comes while a read channel attaches (after the attach's checks, before its relay is
     * published) finds no relay to end: the attach ends it itself, and the channel fails with the LocalClose, not with
     * the relay's cancellation by the aborted socket's job.
     */
    @Test fun negative_aCloseDuringTheReadAttachIsALocalClose(): Unit = endDuringReadAttach(aborted = false) { it.close() }

    /** The same for an abort. */
    @Test fun negative_anAbortDuringTheReadAttachIsALocalClose(): Unit = endDuringReadAttach(aborted = true) { it.abort() }

    private fun endDuringReadAttach(
        aborted: Boolean,
        end: (TlsSocket) -> Unit,
    ): Unit =
        runBlocking {
            val srv = LoopbackServer.start { s -> runCatching { s.openReadChannel().readAvailable(ByteArray(1), 0, 1) } }
            try {
                val c = withTimeout(20.seconds) { srv.client() }
                c.beforeReadAttachForTest = { end(c) }
                val r = c.openReadChannel()
                assertLocalClose(r)
                withTimeout(20.seconds) { c.socketContext.join() }
                srv.awaitHandler(aborted)
            } finally {
                srv.close()
            }
        }

    /**
     * A close that comes while a write channel attaches: nothing is written into the closed session, the close stays
     * graceful, and the peer reads close_notify (a clean end), not internal_error (RFC 9846 section 6.1). The write
     * fails either way, but how depends on who came first: when the close found the pump already published, it closed
     * the channel in order (what was queued still goes out) and the write fails as on any closed channel
     * (ClosedWriteChannelException without a cause); when the attach ended the pump itself, with the LocalClose.
     */
    @Test fun negative_aCloseDuringTheWriteAttachStaysGraceful(): Unit =
        runBlocking {
            val seen = CompletableDeferred<Pair<Int, Throwable?>>()
            val srv =
                LoopbackServer.start { s ->
                    val r = s.openReadChannel()
                    val n = runCatching { r.readAvailable(ByteArray(64), 0, 64) }
                    seen.complete((n.getOrNull() ?: -2) to (n.exceptionOrNull() ?: r.closedCause))
                }
            try {
                val c = withTimeout(20.seconds) { srv.client() }
                c.beforeWriteAttachForTest = { c.close() }
                val w = c.openWriteChannel(autoFlush = true)
                // the close may find the pump published and close its channel cleanly (what was queued still goes out), or
                // the attach ends the pump first: a ClosedWriteChannelException without a cause or the LocalClose, never a
                // cancellation
                val e =
                    runCatching {
                        withTimeout(10.seconds) {
                            w.writeFully(ByteArray(10), 0, 10)
                            w.flush()
                        }
                    }.exceptionOrNull()
                assertTrue(e != null && e !is CancellationException, "the write failed with $e")
                val end = generateSequence(e) { it.cause }.filterIsInstance<ConnectionEndedException>().firstOrNull()
                assertTrue(end == null || end is ConnectionEndedException.LocalClose, "the write failed with $e")
                val (n, cause) = withTimeout(20.seconds) { seen.await() }
                assertEquals(-1, n, "the peer reads the clean end of a graceful close, not data or an alert ($cause)")
                assertEquals(null, cause, "the peer's read side ended cleanly")
                withTimeout(20.seconds) { c.socketContext.join() }
                srv.awaitHandler(false)
            } finally {
                srv.close()
            }
        }

    /** The same for an abort: the write fails with the LocalClose, not with the pump's cancellation. */
    @Test fun negative_anAbortDuringTheWriteAttachIsALocalClose(): Unit =
        runBlocking {
            val srv = LoopbackServer.start { s -> runCatching { s.openReadChannel().readAvailable(ByteArray(1), 0, 1) } }
            try {
                val c = withTimeout(20.seconds) { srv.client() }
                c.beforeWriteAttachForTest = { c.abort() }
                assertWriteLocalClose(c.openWriteChannel(autoFlush = true))
                withTimeout(20.seconds) { c.socketContext.join() }
                srv.awaitHandler(true)
            } finally {
                srv.close()
            }
        }

    /**
     * A reset by the peer that the write pump meets first is the peer's end: neither the write nor the read reports a
     * LocalClose (the pump's failure was taken for this side's end, and the reader got "the TLS socket is closed").
     */
    @Test fun negative_aPeerResetTheWritePumpMeetsIsNotALocalClose(): Unit =
        runBlocking {
            val srv = LoopbackServer.start { s -> s.abort() }
            try {
                val c = withTimeout(20.seconds) { srv.client() }
                val r = c.openReadChannel()
                val w = c.openWriteChannel(autoFlush = true)
                val chunk = ByteArray(64 shl 10)
                val wrote = runCatching { withTimeout(20.seconds) { while (true) w.writeFully(chunk, 0, chunk.size) } }.exceptionOrNull()
                assertTrue(wrote != null && wrote !is CancellationException, "the write after the peer's reset failed with $wrote")
                assertTrue(
                    generateSequence(wrote) { it.cause }.none { it is ConnectionEndedException.LocalClose },
                    "the write failed with this side's end: $wrote",
                )
                runCatching { withTimeout(10.seconds) { r.readAvailable(ByteArray(1), 0, 1) } }
                withTimeout(10.seconds) { while (!r.isClosedForRead) runCatching { r.awaitContent() } }
                assertTrue(r.closedCause != null, "a reset is not a clean end")
                assertTrue(
                    generateSequence(r.closedCause) { it.cause }.none { it is ConnectionEndedException.LocalClose },
                    "the read reports this side's end for the peer's reset: ${r.closedCause}",
                )
                c.close()
                srv.awaitHandler(true)
            } finally {
                srv.close()
            }
        }

    /**
     * The socket's context cancelled (its scope ended) while the relay waits for room for unread inbound data and a write
     * pump is attached: both end promptly, their channels with the typed LocalClose (the relay and the pump run under jobs
     * of their own, linked to the socket's cancellation), and nothing holds the native session.
     */
    @OptIn(InternalAPI::class)
    @Test
    fun negative_aCancelledSocketContextEndsTheRelayAndThePump(): Unit =
        runBlocking {
            val sent = CompletableDeferred<Unit>()
            val srv =
                LoopbackServer.start { s ->
                    val w = s.openWriteChannel(autoFlush = true)
                    runCatching {
                        val data = ByteArray(4 shl 20)
                        w.writeFully(data, 0, data.size)
                        sent.complete(Unit)
                        s.openReadChannel().readAvailable(ByteArray(1), 0, 1)
                    }
                }
            val scope = Job()
            try {
                val c = withTimeout(20.seconds) { srv.client(context = scope) }
                try {
                    val inbound = ByteChannel()
                    val relay = c.attachForReading(inbound)
                    val outbound = ByteChannel()
                    val pump = c.attachForWriting(outbound)
                    // unread inbound data: the relay has filled the application's channel and waits for room
                    withTimeout(20.seconds) { inbound.awaitContent(64 shl 10) }
                    assertTrue(relay.job.isActive && pump.job.isActive)
                    scope.cancel()
                    withTimeout(10.seconds) {
                        relay.job.join()
                        pump.job.join()
                    }
                    for ((name, cause) in listOf("read" to inbound.closedCause, "write" to outbound.closedCause)) {
                        val end = generateSequence(cause) { it.cause }.filterIsInstance<ConnectionEndedException>().firstOrNull()
                        assertIs<ConnectionEndedException.LocalClose>(end, "the $name side ended with $cause")
                    }
                } finally {
                    c.abort()
                }
                srv.awaitHandler(true)
            } finally {
                srv.close()
            }
        }

    /**
     * The socket's context cancelled between an attach's checks and its publication: the session's pumps are cancelled
     * with the socket, and the relay or the write pump that starts then may meet their cancellation before the link to
     * the socket's cancellation ends it. Either way the channel fails with the LocalClose, never a cancellation. Run for
     * the read and the write side; the interleaving is not forced, so this covers both orders over runs.
     */
    @Test fun negative_aContextCancelledDuringTheAttachIsALocalClose(): Unit =
        runBlocking {
            for (write in listOf(false, true)) {
                val srv = LoopbackServer.start { s -> runCatching { s.openReadChannel().readAvailable(ByteArray(1), 0, 1) } }
                val scope = Job()
                try {
                    val c = withTimeout(20.seconds) { srv.client(context = scope) }
                    try {
                        if (write) {
                            c.beforeWriteAttachForTest = { scope.cancel() }
                            assertWriteLocalClose(c.openWriteChannel(autoFlush = true))
                        } else {
                            c.beforeReadAttachForTest = { scope.cancel() }
                            assertLocalClose(c.openReadChannel())
                        }
                    } finally {
                        c.abort()
                    }
                    srv.awaitHandler(true)
                } finally {
                    srv.close()
                }
            }
        }

    /** A write on [w] fails with the write side's LocalClose, never a cancellation. */
    private suspend fun assertWriteLocalClose(w: ByteWriteChannel) {
        val e =
            runCatching {
                withTimeout(10.seconds) {
                    w.writeFully(ByteArray(10), 0, 10)
                    w.flush()
                }
            }.exceptionOrNull()
        assertTrue(e != null && e !is CancellationException, "the write failed with $e")
        val end = generateSequence(e) { it.cause }.filterIsInstance<ConnectionEndedException>().firstOrNull()
        assertIs<ConnectionEndedException.LocalClose>(end, "the write failed with $e")
        assertEquals("the TLS socket is closed: nothing more is written", end.message)
    }

    private fun writeAfterLocalEnd(
        awaitEnd: Boolean,
        aborted: Boolean = false,
        end: (TlsSocket) -> Unit,
    ): Unit =
        runBlocking {
            val srv = LoopbackServer.start { s -> runCatching { s.openReadChannel().readAvailable(ByteArray(1), 0, 1) } }
            try {
                val c = withTimeout(20.seconds) { srv.client() }
                end(c)
                if (awaitEnd) withTimeout(20.seconds) { c.socketContext.join() }
                val w = c.openWriteChannel(autoFlush = true)
                val e =
                    runCatching {
                        withTimeout(10.seconds) {
                            w.writeFully(ByteArray(10), 0, 10)
                            w.flush()
                        }
                    }.exceptionOrNull()
                assertTrue(e != null && e !is CancellationException, "the write after the local end failed with $e")
                val localEnd = generateSequence(e) { it.cause }.filterIsInstance<ConnectionEndedException>().firstOrNull()
                assertIs<ConnectionEndedException.LocalClose>(localEnd, "the write after the local end failed with $e")
                assertEquals("the TLS socket is closed: nothing more is written", localEnd.message)
                withTimeout(20.seconds) { c.socketContext.join() }
                srv.awaitHandler(aborted)
            } finally {
                srv.close()
            }
        }

    /** [end]s the client's socket, then opens its read channel (after the socket's job completed with [awaitEnd]). */
    private fun afterLocalEnd(
        delivering: Boolean,
        end: (TlsSocket) -> Unit,
        awaitEnd: Boolean = false,
        aborted: Boolean = false,
    ): Unit =
        runBlocking {
            val srv = LoopbackServer.start { s -> runCatching { s.openReadChannel().readAvailable(ByteArray(1), 0, 1) } }
            try {
                val c = withTimeout(20.seconds) { srv.client() }
                end(c)
                if (awaitEnd) withTimeout(20.seconds) { c.socketContext.join() }
                val r = if (delivering) c.openDeliveringReadChannel() else c.openReadChannel()
                assertLocalClose(r)
                srv.awaitHandler(aborted)
            } finally {
                srv.close()
            }
        }

    /** Opens the client's read channel, waits in a read on it, and [end]s the socket meanwhile. */
    private fun pendingAtLocalEnd(
        delivering: Boolean,
        aborted: Boolean = false,
        end: (TlsSocket) -> Unit,
    ): Unit =
        runBlocking {
            val srv = LoopbackServer.start { s -> runCatching { s.openReadChannel().readAvailable(ByteArray(1), 0, 1) } }
            try {
                val c = withTimeout(20.seconds) { srv.client() }
                val r = if (delivering) c.openDeliveringReadChannel() else c.openReadChannel()
                val started = CompletableDeferred<Unit>()
                // undispatched: the read runs here until it suspends, so it waits in awaitContent when [end] comes
                val read =
                    async(start = CoroutineStart.UNDISPATCHED) {
                        started.complete(Unit)
                        runCatching { r.readAvailable(ByteArray(1), 0, 1) }
                    }
                assertTrue(started.isCompleted && !read.isCompleted, "the read waits before the end")
                end(c)
                val failure = withTimeout(10.seconds) { read.await() }.exceptionOrNull()
                assertTrue(failure !is CancellationException, "the pending read failed with $failure")
                assertLocalClose(r, failure)
                withTimeout(20.seconds) { c.socketContext.join() }
                srv.awaitHandler(aborted)
            } finally {
                srv.close()
            }
        }

    /**
     * Waits for the server's handler; after an abort it may have failed: the reset can reach the server while its handshake
     * still reads the client's Finished.
     */
    private suspend fun LoopbackServer.awaitHandler(aborted: Boolean) {
        withTimeout(10.seconds) { if (aborted) runCatching { job.await() } else job.await() }
    }

    /**
     * [r] failed with this side's end: its cause is a LocalClose, and so is the failure of a read that waited on it
     * ([failure]). A read of a channel that is closed already returns -1 (ktor's channels), so the cause is what tells.
     */
    private suspend fun assertLocalClose(
        r: ByteReadChannel,
        failure: Throwable? = null,
    ) {
        if (failure != null) {
            val end = generateSequence(failure) { it.cause }.filterIsInstance<ConnectionEndedException>().firstOrNull()
            assertIs<ConnectionEndedException.LocalClose>(end, "the waiting read failed with $failure")
        } else {
            val thrown = runCatching { withTimeout(10.seconds) { r.readAvailable(ByteArray(1), 0, 1) } }.exceptionOrNull()
            assertTrue(thrown !is CancellationException, "the read after the local end failed with $thrown")
        }
        withTimeout(10.seconds) { while (!r.isClosedForRead) runCatching { r.awaitContent() } }
        val end = generateSequence(r.closedCause) { it.cause }.filterIsInstance<ConnectionEndedException>().firstOrNull()
        assertIs<ConnectionEndedException.LocalClose>(end, "the channel's cause ${r.closedCause}")
        assertEquals("the TLS socket is closed: nothing more is read", end.message)
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
            val selector = SelectorManager(Dispatchers.IO)
            try {
                val server = bindTcp(selector, "127.0.0.1", 0)
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
                    val requestLine = r.readLine(LineEnding.Lenient)
                    while (true) {
                        val l = r.readLine(LineEnding.Lenient) ?: break
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
                    val status = withTimeout(10.seconds) { r.readLine(LineEnding.Lenient) }
                    assertEquals("HTTP/1.1 200 OK", status)
                    var contentLength = 0
                    while (true) {
                        val l =
                            r.readLine(LineEnding.Lenient) ?: break
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
                    r.readLine(LineEnding.Lenient)
                    while (true) {
                        val l =
                            r.readLine(LineEnding.Lenient) ?: break
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
                    assertEquals("HTTP/1.1 101 Switching Protocols", withTimeout(10.seconds) { r.readLine(LineEnding.Lenient) })
                    var acceptHeader = ""
                    while (true) {
                        val l =
                            r.readLine(LineEnding.Lenient) ?: break
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
