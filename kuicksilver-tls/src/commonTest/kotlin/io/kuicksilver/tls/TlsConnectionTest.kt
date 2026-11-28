// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    DelicateKuicksilverApi::class,
    io.kuicksilver.annotations.InternalKuicksilverApi::class,
    kotlinx.coroutines.ExperimentalCoroutinesApi::class,
)

package io.kuicksilver.tls

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.cancel
import io.ktor.utils.io.discard
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.IOException
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** Two crossed in-memory channels: what the client writes, the server reads, and the other way round. */
internal open class ChannelPair {
    private val c2s = ByteChannel(autoFlush = true)
    private val s2c = ByteChannel(autoFlush = true)
    open val clientIn: ByteReadChannel get() = s2c
    open val clientOut: ByteWriteChannel get() = c2s
    open val serverIn: ByteReadChannel get() = c2s
    open val serverOut: ByteWriteChannel get() = s2c

    /** Simulates a transport that ends without close_notify in the client's receive direction. */
    fun killServerToClient() {
        s2c.close()
    }
}

/** [ChannelPair] over [BoundedPipe]s: each direction holds a few KiB, so a side that stops reading stops its peer's writes. */
internal class BoundedChannelPair : ChannelPair() {
    private val c2s = BoundedPipe()
    private val s2c = BoundedPipe()
    override val clientIn: ByteReadChannel get() = s2c.read
    override val clientOut: ByteWriteChannel get() = c2s.write
    override val serverIn: ByteReadChannel get() = c2s.read
    override val serverOut: ByteWriteChannel get() = s2c.write
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

private val testScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

/** Starts both handshakes concurrently; failures stay inside the Deferreds so tests can assert on them. */
internal fun connect(
    client: TlsConfig,
    server: TlsConfig,
    pair: ChannelPair = ChannelPair(),
    clientCache: SessionCache = SessionCache.Default,
): Pair<Deferred<TlsConnection>, Deferred<TlsConnection>> {
    val c = testScope.async { TlsConnection.client(pair.clientIn, pair.clientOut, client, EmptyCoroutineContext, clientCache) }
    val s = testScope.async { TlsConnection.server(pair.serverIn, pair.serverOut, server) }
    return c to s
}

/**
 * The side of a handshake a test expects to fail on the other side: closed if it was made (a TLS 1.3 client finishes before
 * the server refuses its certificate), so its native session goes; whatever it ended with is ignored.
 */
internal suspend fun Deferred<TlsConnection>.closeIfMade() {
    runCatching { withTimeout(10.seconds) { await() } }.getOrNull()?.close()
}

/**
 * The session caches a test makes for its own handshakes: [close] (in `@AfterTest`) closes them, which releases their native
 * sessions and every ticket that arrives later. Any thread may make one.
 */
@OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
internal class TestCaches {
    private val made = kotlin.concurrent.atomics.AtomicReference<List<SessionCache>>(emptyList())

    fun new(): SessionCache {
        val c = SessionCache()
        while (true) {
            val l = made.load()
            if (made.compareAndSet(l, l + c)) return c
        }
    }

    fun close() = runBlocking { for (c in made.exchange(emptyList())) c.close() }
}

internal object TcpFixtures {
    fun client(block: TlsConfig.Builder.() -> Unit = {}): TlsConfig =
        tlsConfig(TlsRole.Client) {
            alpn = listOf("x1")
            serverName =
                "server.test"
            trust = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
            block()
        }

    fun server(block: TlsConfig.Builder.() -> Unit = {}): TlsConfig =
        tlsConfig(TlsRole.Server) {
            alpn = listOf("x1")
            identity =
                TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
            block()
        }
}

class TlsConnectionTest {
    /**
     * The client cache of [both]: this test's own. A connection's reader stores the server's tickets after the handshake, and
     * a test that closed its client right away (close does not wait for the reader) may leave a ticket on its way to
     * [SessionCache.Default] after the next test's [load] cleared it; that ticket made the next full handshake a resumption,
     * which reports the earlier server's chain (a 61-certificate one, echoOneMegabyteTls13 on macosArm64, 2026-11-19).
     */
    private val cache = SessionCache()

    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        runBlocking { SessionCache.Default.clear() }
    }

    @AfterTest fun closeCache() {
        runBlocking { cache.close() }
    }

    /**
     * A server flight larger than ksl's BIO pair holds (about 17 KiB: a long chain, a large stapled OCSP response) goes out
     * whole: OpenSSL stops writing when the pair is full and asks to be driven again once it was drained, which the handshake
     * loop must do before it waits for the peer, or both sides wait for each other until the handshake deadline.
     */

    /** The same for the client's flight: a client certificate chain larger than the BIO pair, sent under ClientAuth.Required. */
    @Test fun clientFlightLargerThanTheBioPairCompletes(): Unit =
        runBlocking {
            for (copies in listOf(45, 60)) { // about 20 KiB and 26 KiB of certificates
                val client =
                    TcpFixtures.client {
                        identity =
                            TlsIdentity.fromDer(listOf(TestCerts.client) + List(copies) { TestCerts.testCa }, TestCerts.clientKey.copyOf())
                        certificateCompression = false // the repeated certificates compress to almost nothing (RFC 8879)
                    }
                val server =
                    TcpFixtures.server {
                        clientAuth = ClientAuth.Required
                        trust = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
                    }
                val (cd, sd) = connect(client, server)
                withTimeout(20.seconds) { cd.await().closeAndAwaitPumps() } // its tickets land within this test
                val s = withTimeout(20.seconds) { sd.await() }
                assertEquals(Certificate(TestCerts.client), s.peerCertificates[0])
                s.close()
            }
        }

    @Test fun serverFlightLargerThanTheBioPairCompletes(): Unit =
        runBlocking {
            for (copies in listOf(45, 60)) { // about 20 KiB and 26 KiB of certificates (RevocationTest staples 64 KiB)
                val server =
                    TcpFixtures.server {
                        identity =
                            TlsIdentity.fromDer(listOf(TestCerts.server) + List(copies) { TestCerts.testCa }, TestCerts.serverKey.copyOf())
                        certificateCompression = false // the repeated certificates compress to almost nothing (RFC 8879)
                    }
                val (cd, sd) = connect(TcpFixtures.client(), server)
                withTimeout(20.seconds) { cd.await().closeAndAwaitPumps() } // its tickets land within this test
                withTimeout(20.seconds) { sd.await() }.close()
            }
        }

    private fun both(
        client: TlsConfig = TcpFixtures.client(),
        server: TlsConfig = TcpFixtures.server(),
        pair: ChannelPair = ChannelPair(),
    ): Pair<TlsConnection, TlsConnection> =
        runBlocking {
            val pair2 = connect(client, server, pair, cache)
            withTimeout(20.seconds) { pair2.first.await() to pair2.second.await() }
        }

    /**
     * A ticket another server issued under the same cache key, stored in [SessionCache.Default] after this test began (a late
     * ticket of an earlier test), does not turn [both]'s handshake into a resumption: the client reports the chain its own
     * server presented, one certificate, and not the cached 61.
     */
    @Test fun aLateTicketInTheDefaultCacheLeavesBothAFullHandshake(): Unit =
        runBlocking {
            val longChain =
                TcpFixtures.server {
                    identity = TlsIdentity.fromDer(listOf(TestCerts.server) + List(60) { TestCerts.testCa }, TestCerts.serverKey.copyOf())
                }
            val client = TcpFixtures.client()
            val (cd, sd) = connect(client, longChain)
            val first = withTimeout(20.seconds) { cd.await() }
            val longServer = withTimeout(20.seconds) { sd.await() }
            assertEquals(61, first.peerCertificates.size)
            // the server's tickets precede its first byte, and the reader caches a ticket before it hands on what followed it
            longServer.output.writeFully(byteArrayOf(1), 0, 1)
            longServer.output.flush()
            withTimeout(10.seconds) { first.input.readExactly(1) }
            val key = SessionCache.key(client.serverName, "server.test", client.trust, client.identity)
            assertTrue(SessionCache.Default.peek(key), "the long chain's ticket is in the default cache")
            first.closeAndAwaitPumps()
            longServer.close()
            val (c, s) = both()
            try {
                assertEquals(false, c.sessionReused, "a full handshake")
                assertEquals(1, c.peerCertificates.size)
            } finally {
                c.close()
                s.close()
                SessionCache.Default.clear()
            }
        }

    @Test fun echoOneMegabyteTls13(): Unit =
        runBlocking {
            val (c, s) = both()
            try {
                assertEquals("x1", c.negotiatedAlpn)
                assertEquals(TlsVersion.Tls13, c.protocolVersion)
                assertEquals(1, c.peerCertificates.size)
                val data = ByteArray(1 shl 20) { (it * 7).toByte() }
                val echo =
                    async {
                        val got = s.input.readExactly(data.size)
                        s.output.writeFully(got, 0, got.size)
                        s.output.flush()
                    }
                c.output.writeFully(data, 0, data.size)
                c.output.flush()
                val back = withTimeout(30.seconds) { c.input.readExactly(data.size) }
                echo.await()
                assertContentEquals(data, back)
                assertContentEquals(c.exportKeyingMaterial("l", null, 16), s.exportKeyingMaterial("l", null, 16))
                assertContentEquals(c.channelBinding(), s.channelBinding())
            } finally {
                c.close()
                s.close()
            }
        }

    @Test fun fullDuplexKeepsRecordOrder(): Unit =
        runBlocking(Dispatchers.Default) {
            // both pumps drain ciphertext to the transport: the reader after each read, the writer after each write. Two drains
            // racing reordered records on the wire (the peer answered bad_record_mac; found by the soak)
            repeat(4) { round ->
                val (c, s) = both()
                try {
                    val size = 4 shl 20
                    val up = ByteArray(size) { (it * 7 + round).toByte() }
                    val down = ByteArray(size) { (it * 13 + round).toByte() }
                    withTimeout(60.seconds) {
                        val sw =
                            async {
                                s.output.writeFully(down, 0, size)
                                s.output.flush()
                            }
                        val cw =
                            async {
                                c.output.writeFully(up, 0, size)
                                c.output.flush()
                            }
                        val sr = async { s.input.readExactly(size) }
                        val cr = async { c.input.readExactly(size) }
                        assertContentEquals(up, sr.await(), "client to server, round $round")
                        assertContentEquals(down, cr.await(), "server to client, round $round")
                        sw.await()
                        cw.await()
                    }
                } finally {
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun fullDuplexOverFullTransportsNeverStalls(): Unit =
        runBlocking(Dispatchers.Default) {
            // both applications write and read at once over transports that hold a few KiB: a reader pump that writes the
            // writer's ciphertext and waits for room on its full transport stops reading, and when both peers' reader pumps
            // do, neither transport empties again
            repeat(4) { round ->
                val (c, s) = both(pair = BoundedChannelPair())
                try {
                    val size = 2 shl 20
                    val up = ByteArray(size) { (it * 7 + round).toByte() }
                    val down = ByteArray(size) { (it * 13 + round).toByte() }
                    val done =
                        withTimeoutOrNull(30.seconds) {
                            val sw = async { s.output.writeFully(down, 0, size).also { s.output.flush() } }
                            val cw = async { c.output.writeFully(up, 0, size).also { c.output.flush() } }
                            val sr = async { s.input.readExactly(size) }
                            val cr = async { c.input.readExactly(size) }
                            assertContentEquals(up, sr.await(), "client to server, round $round")
                            assertContentEquals(down, cr.await(), "server to client, round $round")
                            sw.await()
                            cw.await()
                        }
                    assertTrue(done != null, "full-duplex transfer over full transports stalled, round $round")
                } finally {
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun shutdownDeliversEofToPeer(): Unit =
        runBlocking {
            val (c, s) = both()
            try {
                c.output.writeFully("bye".encodeToByteArray(), 0, 3)
                c.shutdown()
                assertContentEquals("bye".encodeToByteArray(), s.input.readExactly(3))
                val tail = ByteArray(8)
                assertEquals(-1, withTimeout(5.seconds) { s.input.readAvailable(tail, 0, 8) }, "clean EOF after close_notify")
                assertNull(s.input.closedCause)
            } finally {
                c.close()
                s.close()
            }
        }

    /**
     * An output the application failed (cancelled with a cause, a handler that threw mid-stream) is not an end: no
     * close_notify, so the peer, reading to the end, gets an error when the transport ends, not a clean end of a cut
     * stream. ktor's `readAvailable` answers -1 for a failed channel as for a closed one when the failure is there
     * before the call; the writer pump, busy on a full transport when the failure came, took that -1 for the end and sent
     * close_notify (a clean end after 8 KiB here before).
     */
    @Test fun negative_aFailedOutputSendsNoCloseNotify(): Unit =
        runBlocking {
            val pair = BoundedChannelPair()
            val (c, s) = both(pair = pair)
            try {
                // more than the server takes while its application does not read (its plaintext buffer, about 1 MiB, and
                // the few KiB of the transport): the writer pump is still on this data, not waiting for more, when the
                // failure comes
                c.output.writeFully(ByteArray(3 shl 19), 0, 3 shl 19)
                c.output.flush()
                c.output.cancel(IOException("the application's stream failed"))
                // the client's session fails with it; then its transport ends, as a socket's close would end it
                launch {
                    runCatching { c.input.awaitContent() }
                    pair.clientOut.flushAndClose()
                }
                val buf = ByteArray(8192)
                val seen =
                    runCatching {
                        withTimeout(10.seconds) {
                            var got = 0L
                            while (true) {
                                val n = s.input.readAvailable(buf, 0, buf.size)
                                if (n < 0) break
                                got += n
                            }
                            s.input.closedCause?.let { throw it }
                            got
                        }
                    }
                assertTrue(seen.isFailure, "the peer read a clean end after ${seen.getOrNull()} bytes of a failed stream")
            } finally {
                c.close()
                s.close()
            }
        }

    /**
     * RFC 9846 section 6.1: "Each party MUST send a 'close_notify' alert before closing its write side of the connection,
     * unless it has already sent some error alert". A TLS 1.3 server whose application's stream failed ends with
     * internal_error (80) after what it had sent: the client reads that, then fails with the alert, never a clean end.
     */
    @Test fun negative_aFailedServerOutputSendsInternalError(): Unit =
        runBlocking {
            val (c, s) = both()
            try {
                s.output.writeFully(byteArrayOf(1, 2, 3), 0, 3)
                s.output.flush()
                assertContentEquals(byteArrayOf(1, 2, 3), withTimeout(10.seconds) { c.input.readExactly(3) })
                assertTrue(s.abortOutput(IOException("the application's stream failed")), "the server sent no alert")
                val seen =
                    runCatching {
                        withTimeout(10.seconds) {
                            val buf = ByteArray(64)
                            while (c.input.readAvailable(buf, 0, buf.size) >= 0) continue
                            c.input.closedCause?.let { throw it }
                        }
                    }
                var cause = seen.exceptionOrNull()
                while (cause != null && cause !is TlsException.AlertReceived) cause = cause.cause
                assertEquals(80, cause?.code, "the client saw $seen, not internal_error")
            } finally {
                c.close()
                s.close()
            }
        }

    /** A TLS 1.3 client has no way to send an alert through OpenSSL 3.5: [TlsConnection.abortOutput] says so at once. */
    @Test fun aFailedClientOutputCannotSendAnAlert(): Unit =
        runBlocking {
            val (c, s) = both()
            try {
                assertEquals(false, c.abortOutput(IOException("the application's stream failed")))
            } finally {
                c.close()
                s.close()
            }
        }

    /**
     * The peer stops reading: once its transport and its plaintext buffer are full the writer pump waits on the transport for
     * good, and shutdown() must still return at its bound (the KDoc says bounded) instead of waiting for the writer forever.
     */
    @Test fun negative_shutdownIsBoundedWhenThePeerStopsReading() {
        val (c, s) = both(pair = BoundedChannelPair())
        try {
            runTest(timeout = 30.seconds) {
                // more than the server's plaintext buffer (about 1 MiB, its application never reads) and the few KiB of the
                // transport take, less than the client's own output buffer also holds: the write returns, the rest stays queued
                val data = ByteArray(3 shl 19)
                c.output.writeFully(data, 0, data.size)
                c.output.flush()
                c.shutdown()
                assertEquals(
                    TlsConnection.SHUTDOWN_TIMEOUT.inWholeMilliseconds,
                    testScheduler.currentTime,
                    "shutdown waits its bound, then closes",
                )
            }
        } finally {
            c.close()
            s.close()
        }
    }

    /**
     * shutdown(drainTimeout = null), the server side of an engine that bounds the connection itself: sending what is queued
     * has no bound (the peer reads late, nothing is dropped), and only the wait for the peer's close_notify after it is bounded
     * by SHUTDOWN_TIMEOUT.
     */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    @Test
    fun unboundedDrainStillBoundsTheCloseNotifyWait() {
        val (c, s) = both(pair = BoundedChannelPair())
        try {
            runTest(timeout = 30.seconds) {
                val data = ByteArray(3 shl 19) { it.toByte() } // more than the server's buffers take while it does not read
                c.output.writeFully(data, 0, data.size)
                c.output.flush()
                val done = launch { c.shutdown(drainTimeout = null) }
                advanceTimeBy(10 * TlsConnection.SHUTDOWN_TIMEOUT.inWholeMilliseconds)
                runCurrent()
                assertTrue(done.isActive, "the drain has no bound: after 10 x SHUTDOWN_TIMEOUT it still waits for the reader")
                val drainedAt = testScheduler.currentTime
                // the server reads it all now; it never answers with close_notify, so the client waits out SHUTDOWN_TIMEOUT
                val got = withContext(Dispatchers.Default) { s.input.readExactly(data.size) }
                assertContentEquals(data, got, "nothing queued was dropped")
                done.join()
                assertEquals(
                    drainedAt + TlsConnection.SHUTDOWN_TIMEOUT.inWholeMilliseconds,
                    testScheduler.currentTime,
                    "after the drain, the wait for the peer's close_notify is bounded",
                )
            }
        } finally {
            c.close()
            s.close()
        }
    }

    @Test fun negative_truncatedTlsStreamIsError(): Unit =
        runBlocking {
            val pair = ChannelPair()
            val (c, s) = both(pair = pair)
            try {
                pair.killServerToClient()
                val e =
                    assertFailsWith<Exception> {
                        withTimeout(5.seconds) { c.input.readExactly(1) }
                    } // ktor wraps the close cause in ClosedByteChannelException
                val tls = generateSequence<Throwable>(e) { it.cause }.filterIsInstance<TlsException>().firstOrNull()
                assertTrue(
                    (tls is TlsException.Protocol && tls.message!!.contains("truncation")) || e.message!!.contains("truncation"),
                    "got $e / cause ${e.cause}",
                )
            } finally {
                c.close()
                s.close()
            }
        }

    /**
     * Bytes the peer sent before the transport ended without close_notify are still delivered; only then does the input
     * fail with the truncation (an HTTP/2 GOAWAY or the last bytes of an HTTP/1.1 response written just before a peer's
     * abortive close were lost with the failure). The truncation itself stays an error (negative_truncatedTlsStreamIsError).
     */
    @Test fun negative_bytesBeforeATruncationAreReadableThenItFails(): Unit =
        runBlocking {
            val pair = ChannelPair()
            val (c, s) = both(pair = pair)
            try {
                s.output.writeFully("before".encodeToByteArray())
                s.output.flush()
                // the bytes are decrypted and waiting in the client's input, unread (awaitContent does not consume them)
                assertTrue(withTimeout(5.seconds) { c.input.awaitContent(6) })
                pair.killServerToClient()
                // waiting for one byte more than were sent ends when the pump met the end of the transport: then it fails
                // with the truncation, without taking the 6 bytes, which are still to be read
                assertFailsWith<Exception> { withTimeout(5.seconds) { c.input.awaitContent(7) } }
                assertTrue(c.input.closedCause != null, "the input knows the failure")
                assertEquals("before", withTimeout(5.seconds) { c.input.readExactly(6) }.decodeToString())
                val e = assertFailsWith<Exception> { withTimeout(5.seconds) { c.input.readExactly(1) } }
                val tls = generateSequence<Throwable>(e) { it.cause }.filterIsInstance<TlsException>().firstOrNull()
                assertTrue(tls is TlsException.Protocol && tls.message!!.contains("truncation"), "got $e / cause ${e.cause}")
                assertEquals(false, c.input.isClosedForRead, "a truncated stream never looks complete")
            } finally {
                c.close()
                s.close()
            }
        }

    @Test fun keyUpdateBothDirections(): Unit =
        runBlocking {
            val (c, s) = both()
            try {
                c.keyUpdate(requestPeer = true)
                roundTrip(c, s, 3000)
                s.keyUpdate()
                roundTrip(c, s, 3000)
            } finally {
                c.close()
                s.close()
            }
        }

    private suspend fun roundTrip(
        c: TlsConnection,
        s: TlsConnection,
        n: Int,
    ) {
        val data = ByteArray(n) { it.toByte() }
        c.output.writeFully(data, 0, n)
        c.output.flush()
        val got = withTimeout(5.seconds) { s.input.readExactly(n) }
        assertContentEquals(data, got)
        s.output.writeFully(got, 0, n)
        s.output.flush()
        assertContentEquals(data, withTimeout(5.seconds) { c.input.readExactly(n) })
    }

    @Test fun negative_alpnMismatchClosesConnection() {
        val pair = ChannelPair()
        val (cd, sd) = connect(TcpFixtures.client { alpn = listOf("other") }, TcpFixtures.server(), pair)
        runBlocking {
            val e = assertFailsWith<TlsException.AlertReceived> { withTimeout(10.seconds) { cd.await() } }
            assertEquals(120, e.code)
            assertFailsWith<TlsException> { withTimeout(10.seconds) { sd.await() } }
        }
    }

    /**
     * Tls12And13 on both sides still negotiates TLS 1.3. The negative control for a TLS 1.2 peer without EMS
     * (`negative_tls12WithoutEmsRejected`, threat model section 5) lives in the C suite (`tcp_tls12_profile_and_ems`): the Kotlin
     * API cannot build a peer without extended master secret.
     */
    @Test fun tls12And13PeersNegotiateTls13() {
        val (c, s) =
            both(
                TcpFixtures.client {
                    versions = TlsVersions.Tls12And13
                    cipherSuites =
                        CipherSuites(listOf("TLS_AES_128_GCM_SHA256"))
                },
                TcpFixtures.server { versions = TlsVersions.Tls12And13 },
            )
        runBlocking {
            try {
                assertEquals(TlsVersion.Tls13, c.protocolVersion)
            } finally {
                c.close()
                s.close()
            }
        }
    }

    @Test fun handshakeTimeout() {
        val pair = ChannelPair()
        val e =
            runBlocking {
                assertFailsWith<TlsException.Protocol> {
                    withTimeout(10.seconds) {
                        TlsConnection.client(
                            pair.clientIn,
                            pair.clientOut,
                            TcpFixtures.client {
                                handshakeTimeout =
                                    1.seconds
                            },
                        )
                    }
                }
            }
        assertTrue(e.message!!.contains("timed out"), e.message)
    }

    /** A connection that fails while it is built (here: no reference identifier) frees its SSL* and its context. */
    @Test fun aConnectionThatCannotStartLeaksNoNativeObject() {
        val pair = ChannelPair()
        runBlocking {
            val before = Ksl.liveObjects()
            repeat(50) {
                assertFailsWith<TlsException.Config> {
                    TlsConnection.client(pair.clientIn, pair.clientOut, TcpFixtures.client { serverName = null })
                }
            }
            val after = Ksl.liveObjects()
            // other tests' connections free theirs asynchronously, so a count may drop meanwhile but never grow by 50
            assertTrue(after[KslConst.LIVE_SSL] <= before[KslConst.LIVE_SSL], "SSL objects ${before.toList()} -> ${after.toList()}")
            assertTrue(after[KslConst.LIVE_CTX] <= before[KslConst.LIVE_CTX], "contexts ${before.toList()} -> ${after.toList()}")
        }
    }

    /**
     * Cancelling the job the connection was started in ends it as a close does (the documented contract): the channels fail
     * and the native session is freed, although nobody called close(). It was freed only by close(), so an owner that ended
     * the connection through its job (or never got it: a handshake result dropped by a timeout) leaked the SSL object.
     */
    @Test fun cancellingTheCallersJobFreesTheNativeSession(): Unit =
        runBlocking {
            val pair = ChannelPair()
            val clientJob = kotlinx.coroutines.Job()
            val serverJob = kotlinx.coroutines.Job()
            val (c, s) =
                withTimeout(20.seconds) {
                    val c =
                        async(Dispatchers.Default) { TlsConnection.client(pair.clientIn, pair.clientOut, TcpFixtures.client(), clientJob) }
                    val s =
                        async(Dispatchers.Default) { TlsConnection.server(pair.serverIn, pair.serverOut, TcpFixtures.server(), serverJob) }
                    c.await() to s.await()
                }
            assertTrue(!c.nativeFreedForTest && !s.nativeFreedForTest)
            clientJob.cancel()
            serverJob.cancel()
            withTimeout(5.seconds) {
                while (!c.nativeFreedForTest || !s.nativeFreedForTest) delay(10)
            }
            assertFailsWith<Exception> { withTimeout(5.seconds) { c.input.readExactly(1) } }
        }

    /**
     * The input of a connection whose job was cancelled fails with a cause ktor keeps on every runtime, never as a clean end.
     * The reader pump cancelled it with the job's own cancellation, a JobCancellationException, which is a CopyableThrowable:
     * ktor re-creates such a cause through createCopy() wherever it hands it on, and outside the coroutines debug mode
     * (Android) createCopy() is null, so the input read as ended cleanly, a cancellation as the peer's close_notify (a
     * TlsSocket's relay then ended the application's channel cleanly instead of with its LocalClose). The JVM tests run in
     * debug mode, where the copy survives: the cause's type is what tells.
     */
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    @Test
    fun negative_aCancelledJobFailsTheInputWithACauseEveryRuntimeKeeps(): Unit =
        runBlocking {
            val pair = ChannelPair()
            val clientJob = kotlinx.coroutines.Job()
            val (c, s) =
                withTimeout(20.seconds) {
                    val c =
                        async(Dispatchers.Default) { TlsConnection.client(pair.clientIn, pair.clientOut, TcpFixtures.client(), clientJob) }
                    val s = async(Dispatchers.Default) { TlsConnection.server(pair.serverIn, pair.serverOut, TcpFixtures.server()) }
                    c.await() to s.await()
                }
            try {
                clientJob.cancel()
                withTimeout(10.seconds) { while (!c.input.isClosedForRead) runCatching { c.input.awaitContent() } }
                val cause = c.input.closedCause
                assertIs<kotlinx.coroutines.CancellationException>(cause, "the cancelled input's cause")
                assertTrue(
                    cause !is kotlinx.coroutines.CopyableThrowable<*>,
                    "the input's cause is re-created through createCopy(), which is null outside the debug mode: $cause",
                )
            } finally {
                c.close()
                s.close()
            }
        }

    /**
     * The handshake reads the peer's chain and the negotiated parameters from ksl outside the session lock: a job cancelled
     * as the handshake completes (an HTTP client call cancelled, a hard stop) must not free the native session under it.
     * Freed at once from the job's end, it was gone while the handshake still used it (a use after free, and a cached
     * session or SNI context assigned after the free was never released). It is freed once the handshake is over, and the
     * handshake fails as a closed connection, not with ksl's "connection closed" state error.
     */
    @Test fun aJobCancelledAsTheHandshakeCompletesDoesNotFreeTheSessionUnderIt(): Unit =
        runBlocking {
            val pair = ChannelPair()
            val clientJob = kotlinx.coroutines.Job()
            var client: TlsConnection? = null
            var freedUnderTheHandshake: Boolean? = null
            TlsConnection.handshakeCompletedForTest = { c ->
                if (c.contextForTest.config.role == TlsRole.Client) {
                    client = c
                    clientJob.cancel()
                    delay(300) // the free, had it been launched, has run by now
                    freedUnderTheHandshake = c.nativeFreedForTest
                }
            }
            try {
                val s = testScope.async { TlsConnection.server(pair.serverIn, pair.serverOut, TcpFixtures.server()) }
                val e =
                    assertFailsWith<TlsException.Protocol> {
                        withTimeout(20.seconds) { TlsConnection.client(pair.clientIn, pair.clientOut, TcpFixtures.client(), clientJob) }
                    }
                assertTrue(e.message!!.contains("connection closed"), e.message)
                assertEquals(false, freedUnderTheHandshake, "the native session was freed while the handshake used it")
                val c = assertNotNull(client)
                withTimeout(5.seconds) { while (!c.nativeFreedForTest) delay(10) } // and freed once the handshake was over
                runCatching { withTimeout(5.seconds) { s.await() } }.getOrNull()?.close()
            } finally {
                TlsConnection.handshakeCompletedForTest = null
            }
        }

    /** Contexts cancelled at any moment of the handshake: never ksl's state error, never a crash (Native would abort). */
    @Test fun contextsCancelledDuringTheHandshakeEndItCleanly(): Unit =
        runBlocking {
            repeat(40) { i ->
                val pair = ChannelPair()
                val clientJob = kotlinx.coroutines.Job()
                val s = testScope.async { TlsConnection.server(pair.serverIn, pair.serverOut, TcpFixtures.server()) }
                val c = testScope.async { TlsConnection.client(pair.clientIn, pair.clientOut, TcpFixtures.client(), clientJob) }
                delay((i % 10).toLong())
                clientJob.cancel()
                val outcome = runCatching { withTimeout(20.seconds) { c.await() } }
                outcome.exceptionOrNull()?.let { assertIs<TlsException>(it, "attempt $i: $it") }
                outcome.getOrNull()?.close()
                pair.killServerToClient()
                runCatching { withTimeout(5.seconds) { s.await() } }.getOrNull()?.close()
            }
        }

    /** A transport that failed (a reset) during the handshake is the cause of the handshake's failure, not dropped. */
    @Test fun aFailedTransportIsTheCauseOfAHandshakeFailure(): Unit =
        runBlocking {
            val clientIn = ByteChannel(autoFlush = true)
            val marker = IOException("connection reset (marker)")
            clientIn.cancel(marker)
            val e =
                assertFailsWith<TlsException.Protocol> {
                    withTimeout(10.seconds) { TlsConnection.client(clientIn, ByteChannel(autoFlush = true), TcpFixtures.client()) }
                }
            assertTrue(e.message!!.contains("transport closed"), e.message)
            assertTrue(generateSequence(e.cause) { it.cause }.any { it === marker }, "cause chain of $e: ${e.cause}")
        }

    /** A transport that fails on an established connection is the cause of the input's truncation failure. */
    @Test fun aFailedTransportIsTheCauseOfATruncation(): Unit =
        runBlocking {
            val c2s = ByteChannel(autoFlush = true)
            val s2c = ByteChannel(autoFlush = true)
            val (c, s) =
                withTimeout(20.seconds) {
                    val c = async(Dispatchers.Default) { TlsConnection.client(s2c, c2s, TcpFixtures.client()) }
                    val s = async(Dispatchers.Default) { TlsConnection.server(c2s, s2c, TcpFixtures.server()) }
                    c.await() to s.await()
                }
            try {
                // a round trip first: the server's post-handshake records (TLS 1.3 NewSessionTicket) are fed before its
                // first data, so the hook below meets the record of the byte under test, not a late ticket (on a slow host
                // the ticket could still be on its way and the transport failed before that byte was ever read)
                s.output.writeFully(byteArrayOf(0))
                s.output.flush()
                assertEquals(1, withTimeout(5.seconds) { c.input.readExactly(1) }.size)
                // the transport fails while the client's reader pump is busy with a record, not waiting on it: its next read
                // then answers -1 (ktor-io reads a channel failed with a cause as one that ended); a reader already waiting
                // gets the failure thrown instead
                val marker = IOException("connection reset (marker)")
                var armed = true
                c.refuseFeedForTest = {
                    if (armed) {
                        armed = false
                        s2c.cancel(marker)
                    }
                    false
                }
                s.output.writeFully(byteArrayOf(1))
                s.output.flush()
                assertEquals(1, withTimeout(5.seconds) { c.input.readExactly(1) }.size)
                val e = assertFailsWith<Exception> { withTimeout(5.seconds) { c.input.readExactly(1) } }
                val tls = generateSequence<Throwable>(e) { it.cause }.filterIsInstance<TlsException.Protocol>().first()
                assertTrue(tls.message!!.contains("truncation"), tls.message)
                assertTrue(generateSequence(tls.cause) { it.cause }.any { it === marker }, "cause chain of $tls: ${tls.cause}")
            } finally {
                c.close()
                s.close()
            }
        }

    @Test fun cancellationNotWrapped() {
        val pair = ChannelPair()
        runBlocking {
            assertFailsWith<TimeoutCancellationException> {
                withTimeout(1.seconds) {
                    TlsConnection.client(
                        pair.clientIn,
                        pair.clientOut,
                        TcpFixtures.client {
                            handshakeTimeout =
                                30.seconds
                        },
                    )
                }
            }
        }
    }
}

class TlsServerTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        runBlocking { SessionCache.Default.clear() }
    }

    private val proxyIdentity get() = TlsIdentity.fromDer(listOf(TestCerts.proxy), TestCerts.proxyKey.copyOf())
    private val serverIdentity get() = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())

    @Test fun sniSelectorOverridesIdentity(): Unit =
        runBlocking {
            val seen = CompletableDeferred<ClientHelloInfo>()
            val server =
                TcpFixtures.server {
                    identity = proxyIdentity
                    sniSelector =
                        { info ->
                            seen.complete(info)
                            if (info.serverName == "server.test") ServerTlsOverride(serverIdentity) else null
                        }
                }
            val (cd, sd) = connect(TcpFixtures.client(), server)
            val c = withTimeout(10.seconds) { cd.await() }
            val s = withTimeout(10.seconds) { sd.await() }
            try {
                assertEquals("server.test", seen.await().serverName)
                assertEquals(listOf("x1"), seen.await().alpn)
                assertTrue(seen.await().signatureSchemes.isNotEmpty())
                assertEquals(Certificate(TestCerts.server), c.peerCertificates[0])
            } finally {
                c.close()
                s.close()
            }
        }

    @Test fun negative_unrecognizedSniFatal() {
        val server =
            TcpFixtures.server {
                identity = proxyIdentity
                sniSelector = { null }
            }
        val (cd, _) = connect(TcpFixtures.client(), server)
        runBlocking {
            val e = assertFailsWith<TlsException.AlertReceived> { withTimeout(10.seconds) { cd.await() } }
            assertEquals(112, e.code)
        }
    }

    /**
     * RFC 9114 section 3.1: `h3` identifies HTTP/3 over QUIC, so TLS over TCP never negotiates it from an override's list,
     * even listed first (the server's order decides, RFC 7301 section 3.2); the connection reports the answer's list as set.
     */
    @Test fun negative_anOverrideNeverNegotiatesH3OverTcp(): Unit =
        runBlocking {
            val server = TcpFixtures.server { sniSelector = { ServerTlsOverride(serverIdentity, alpn = listOf("h3", "h3", "x1")) } }
            val (cd, sd) = connect(TcpFixtures.client { alpn = listOf("h3", "x1") }, server)
            val c = withTimeout(10.seconds) { cd.await() }
            val s = withTimeout(10.seconds) { sd.await() }
            try {
                assertEquals("x1", c.negotiatedAlpn)
                assertEquals("x1", s.negotiatedAlpn)
                assertEquals(listOf("h3", "h3", "x1"), s.sniSelectedAlpn)
            } finally {
                c.close()
                s.close()
            }
        }

    /** An override of `h3` alone serves its name over QUIC only: over TCP the handshake ends with `no_application_protocol`. */
    @Test fun negative_anH3OnlyOverrideEndsATcpHandshakeWithNoApplicationProtocol() {
        for (offer in listOf(listOf("h3"), listOf("x1"), emptyList())) {
            val server = TcpFixtures.server { sniSelector = { ServerTlsOverride(serverIdentity, alpn = listOf("h3")) } }
            val (cd, sd) = connect(TcpFixtures.client { alpn = offer }, server)
            runBlocking {
                val e = assertFailsWith<TlsException.AlertReceived>("offer $offer") { withTimeout(10.seconds) { cd.await() } }
                assertEquals(120, e.code, "offer $offer")
                assertFailsWith<TlsException>("offer $offer") { withTimeout(10.seconds) { sd.await() } }
            }
        }
    }

    /**
     * The ALPN a client without the extension gets from a server with [TlsConfig.alpnFallback] `fb` (null: it connected
     * without ALPN), or the alert that ended its handshake: [base] is the server's list, [answer] its selector's, if any.
     */
    @OptIn(ExperimentalKuicksilverApi::class)
    private fun withoutAlpn(
        base: List<String>,
        answer: List<String>? = null,
        selector: Boolean = answer != null,
        offer: List<String> = emptyList(),
        fb: String? = "fb",
    ): String =
        runBlocking {
            val server =
                TcpFixtures.server {
                    alpn = base
                    expert { alpnFallback = fb }
                    if (selector) sniSelector = { ServerTlsOverride(serverIdentity, alpn = answer) }
                }
            val (cd, sd) = connect(TcpFixtures.client { alpn = offer }, server)
            val c = runCatching { withTimeout(10.seconds) { cd.await() } }
            val s = runCatching { withTimeout(10.seconds) { sd.await() } }
            try {
                c.exceptionOrNull()?.let { e ->
                    assertTrue(s.isFailure, "the server completed a handshake its client saw fail: $e")
                    return@runBlocking "alert ${(e as? TlsException.AlertReceived)?.code ?: e}"
                }
                assertEquals(c.getOrThrow().negotiatedAlpn, s.getOrThrow().negotiatedAlpn)
                c.getOrThrow().negotiatedAlpn ?: "none"
            } finally {
                c.getOrNull()?.close()
                s.getOrNull()?.close()
            }
        }

    /**
     * RFC 9113 section 3.3: "HTTP/2 connections over TLS MUST use protocol negotiation in TLS", so a client without ALPN speaks
     * the fallback protocol; where the protocols in effect leave it out, the handshake ends with `no_application_protocol`
     * (120, as RFC 9001 section 8.1 for a QUIC client that negotiated none), on the base configuration and an override alike.
     */
    @Test fun negative_aClientWithoutAlpnIsRefusedWhereTheFallbackIsNotOffered() {
        assertEquals("alert 120", withoutAlpn(base = listOf("x1")), "the base configuration, no selector")
        assertEquals("alert 120", withoutAlpn(base = listOf("x1"), selector = true), "a selector answer without alpn: the base list")
        assertEquals("alert 120", withoutAlpn(base = listOf("x1", "fb"), answer = listOf("x1")), "the answer's list")
        assertEquals("alert 120", withoutAlpn(base = listOf("x1", "fb"), answer = listOf("h3")), "h3 alone stays 120")
        assertEquals("alert 120", withoutAlpn(base = listOf("x1", "fb"), answer = listOf("h3", "x1")), "h3 dropped first")
    }

    /**
     * A server's own list over TCP goes without `h3` too, as an answer's does: `h3` listed first is never selected, and a list
     * of `h3` alone refuses every client (RFC 9114 section 3.1, RFC 7301 section 3.2).
     */
    @Test fun negative_aServersOwnH3IsNeverSelectedOverTcp() {
        assertEquals("x1", withoutAlpn(base = listOf("h3", "x1"), offer = listOf("h3", "x1"), fb = null))
        assertEquals("alert 120", withoutAlpn(base = listOf("h3"), offer = listOf("h3"), fb = null))
        assertEquals("alert 120", withoutAlpn(base = listOf("h3"), fb = null), "a client without ALPN too")
        assertEquals("alert 120", withoutAlpn(base = listOf("h3", "fb"), offer = listOf("h3"), fb = "fb"), "only h3 offered")
        assertEquals("none", withoutAlpn(base = listOf("h3", "fb"), fb = "fb"), "the fallback is listed beside h3")
    }

    /** The controls: the fallback offered, an empty list (no ALPN), a client with ALPN, and no fallback (OpenSSL's default). */
    @Test fun aClientWithoutAlpnConnectsWhereTheFallbackIsOfferedOrNoneIsSet() {
        assertEquals("none", withoutAlpn(base = listOf("x1", "fb")))
        assertEquals("none", withoutAlpn(base = listOf("x1"), answer = listOf("fb", "x1")))
        assertEquals("none", withoutAlpn(base = listOf("x1", "fb"), selector = true))
        assertEquals("none", withoutAlpn(base = listOf("x1"), answer = emptyList()), "an empty answer: no ALPN")
        assertEquals("none", withoutAlpn(base = emptyList()), "a server without ALPN")
        assertEquals("none", withoutAlpn(base = listOf("x1"), fb = null), "no fallback: completes without ALPN")
        assertEquals("none", withoutAlpn(base = listOf("x1"), answer = listOf("x1"), fb = null))
        assertEquals("x1", withoutAlpn(base = listOf("x1"), offer = listOf("x1")), "a client with ALPN is not concerned")
        assertEquals("x1", withoutAlpn(base = listOf("x1", "fb"), answer = listOf("x1"), offer = listOf("x1")))
        assertEquals("alert 120", withoutAlpn(base = listOf("x1"), offer = listOf("fb")), "an offer without overlap stays 120")
    }

    /** A client without ALPN over TCP never speaks HTTP/3, which is QUIC only (RFC 9114 section 3.1): `h3` is no fallback. */
    @OptIn(ExperimentalKuicksilverApi::class)
    @Test
    fun negative_alpnFallbackIsForServersAndANameOfOneToTwoHundredFiftyFiveBytes() {
        assertFailsWith<TlsException.Config> { TcpFixtures.server { expert { alpnFallback = "h3" } } }
        assertFailsWith<TlsException.Config> { TcpFixtures.client { expert { alpnFallback = "http/1.1" } } }
        assertFailsWith<TlsException.Config> { TcpFixtures.server { expert { alpnFallback = "" } } }
        assertFailsWith<TlsException.Config> { TcpFixtures.server { expert { alpnFallback = "x".repeat(256) } } }
    }

    /** An empty override list keeps meaning "no ALPN" over TCP, as an empty [TlsConfig.alpn] does. */
    @Test fun anEmptyOverrideListNegotiatesNoAlpnOverTcp(): Unit =
        runBlocking {
            val server = TcpFixtures.server { sniSelector = { ServerTlsOverride(serverIdentity, alpn = emptyList()) } }
            val (cd, sd) = connect(TcpFixtures.client(), server)
            val c = withTimeout(10.seconds) { cd.await() }
            val s = withTimeout(10.seconds) { sd.await() }
            try {
                assertEquals(null, c.negotiatedAlpn)
                assertEquals(null, s.negotiatedAlpn)
            } finally {
                c.close()
                s.close()
            }
        }

    /**
     * RFC 9846 section 9.2: "Servers requiring this extension SHOULD respond to a ClientHello lacking a "server_name" extension
     * by terminating the connection with a "missing_extension" alert": a server with only an sniSelector, whose selector has
     * nothing for a ClientHello without SNI, has no identity to answer it with.
     */
    @Test fun negative_noSniWithoutDefaultIdentityEndsWithMissingExtension() {
        val server =
            tlsConfig(TlsRole.Server) {
                alpn = listOf("x1")
                sniSelector = { info -> if (info.serverName == "server.test") ServerTlsOverride(serverIdentity) else null }
            }
        val client =
            tlsConfig(TlsRole.Client) {
                alpn = listOf("x1")
                serverName = "127.0.0.1" // IP literal: no SNI
                trust = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
            }
        val (cd, _) = connect(client, server)
        runBlocking {
            val e = assertFailsWith<TlsException.AlertReceived> { withTimeout(10.seconds) { cd.await() } }
            assertEquals(109, e.code)
        }
    }

    @Test fun noSniUsesDefaultIdentity(): Unit =
        runBlocking {
            val seen = CompletableDeferred<String?>()
            val server =
                TcpFixtures.server {
                    sniSelector = { info ->
                        seen.complete(info.serverName)
                        null
                    }
                }
            val client =
                tlsConfig(TlsRole.Client) {
                    alpn = listOf("x1")
                    serverName = "127.0.0.1"
                    trust =
                        TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
                } // IP literal: no SNI
            val (cd, sd) = connect(client, server)
            val c = withTimeout(10.seconds) { cd.await() }
            val s = withTimeout(10.seconds) { sd.await() }
            try {
                assertNull(seen.await(), "no SNI for an IP literal")
                assertEquals(1, c.peerCertificates.size)
            } finally {
                c.close()
                s.close()
            }
        }

    /** RFC 6066 section 3 ( literal IP addresses are not permitted in server_name): an IP serverName is never sent as SNI, also when ExpectedName supplies a DNS reference. */
    @Test fun ipServerNameNeverSentAsSni(): Unit =
        runBlocking {
            val seen = CompletableDeferred<String?>()
            val server =
                TcpFixtures.server {
                    sniSelector = { info ->
                        seen.complete(info.serverName)
                        null
                    }
                }
            val client =
                tlsConfig(TlsRole.Client) {
                    alpn = listOf("x1")
                    serverName = "127.0.0.1"
                    trust =
                        TrustConfig.ExpectedName("server.test", base = TrustConfig.AnchoredCa(listOf(Fixtures.testCa)))
                }
            val (cd, sd) = connect(client, server)
            val c = withTimeout(10.seconds) { cd.await() }
            val s = withTimeout(10.seconds) { sd.await() }
            try {
                assertNull(withTimeout(5.seconds) { seen.await() }, "no SNI for an IP literal")
            } finally {
                c.close()
                s.close()
            }
        }

    /** ClientAuth.Optional + Pinned (review T3): a client without a certificate is accepted (TlsConfig.clientAuth KDoc), a presented one must match a pin. */
    @Test fun clientAuthOptionalPinnedAcceptsClientWithoutCertificate(): Unit =
        runBlocking {
            val ca = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
            val server =
                TcpFixtures.server {
                    clientAuth = ClientAuth.Optional
                    trust = TrustConfig.Pinned(setOf(Certificate(TestCerts.proxy).spkiSha256), base = ca)
                }
            val (c, s) = both(TcpFixtures.client(), server)
            try {
                assertTrue(s.peerCertificates.isEmpty(), "no client certificate")
            } finally {
                c.close()
                s.close()
            }
            val (cd, sd) =
                connect(
                    TcpFixtures.client {
                        identity =
                            TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())
                    },
                    server,
                )
            assertIs<VerifyReason.PinMismatch>(assertFailsWith<TlsException.Verify> { withTimeout(10.seconds) { sd.await() } }.reason)
            cd.closeIfMade()
        }

    @Test fun clientAuthRequiredAnchoredCaAndPinned(): Unit =
        runBlocking {
            val ca = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
            val ok =
                both(
                    TcpFixtures.client { identity = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf()) },
                    TcpFixtures.server {
                        clientAuth =
                            ClientAuth.Required
                        ; trust = ca
                    },
                )
            try {
                assertEquals(Certificate(TestCerts.client), ok.second.peerCertificates[0])
            } finally {
                ok.first.close()
                ok.second.close()
            }
            val (badClient, bad) =
                connect(
                    TcpFixtures.client {
                        identity =
                            TlsIdentity.fromDer(listOf(TestCerts.clientOtherCa), TestCerts.clientOtherCaKey.copyOf())
                    },
                    TcpFixtures.server {
                        clientAuth =
                            ClientAuth.Required
                        ; trust = ca
                    },
                )
            assertFailsWith<TlsException.Verify> { withTimeout(10.seconds) { bad.await() } }
            badClient.closeIfMade()
            val pinned = TrustConfig.Pinned(setOf(Certificate(TestCerts.proxy).spkiSha256), base = ca)
            val (pinBadClient, pinBad) =
                connect(
                    TcpFixtures.client {
                        identity =
                            TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())
                    },
                    TcpFixtures.server {
                        clientAuth =
                            ClientAuth.Required
                        ; trust = pinned
                    },
                )
            val e = assertFailsWith<TlsException.Verify> { withTimeout(10.seconds) { pinBad.await() } }
            pinBadClient.closeIfMade()
            assertIs<VerifyReason.PinMismatch>(e.reason)
        }

    /**
     * Threat model 5, item 2: a server pinning client certificates issues no ticket before its pin verdict. TLS 1.3: the
     * ticket is explicit, after the verdict, so a rejected client caches nothing. TLS 1.2 (a raw ksl client, TlsConfig cannot cap a peer
     * at 1.2): the in-handshake ticket is suppressed, so the client holds no resumable session although its handshake completed.
     */
    @Test fun negative_serverTicketBeforePinVerdict(): Unit =
        runBlocking {
            val ca = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
            // the client's certificate does not match
            val pinned = TrustConfig.Pinned(setOf(Certificate(TestCerts.proxy).spkiSha256), base = ca)
            val server =
                TcpFixtures.server {
                    versions = TlsVersions.Tls12And13
                    clientAuth = ClientAuth.Required
                    trust = pinned
                }
            val (cd, sd) =
                connect(
                    TcpFixtures.client {
                        identity = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())
                    },
                    server,
                )
            assertIs<VerifyReason.PinMismatch>(assertFailsWith<TlsException.Verify> { withTimeout(10.seconds) { sd.await() } }.reason)
            runCatching { withTimeout(10.seconds) { cd.await() }.close() }
            delay(200)
            assertEquals(0, SessionCache.Default.size(), "TLS 1.3: no ticket reached the rejected client")

            val pair = ChannelPair()
            val sd2 = testScope.async { TlsConnection.server(pair.serverIn, pair.serverOut, server) }
            val ctx = Ksl.ctxNew(KslConst.CLIENT)
            try {
                Ksl.ctxSetAlpn(ctx, byteArrayOf(2, 'x'.code.toByte(), '1'.code.toByte()))
                Ksl.ctxSetIdentity(ctx, listOf(TestCerts.client), TestCerts.clientKey.copyOf())
                Ksl.ctxSetOption(ctx, KslConst.OPT_MIN_VERSION, KslConst.TLS1_2)
                Ksl.ctxSetOption(ctx, KslConst.OPT_MAX_VERSION, KslConst.TLS1_2)
                Ksl.ctxSetOption(ctx, KslConst.OPT_VERIFY_MODE, KslConst.VERIFY_NONE)
                Ksl.ctxFreeze(ctx)
                val ssl = Ksl.sslNew(ctx, KslConst.MODE_TCP)
                try {
                    assertEquals(
                        KslConst.OK,
                        withTimeout(10.seconds) {
                            rawHandshake(ssl, pair.clientIn, pair.clientOut)
                        },
                        "the TLS 1.2 client finishes before the server's verdict",
                    )
                    assertEquals(byteArrayOf(0x03, 0x03).toList(), Ksl.sslGet(ssl, KslConst.GET_VERSION).toList())
                    assertIs<VerifyReason.PinMismatch>(
                        assertFailsWith<TlsException.Verify> { withTimeout(10.seconds) { sd2.await() } }.reason,
                    )
                    assertEquals(0L, Ksl.sslGet1Session(ssl), "TLS 1.2: no resumable session was handed out before the verdict")
                } finally {
                    Ksl.sslFree(ssl)
                }
            } finally {
                Ksl.ctxFree(ctx)
            }
        }

    /**
     * Threat model 5, item 2, through an SNI override (review T1): the base configuration asks for no client certificate and
     * issues tickets in the handshake, the selector's override pins client certificates. The override's settings must be in
     * effect: no ticket before its pin verdict, so a client whose CA-issued certificate is not pinned can never resume past the pin.
     */
    @Test fun negative_sniOverridePinnedClientsNoTicketBeforeVerdict(): Unit =
        runBlocking {
            val pinned =
                TrustConfig.Pinned(setOf(Certificate(TestCerts.proxy).spkiSha256), base = TrustConfig.AnchoredCa(listOf(Fixtures.testCa)))
            val server =
                TcpFixtures.server {
                    sniSelector = { ServerTlsOverride(serverIdentity, clientAuth = ClientAuth.Required, trust = pinned) }
                }
            val client = TcpFixtures.client { identity = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf()) }
            repeat(2) { attempt ->
                val (cd, sd) = connect(client, server)
                val e = assertFailsWith<TlsException.Verify>("attempt $attempt") { withTimeout(10.seconds) { sd.await() } }
                assertIs<VerifyReason.PinMismatch>(e.reason, "attempt $attempt: the pin is checked")
                // the server's close_notify follows anything it sent: reading to the end has processed a ticket, if one came
                runCatching {
                    withTimeout(10.seconds) {
                        val c = cd.await()
                        try {
                            c.input.discard()
                        } finally {
                            c.close()
                        }
                    }
                }
                assertEquals(0, SessionCache.Default.size(), "attempt $attempt: no ticket reached the rejected client")
            }
        }

    /** Drives a raw `ksl` TCP session over channels until its handshake completes; returns the last drive result. */
    private suspend fun rawHandshake(
        ssl: Long,
        input: ByteReadChannel,
        output: ByteWriteChannel,
    ): Int {
        val buf = ByteArray(16 * 1024)
        while (true) {
            val rc = Ksl.drive(ssl)
            while (true) {
                val n = Ksl.tcpDrain(ssl, buf, 0, buf.size)
                if (n <= 0) break
                output.writeFully(buf, 0, n)
            }
            output.flush()
            if (rc != KslConst.WANT_READ) return rc
            val n = input.readAvailable(buf, 0, buf.size)
            if (n < 0) return rc
            var off = 0
            while (off < n) {
                val used = Ksl.tcpFeed(ssl, buf, off, n - off)
                if (used <= 0) return rc
                off += used
            }
        }
    }

    private fun both(
        client: TlsConfig,
        server: TlsConfig,
    ): Pair<TlsConnection, TlsConnection> =
        runBlocking {
            val (cd, sd) = connect(client, server)
            withTimeout(20.seconds) {
                cd.await() to
                    sd.await()
            }
        }
}

class SessionResumptionTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        runBlocking { SessionCache.Default.clear() }
    }

    private fun once(
        client: TlsConfig,
        server: TlsConfig,
        exchange: Boolean = true,
    ): Pair<TlsConnection, Boolean> =
        runBlocking {
            val (cd, sd) = connect(client, server)
            val c = withTimeout(20.seconds) { cd.await() }
            val s = withTimeout(20.seconds) { sd.await() }
            if (exchange) {
                c.output.writeFully(byteArrayOf(1), 0, 1)
                c.output.flush()
                s.input.readExactly(1)
                s.output.writeFully(byteArrayOf(2), 0, 1)
                s.output.flush()
                c.input.readExactly(1)
            } // lets the ticket arrive
            val reused = c.sessionReused && s.sessionReused
            if (exchange) awaitTicket(keyOf(client)) // the ticket lands asynchronously; keep the connection open until it does
            c.close()
            s.close()
            c to reused
        }

    private fun keyOf(client: TlsConfig) = SessionCache.key(client.serverName, "server.test", client.trust, client.identity)

    private suspend fun awaitTicket(key: String): Boolean =
        withTimeoutOrNull(5.seconds) {
            while (!SessionCache.Default.peek(key)) delay(10)
            true
        } ?: false

    private fun stored(key: String): Boolean = runBlocking { awaitTicket(key) }

    /**
     * ADR-0011 (review T4): on the OpenSSL verifier's path (AnchoredCa here, Platform on Linux) a resumption verifies the cached
     * chain again; a chain that expired since the full handshake is not resumed, the client runs a full handshake instead.
     */
    @Test fun negative_resumptionRechecksCachedChainOnOpenSslPath() {
        val client = TcpFixtures.client()
        val server = TcpFixtures.server()
        once(client, server)
        resumptionClockSkewForTest = 101L * 366 * 24 * 3600 // past the test certificates' notAfter (2126)
        try {
            val (_, r) = once(client, server)
            assertTrue(!r, "an expired cached chain is never resumed")
        } finally {
            resumptionClockSkewForTest = 0
        }
        val (_, r2) = once(client, server)
        assertTrue(r2, "control: the fresh ticket of that full handshake resumes")
    }

    @Test fun secondConnectionResumes() {
        val client = TcpFixtures.client()
        val server = TcpFixtures.server()
        val (_, r1) = once(client, server)
        assertTrue(!r1, "first connection is a full handshake")
        val key = SessionCache.key("server.test", "server.test", client.trust, null)
        assertTrue(stored(key), "ticket stored")
        val (c2, r2) = once(client, server)
        assertTrue(r2, "second connection resumes")
        assertEquals(1, c2.peerCertificates.size, "chain comes from the cache on a resumed handshake")
        assertTrue(stored(key), "the resumed connection stored the fresh ticket")
    }

    /**
     * The ticket travels before the data that follows it, so it is cached before the application sees that data: a
     * client that reads one response and closes keeps its ticket (run 38287900994, SocketTlsTest on the macOS runner).
     * The ticket goes into the connection's own cache (an engine's), not into [SessionCache.Default].
     */
    @Test fun ticketCachedBeforeTheDataThatFollowsIt() {
        val client = TcpFixtures.client()
        val key = keyOf(client)
        repeat(100) { round ->
            runBlocking {
                val own = SessionCache()
                val (cd, sd) = connect(client, TcpFixtures.server(), clientCache = own)
                val c = withTimeout(20.seconds) { cd.await() }
                val s = withTimeout(20.seconds) { sd.await() }
                s.output.writeFully(byteArrayOf(2), 0, 1)
                s.output.flush()
                c.input.readExactly(1)
                val cached = own.peek(key)
                c.close()
                s.close()
                own.clear()
                assertTrue(cached, "round $round: the ticket that preceded the data is cached")
                assertEquals(0, SessionCache.Default.size(), "round $round: the ticket stays in the connection's own cache")
            }
        }
    }

    /**
     * RFC 9846 appendix C.4: "Servers that issue tickets SHOULD offer at least as many tickets as the number of connections that
     * a client might use; for example, a web browser using HTTP/1.1 [RFC9112] might open six connections to a server". A TCP
     * full handshake leaves six tickets, so six connections opened together all resume.
     */
    @Test fun sixConnectionsResumeFromOneFullHandshake() {
        val client = TcpFixtures.client()
        val server = TcpFixtures.server()
        val (_, r1) = once(client, server)
        assertTrue(!r1, "first connection is a full handshake")
        assertEquals(6, runBlocking { SessionCache.Default.size() }, "the full handshake left six tickets")
        val resumed = List(6) { once(client, server, exchange = false).second }
        assertTrue(resumed.all { it }, "all six connections resumed: $resumed")
    }

    @Test fun ticketIsSingleUse() {
        val client = TcpFixtures.client()
        val server = TcpFixtures.server()
        once(client, server)
        val key = SessionCache.key("server.test", "server.test", client.trust, null)
        assertTrue(stored(key))
        val (_, r2) = once(client, server)
        assertTrue(r2)
        assertTrue(stored(key))
        val (_, r3) = once(client, server)
        assertTrue(r3, "every resumed connection leaves a fresh ticket behind")
        runBlocking { SessionCache.Default.clear() }
        val (_, r4) = once(client, server)
        assertTrue(!r4, "a consumed ticket is never replayed")
    }

    @Test fun cacheKeyIncludesClientIdentity() {
        val ca = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
        val id = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())
        val plain = TcpFixtures.client()
        val withId = TcpFixtures.client { identity = id }
        val server =
            TcpFixtures.server {
                clientAuth =
                    ClientAuth.Optional
                ; trust = ca
            }
        once(plain, server)
        val (_, r) = once(withId, server)
        assertTrue(!r, "a client with another identity never resumes the anonymous session")
    }

    @Test fun serverPinnedClientCertResumes() {
        val ca = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
        val id = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())
        val client = TcpFixtures.client { identity = id }
        val server =
            TcpFixtures.server {
                clientAuth = ClientAuth.Required
                trust =
                    TrustConfig.Pinned(setOf(Certificate(TestCerts.client).spkiSha256), base = ca)
            }
        val (_, r1) = once(client, server)
        assertTrue(!r1)
        val (_, r2) = once(client, server)
        assertTrue(r2, "pinned client certificate re-checked from the session, handshake resumes")
    }

    /** A resumed handshake carries only the client's leaf, so a CA pin (AnyInValidatedChain) cannot be re-checked; the verdict of the full handshake travels with the ticket. */
    @Test fun serverChainScopePinnedClientResumes() {
        val ca = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
        val client = TcpFixtures.client { identity = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf()) }
        val server =
            TcpFixtures.server {
                clientAuth = ClientAuth.Required
                trust =
                    TrustConfig.Pinned(setOf(Fixtures.testCa.spkiSha256), PinScope.AnyInValidatedChain, ca)
            }
        val (_, r1) = once(client, server)
        assertTrue(!r1)
        val (_, r2) = once(client, server)
        assertTrue(r2, "a client pinned through its CA resumes")
    }

    /** The verdict is bound to the server's trust configuration; a ticket another configuration issued (process-wide ticket keys) is not resumed. */
    @Test fun serverTicketFromOtherTrustConfigNotResumed() {
        val ca = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
        val client = TcpFixtures.client { identity = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf()) }
        once(
            client,
            TcpFixtures.server {
                clientAuth = ClientAuth.Required
                trust = ca
            },
        )
        val pinnedServer =
            TcpFixtures.server {
                clientAuth = ClientAuth.Required
                trust =
                    TrustConfig.Pinned(setOf(Certificate(TestCerts.client).spkiSha256), base = ca)
            }
        val (_, r) = once(client, pinnedServer)
        assertTrue(!r, "full handshake (and pin check) under the other configuration")
    }

    @Test fun negative_resumedSessionRechecksPin() {
        var accept = true
        val verifier =
            CertificateVerifier {
                chain,
                _,
                _,
                ->
                if (accept) VerifyResult.Accepted(chain) else VerifyResult.Rejected(VerifyReason.PinMismatch(chain.map { it.spkiSha256 }))
            }
        val client = TcpFixtures.client { trust = TrustConfig.Custom(verifier) }
        val server = TcpFixtures.server()
        once(client, server)
        accept = false
        runBlocking {
            val (cd, sd) = connect(client, server)
            val e = assertFailsWith<TlsException.Verify> { withTimeout(10.seconds) { cd.await() } }
            assertIs<VerifyReason.PinMismatch>(e.reason)
            sd.closeIfMade()
        }
    }

    @Test fun cacheKeyIncludesTrustConfig() {
        val server = TcpFixtures.server()
        once(TcpFixtures.client(), server)
        val other =
            TcpFixtures.client {
                trust =
                    TrustConfig.Pinned(
                        setOf(Certificate(TestCerts.server).spkiSha256),
                        base = TrustConfig.AnchoredCa(listOf(Fixtures.testCa)),
                    )
            }
        val (c2, r) = once(other, server)
        assertEquals(1, c2.peerCertificates.size)
        assertTrue(!r, "different trust config: no resumption")
        assertTrue(stored(SessionCache.key("server.test", "server.test", other.trust, null)))
    }
}
