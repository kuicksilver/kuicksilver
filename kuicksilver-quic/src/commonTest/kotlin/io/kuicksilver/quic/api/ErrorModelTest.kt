// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.runtime.ConnectionRuntime
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class ErrorModelTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun connectionCloseFailsStreamsWithSameReason() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    st.output.writeFully(byteArrayOf(1), 0, 1)
                    st.output.flush()
                    val ss = s.acceptStream()
                    ss.input.readExactly(1)
                    s.close(5, "server done")
                    val reason = c.closed.await()
                    val e = assertFailsWith<Throwable> { st.input.readExactly(1) }
                    assertTrue(
                        generateSequence<Throwable>(e) { it.cause }.any {
                            it is QuicException.ConnectionLost.ApplicationClosed &&
                                it.code == 5L &&
                                it.initiator == Initiator.Peer
                        },
                        "stream failure carries the connection's reason: $e",
                    )
                    assertIs<QuicException.ConnectionLost.ApplicationClosed>(reason)
                    assertEquals(5L, reason.code)
                }
            }
        }

    @Test fun cancellationNeverWrapped() =
        runBlocking {
            ApiPair.open(serverAnswers = false).use { p ->
                val scope = CoroutineScope(Job())
                val d = scope.async { p.client.connect(p.server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build()) }
                kotlinx.coroutines.delay(200)
                scope.cancel("stop")
                val e = assertFailsWith<Throwable> { d.await() }
                assertIs<CancellationException>(e)
                assertTrue(generateSequence<Throwable>(e) { it.cause }.none { it is QuicException })
            }
        }

    @Test fun peerTransportErrorSurfaces() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, _) = p.connect()
                    // the stream is opened before the provocation is armed: once armed, the client's next packet carries it, and
                    // that may be its ACK of the server's post-handshake flight (HANDSHAKE_DONE, NEW_TOKEN) with no write of
                    // ours, so the peer's close can land before a later openBidi, which then throws it (QuicConnection.openBidi)
                    val st = c.openBidi()
                    armClientHandshakeDone(c)
                    runCatching {
                        st.output.writeFully(byteArrayOf(1), 0, 1)
                        st.output.flush()
                    } // the write may already see the close
                    val r = c.closed.await()
                    assertIs<QuicException.ConnectionLost.TransportClosed>(r)
                    assertEquals(0x0aL, r.code) // PROTOCOL_VIOLATION, RFC 9000 section 19.20
                    assertEquals(Initiator.Peer, r.initiator)
                }
            }
        }

    /** The interleaving that lost [peerTransportErrorSurfaces] its stream on a slow runner: a stream asked for after the peer's close gets that close. */
    @Test fun openAfterPeerTransportCloseThrowsTheReason() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, _) = p.connect()
                    armClientHandshakeDone(c)
                    val r = c.closed.await() // no write of ours: the client's ACK of the server's post-handshake flight carries it
                    assertIs<QuicException.ConnectionLost.TransportClosed>(r)
                    assertEquals(0x0aL, r.code)
                    assertEquals(Initiator.Peer, r.initiator)
                    // the connection's own reason (on the JVM, coroutines' stack-trace recovery may hand over a copy of it)
                    for (e in listOf(assertFailsWith<QuicException.ConnectionLost> { c.openBidi() }, assertFailsWith { c.openUni() })) {
                        assertIs<QuicException.ConnectionLost.TransportClosed>(e)
                        assertEquals(0x0aL, e.code)
                        assertEquals(Initiator.Peer, e.initiator)
                        assertEquals(r.message, e.message)
                    }
                }
            }
        }

    /** Makes the client's next 1-RTT packet carry HANDSHAKE_DONE, which a server MUST treat as PROTOCOL_VIOLATION (RFC 9000 section 19.20); set on the loop that reads it. */
    private suspend fun armClientHandshakeDone(c: QuicConnection) =
        withContext((c as ConnectionRuntime).loopDispatcherForTest) { c.core.testInjectHandshakeDone = true }
}
