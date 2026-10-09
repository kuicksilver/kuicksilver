// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readUTF8Line
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.activePath
import io.kuicksilver.quic.incomingConnections
import io.kuicksilver.quic.incomingStreams
import io.kuicksilver.quic.isClientInitiated
import io.kuicksilver.quic.isUnidirectional
import io.kuicksilver.quic.quicClientConfig
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** The coroutine conveniences of QuicConveniences.kt over the in-memory network (all platforms). */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class ConveniencesTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun incomingConnectionsYieldsAccepted() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val accepted =
                        async {
                            p.server
                                .incomingConnections()
                                .take(2)
                                .toList()
                        }
                    val config = quicClientConfig(CoreFixtures.client())
                    val a = p.client.connect(p.server.localAddress, config)
                    val b = p.client.connect(p.server.localAddress, config)
                    assertEquals(2, accepted.await().size)
                    a.close()
                    b.close()
                }
            }
        }

    @Test fun incomingConnectionsCompletesWhenEndpointCloses() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(5.seconds) {
                    val collected = async(start = CoroutineStart.UNDISPATCHED) { p.server.incomingConnections().toList() }
                    yield()
                    p.server.close()
                    assertEquals(0, collected.await().size)
                }
            }
        }

    @Test fun incomingStreamsYieldsPeerStreamsInOrder() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val ids =
                        async {
                            s
                                .incomingStreams()
                                .take(2)
                                .toList()
                                .map { it.id }
                        }
                    val bidi = c.openBidi()
                    bidi.output.writeStringUtf8("a\n")
                    bidi.output.flush()
                    val uni = c.openUni()
                    uni.output.writeStringUtf8("b\n")
                    uni.output.flushAndClose()
                    assertEquals(listOf(0L, 2L), ids.await())
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun incomingStreamsCompletesOnLocalClose() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val seen = async(start = CoroutineStart.UNDISPATCHED) { s.incomingStreams().toList() }
                    s.close(code = 0, reason = "bye")
                    assertEquals(0, seen.await().size)
                    assertTrue(s.closed.isCompleted)
                    c.close()
                }
            }
        }

    @Test fun incomingStreamsPropagatesCallerCancellation() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val job = launch(start = CoroutineStart.UNDISPATCHED) { s.incomingStreams().collect { } }
                    job.cancel()
                    job.join()
                    assertTrue(job.isCancelled)
                    assertFalse(s.closed.isCompleted, "cancelling the collector leaves the connection alone")
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun streamDirectionFromId() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val bidi = c.openBidi()
                    assertFalse(bidi.isUnidirectional)
                    assertTrue(bidi.isClientInitiated)
                    val serverUni: QuicStream = s.openUni()
                    assertTrue(serverUni.isUnidirectional)
                    assertFalse(serverUni.isClientInitiated)
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun activePathFollowsMigration() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    val echo =
                        launch {
                            val st = s.acceptStream()
                            st.output.writeStringUtf8((st.input.readUTF8Line() ?: "") + "\n")
                            st.output.flushAndClose()
                        }
                    val st = c.openBidi()
                    st.output.writeStringUtf8("hi\n")
                    st.output.flushAndClose()
                    assertEquals("hi", st.input.readUTF8Line())
                    echo.join()
                    assertEquals(p.clientIo.localAddress, assertNotNull(c.activePath).localAddress)
                    val newAddr = InetSocketAddress("10.0.0.3", 3333)
                    c.migrate(p.net.open(newAddr))
                    assertEquals(newAddr, assertNotNull(c.activePath).localAddress)
                    c.close()
                    s.close()
                }
            }
        }

    /** A collector idle in `datagrams` when the connection closes gets the ConnectionLost, not a channel exception. */
    @Test fun idleDatagramCollectorSeesConnectionLostOnClose() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val outcome =
                        async {
                            try {
                                s.datagrams.collect { }
                                null
                            } catch (e: Throwable) {
                                e
                            }
                        }
                    delay(300.milliseconds) // the collector drained the empty queue and waits for a signal
                    s.close(code = 0, reason = "done")
                    assertIs<QuicException.ConnectionLost.ApplicationClosed>(outcome.await())
                    c.close()
                }
            }
        }
}
