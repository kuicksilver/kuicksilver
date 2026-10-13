// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.runtime.EndpointLoop
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** 0-RTT through the public runtime API (ADR-0015): tickets kept per endpoint, connectEarly, early accept on the server. */
@OptIn(ExperimentalKuicksilverApi::class)
class ZeroRttApiTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun clientConfig(mode: EarlyDataState = EarlyDataState.Allowed) =
        QuicClientConfig.Builder(CoreFixtures.client()).apply { earlyData = mode }.build()

    private suspend fun QuicConnection.echo(text: String): String {
        val s = openBidi()
        s.output.writeFully(text.encodeToByteArray())
        s.output.flushAndClose()
        return s.input.readAll()
    }

    private suspend fun io.ktor.utils.io.ByteReadChannel.readAll(): String {
        val b = ByteArray(4096)
        var out = ""
        while (true) {
            val n = readAvailable(b, 0, b.size)
            if (n < 0) return out
            out += b.decodeToString(0, n)
        }
    }

    @Test fun connectEarlySendsRequestIn0Rtt(): Unit =
        runBlocking {
            ApiPair.open(crypto = KslQuicCrypto, serverEarlyData = true).use { p ->
                withTimeout(20.seconds) {
                    val earlyRequestRead = CompletableDeferred<Unit>()
                    val server =
                        async {
                            repeat(2) {
                                val c = p.server.accept()
                                val s = c.acceptStream()
                                val got = s.input.readAll()
                                val tag = "${c.earlyDataAccepted}/${s.receivedEarly}"
                                if (it == 1) earlyRequestRead.complete(Unit)
                                s.output.writeFully("$got:$tag".encodeToByteArray())
                                s.output.flushAndClose()
                            }
                        }
                    val first = p.client.connect(p.server.localAddress, clientConfig())
                    assertEquals("one:null/false", first.echo("one"))
                    val sessions = (p.client as EndpointLoop).sessions
                    while (sessions.size() == 0) yield() // the ticket arrives after the handshake
                    first.close()
                    // the server's answers wait until it has read the whole request: a caller that resumes only after the
                    // handshake completed would rightly send it in 1-RTT (seen once on a loaded host), and the test is about 0-RTT
                    p.net.hold(p.clientIo.localAddress)
                    val second = p.client.connectEarly(p.server.localAddress, clientConfig())
                    val s = second.openBidi()
                    s.output.writeFully("two".encodeToByteArray())
                    s.output.flushAndClose()
                    earlyRequestRead.await()
                    assertEquals(false, second.isHandshakeComplete, "the request was sent before the handshake completed")
                    p.net.release(p.clientIo.localAddress)
                    assertEquals("two:true/true", s.input.readAll(), "accepted early and answered")
                    second.awaitHandshake()
                    assertEquals(true, second.earlyDataAccepted)
                    server.await()
                }
            }
        }

    /** Every native key a 1-RTT and a 0-RTT connection made is freed by the time both endpoints closed (found by the soak harness). */
    @Test fun keysOfResumedConnectionsAreFreed(): Unit =
        runBlocking {
            for (early in listOf(false, true)) {
                val before = Ksl.liveObjects()[KslConst.LIVE_KEY]
                val p = ApiPair.open(crypto = KslQuicCrypto, serverEarlyData = true)
                withTimeout(20.seconds) {
                    val server =
                        async {
                            repeat(4) {
                                val c = p.server.accept()
                                val s = c.acceptStream()
                                val got = s.input.readAll()
                                s.output.writeFully(got.encodeToByteArray())
                                s.output.flushAndClose()
                                c.closed.await()
                            }
                        }
                    val sessions = (p.client as EndpointLoop).sessions
                    repeat(4) {
                        val c =
                            if (early) {
                                p.client.connectEarly(p.server.localAddress, clientConfig())
                            } else {
                                p.client.connect(p.server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                            }
                        assertEquals("x$it", c.echo("x$it"))
                        c.awaitHandshake()
                        if (early) while (sessions.size() == 0) yield()
                        c.close()
                    }
                    server.await()
                }
                p.client.closeAndJoin()
                p.server.closeAndJoin()
                // other tests' endpoints may still be finishing their close (they only free keys): never more than before
                val after = Ksl.liveObjects()[KslConst.LIVE_KEY]
                assertTrue(
                    after <= before,
                    "native keys left after ${if (early) "0-RTT" else "1-RTT"} connections: $before before, $after after",
                )
            }
        }

    @Test fun streamsOpenedEarlyAndAfterTheHandshake(): Unit =
        runBlocking {
            ApiPair.open(crypto = KslQuicCrypto, serverEarlyData = true).use { p ->
                withTimeout(20.seconds) {
                    val server =
                        async {
                            repeat(2) {
                                val c = p.server.accept()
                                repeat(if (it == 0) 1 else 2) {
                                    val s = c.acceptStream()
                                    if (s.id and 2L != 0L) {
                                        launch { s.input.readAll() } // the uni stream ends only after the echo
                                    } else {
                                        val got = s.input.readAll()
                                        s.output.writeFully("$got!".encodeToByteArray())
                                        s.output.flushAndClose()
                                    }
                                }
                            }
                        }
                    val first = p.client.connect(p.server.localAddress, clientConfig())
                    assertEquals("one!", first.echo("one"))
                    val sessions = (p.client as EndpointLoop).sessions
                    while (sessions.size() == 0) yield()
                    first.close()
                    val second = p.client.connectEarly(p.server.localAddress, clientConfig())
                    val u = second.openUni()
                    u.output.writeFully("control".encodeToByteArray())
                    u.output.flush()
                    second.awaitHandshake()
                    assertEquals("after!", second.echo("after"), "a stream opened after the handshake on a 0-RTT connection")
                    u.output.flushAndClose()
                    server.await()
                }
            }
        }

    @Test fun requiredWithoutTicketFails(): Unit =
        runBlocking {
            ApiPair.open(crypto = KslQuicCrypto, serverEarlyData = true).use { p ->
                withTimeout(20.seconds) {
                    assertFailsWith<QuicException.ConnectionLost.ZeroRttRejected> {
                        p.client.connectEarly(p.server.localAddress, clientConfig(EarlyDataState.Required))
                    }
                }
            }
        }

    @Test fun earlyDataDisabledByDefault(): Unit =
        runBlocking {
            ApiPair.open(crypto = KslQuicCrypto).use { p ->
                withTimeout(20.seconds) {
                    val server = async { p.server.accept() }
                    val c = p.client.connectEarly(p.server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                    assertTrue(server.await().earlyDataAccepted == null && c.earlyDataAccepted == null)
                    assertEquals(0, (p.client as EndpointLoop).sessions.size(), "no tickets kept without the opt-in")
                }
            }
        }
}
