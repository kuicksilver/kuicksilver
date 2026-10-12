// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.runtime.EndpointLoop
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.async
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

    @Test fun connectEarlySendsRequestIn0Rtt() =
        runBlocking {
            ApiPair.open(crypto = KslQuicCrypto, serverEarlyData = true).use { p ->
                withTimeout(20.seconds) {
                    val server =
                        async {
                            repeat(2) {
                                val c = p.server.accept()
                                val s = c.acceptStream()
                                val got = s.input.readAll()
                                val tag = "${c.earlyDataAccepted}/${s.receivedEarly}"
                                s.output.writeFully("$got:$tag".encodeToByteArray())
                                s.output.flushAndClose()
                            }
                        }
                    val first = p.client.connect(p.server.localAddress, clientConfig())
                    assertEquals("one:null/false", first.echo("one"))
                    val sessions = (p.client as EndpointLoop).sessions
                    while (sessions.size() == 0) yield() // the ticket arrives after the handshake
                    first.close()
                    val second = p.client.connectEarly(p.server.localAddress, clientConfig())
                    assertEquals("two:true/true", second.echo("two"), "accepted early and answered")
                    second.awaitHandshake()
                    assertEquals(true, second.earlyDataAccepted)
                    server.await()
                }
            }
        }

    @Test fun requiredWithoutTicketFails() =
        runBlocking {
            ApiPair.open(crypto = KslQuicCrypto, serverEarlyData = true).use { p ->
                withTimeout(20.seconds) {
                    assertFailsWith<QuicException.ConnectionLost.ZeroRttRejected> {
                        p.client.connectEarly(p.server.localAddress, clientConfig(EarlyDataState.Required))
                    }
                }
            }
        }

    @Test fun earlyDataDisabledByDefault() =
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
