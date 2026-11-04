// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TestCerts
import io.kuicksilver.quic.endpoint.EndpointPair
import io.kuicksilver.quic.ksl
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.QuicSessionTicket
import io.kuicksilver.tls.TlsIdentity
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * `TlsIdentity.Reloadable` behind a QUIC server: each QUIC session builds its TLS context from one identity snapshot, so a
 * reload reaches the next Initial and no running connection; tickets and the 0-RTT replay register outlive it.
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class ReloadIdentityQuicTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val leafA = Certificate(TestCerts.server)
    private val leafB = Certificate(TestCerts.serverViaIntermediate)

    private fun identityA() = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())

    private fun identityB() =
        TlsIdentity.fromDer(listOf(TestCerts.serverViaIntermediate, TestCerts.intermediate), TestCerts.serverViaIntermediateKey.copyOf())

    private suspend fun io.ktor.utils.io.ByteReadChannel.readText(): String {
        val b = ByteArray(4096)
        var out = ""
        while (true) {
            val n = readAvailable(b, 0, b.size)
            if (n < 0) return out
            out += b.decodeToString(0, n)
        }
    }

    private suspend fun QuicConnection.echo(text: String): String {
        val s = openBidi()
        s.output.writeFully(text.encodeToByteArray())
        s.output.flushAndClose()
        return s.input.readText()
    }

    /** Through the endpoint runtime over a `MemoryNetwork`: the next handshake shows the new leaf, the open connection still serves. */
    @Test fun newQuicHandshakeSeesReloadedLeaf(): Unit =
        runBlocking {
            val r = TlsIdentity.reloadable(identityA())
            ApiPair.open(crypto = KslQuicCrypto, serverTls = CoreFixtures.server { identity = r }).use { p ->
                withTimeout(20.seconds) {
                    // each connection served on its own: the test talks to them out of order
                    val serving =
                        async {
                            List(3) {
                                val c = p.server.accept()
                                async {
                                    val s = c.acceptStream()
                                    s.output.writeFully("${s.input.readText()}!".encodeToByteArray())
                                    s.output.flushAndClose()
                                }
                            }.forEach { it.await() }
                        }
                    val cfg = QuicClientConfig.Builder(CoreFixtures.client()).build()
                    val first = p.client.connect(p.server.localAddress, cfg)
                    assertEquals(leafA, first.peerCertificates[0])
                    r.reload(identityB())
                    val second = p.client.connect(p.server.localAddress, cfg)
                    assertEquals(leafB, second.peerCertificates[0], "a QUIC handshake after the reload presents the new leaf")
                    assertEquals("two!", second.echo("two"))
                    assertEquals("one!", first.echo("one"), "the connection made before the reload goes on")
                    assertEquals(leafA, first.peerCertificates[0])
                    val third = p.client.connect(p.server.localAddress, cfg)
                    assertEquals(leafB, third.peerCertificates[0])
                    assertEquals("three!", third.echo("three"))
                    serving.await()
                }
            }
            r.close()
        }

    private val earlyCfg = QuicClientConfig.Builder(CoreFixtures.client()).apply { earlyData = EarlyDataState.Allowed }.build()

    private fun pairServing(r: TlsIdentity.Reloadable) =
        EndpointPair(crypto = ksl) {
            server =
                QuicServerConfig
                    .Builder(CoreFixtures.server { identity = r })
                    .apply { earlyData = true }
                    .build()
        }

    private fun ticket(p: EndpointPair): QuicSessionTicket {
        val c = p.client.connect(earlyCfg, p.serverAddr, p.now)
        assertTrue(p.runUntil { p.events[c]?.any { it is ConnectionEvent.SessionTicket } == true })
        return p.events[c]!!
            .filterIsInstance<ConnectionEvent.SessionTicket>()
            .last()
            .ticket
    }

    /**
     * Sans-IO endpoints on virtual time: a ticket issued under identity A still carries 0-RTT that the server accepts after the
     * reload to B (tickets are not bound to the certificate), and a replay of that first flight is still refused, so the
     * reload did not reset the process-wide replay register (RFC 9846 section 8).
     */
    @Test fun earlyDataStillAcceptedAfterReload() {
        val r = TlsIdentity.reloadable(identityA())
        val p = pairServing(r)
        val t = ticket(p)
        r.reload(identityB())
        val flight = ArrayList<ByteArray>()
        p.filterToServer = { _, b ->
            flight += b
            true
        }
        val c = p.client.connect(earlyCfg, p.serverAddr, p.now, t)
        val id = c.openStream(bidi = true)
        val req = "GET /after-reload".encodeToByteArray()
        assertEquals(req.size, c.writeStream(id, req, 0, req.size, fin = true))
        var server: ConnectionCore? = null
        p.onServerCreated = { server = it }
        p.step()
        assertEquals(true, server!!.earlyDataAccepted, "0-RTT of a ticket issued before the reload is accepted")
        assertTrue(server!!.streamReceivedEarly(id))
        // the same first flight from an attacker on the path, to a second endpoint of this process with the same identity
        val q = pairServing(r)
        var replayed: ConnectionCore? = null
        for (b in flight) q.feed(q.server, b, q.clientAddr)?.let { if (replayed == null) replayed = it }
        assertEquals(false, replayed!!.earlyDataAccepted, "the replay register survives the reload")
        // a full handshake now presents the new identity
        val fresh = p.client.connect(QuicClientConfig.Builder(CoreFixtures.client()).build(), p.serverAddr, p.now)
        assertTrue(p.confirmed(fresh))
        assertEquals(leafB, fresh.peerCertificates[0])
        p.close()
        q.close()
        r.close()
    }
}
