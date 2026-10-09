// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.TestCerts
import io.kuicksilver.quic.ksl
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyResult
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class HandshakeTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun nullHandshakeCompletesBothSides() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            assertTrue(p.runUntil { p.client.state == ConnectionState.Confirmed })
            assertEquals(ConnectionState.Confirmed, p.server!!.state)
            assertEquals("hq-interop", p.client.negotiatedAlpn)
        } finally {
            p.close()
        }
    }

    @Test fun kslHandshakeAlpnHqInterop() {
        val p = CorePair(crypto = ksl)
        try {
            assertTrue(p.handshake(), "client=${p.closedReason(p.clientEvents)} server=${p.closedReason(p.serverEvents)}")
            assertEquals("hq-interop", p.client.negotiatedAlpn)
            assertEquals(1, p.client.peerCertificates.size)
            assertEquals(Certificate(TestCerts.server), p.client.peerCertificates[0])
            assertTrue(p.runUntil { p.client.state == ConnectionState.Confirmed && p.server!!.state == ConnectionState.Confirmed })
            assertContentEquals(p.client.exportKeyingMaterial("test", null, 16), p.server!!.exportKeyingMaterial("test", null, 16))
        } finally {
            p.close()
        }
    }

    @Test fun clientInitialDatagramsAtLeast1200() {
        val p = CorePair(crypto = ksl)
        val sizes = ArrayList<Int>()
        p.filterToServer =
            { _, b ->
                if (b[0].toInt() and 0xf0 == 0xc0) sizes += b.size
                true
            }
        try {
            assertTrue(p.handshake())
            assertTrue(sizes.isNotEmpty() && sizes.all { it >= 1200 }, "$sizes")
        } finally {
            p.close()
        }
    }

    @Test fun largeClientHelloSpansMultipleInitials() {
        val p = CorePair(crypto = ksl)
        var initials = 0
        p.filterToServer = { i, _ ->
            if (i == 0 || i == 1) initials++
            true
        }
        try {
            p.step()
            assertTrue(p.toServer.size >= 2 || initials >= 2, "ClientHello with X25519MLKEM768 needs two Initial packets")
            assertTrue(p.handshake())
        } finally {
            p.close()
        }
    }

    @Test fun transportParametersCidAuthentication() {
        val p = CorePair(crypto = ksl)
        p.client.testForgeInitialSourceCid = true
        try {
            assertFalse(p.handshake())
            val r = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x08L, r.code)
        } finally {
            p.close()
        }
    }

    @Test fun tlsFailureMapsToCryptoError() {
        val p =
            CorePair(clientTls = CoreFixtures.client(trust = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.otherCa)))), crypto = ksl)
        try {
            assertFalse(p.handshake())
            val r = p.closedReason(p.clientEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x0130L, r.code)
            assertEquals(Initiator.Local, r.initiator)
            assertIs<TlsException.Verify>(r.cause)
            val s = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(s)
            assertEquals(0x0130L, s.code)
            assertEquals(Initiator.Peer, s.initiator)
            assertIs<TlsException.AlertReceived>(s.cause)
            assertEquals(48, (s.cause as TlsException.AlertReceived).code)
        } finally {
            p.close()
        }
    }

    @Test fun alpnMismatchCloses0x0178() {
        val p = CorePair(clientTls = CoreFixtures.client(alpn = "h3"), serverTls = CoreFixtures.server(alpn = "hq-interop"), crypto = ksl)
        try {
            assertFalse(p.handshake())
            val s = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(s)
            assertEquals(0x0178L, s.code)
            val c = p.closedReason(p.clientEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(c)
            assertEquals(0x0178L, c.code)
        } finally {
            p.close()
        }
    }

    @Test fun verifyPauseRoundTrip() {
        var asked = 0
        val p =
            CorePair(
                clientTls =
                    CoreFixtures.client(
                        trust =
                            TrustConfig.Custom {
                                chain,
                                _,
                                _,
                                ->
                                asked++
                                VerifyResult.Accepted(chain)
                            },
                    ),
                crypto = ksl,
            )
        p.autoVerify =
            false
        try {
            p.runUntil(limit = 500.milliseconds()) { p.clientEvents.any { it is ConnectionEvent.VerifyRequested } }
            val req = p.clientEvents.filterIsInstance<ConnectionEvent.VerifyRequested>().single()
            assertEquals(1, req.chain.size)
            p.runUntil(limit = 300.milliseconds()) { false }
            assertFalse(p.clientEvents.any { it is ConnectionEvent.HandshakeCompleted }, "handshake waits for the verdict")
            p.client.resumeVerify(kotlinx.coroutines.runBlocking { req.session.verifyPeer(req.chain) })
            assertEquals(1, asked)
            assertTrue(p.handshake())
        } finally {
            p.close()
        }
    }

    @Test fun postHandshakeWantReadIsNotAnError() {
        val p = CorePair(crypto = ksl)
        try {
            assertTrue(p.handshake())
            p.runUntil(limit = 200.milliseconds()) { false }
            assertNull(p.closedReason(p.clientEvents))
            assertNull(p.closedReason(p.serverEvents))
        } finally {
            p.close()
        }
    }

    @Test fun streamEchoOneMiB() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            val data = ByteArray(1 shl 20) { (it * 31).toByte() }
            val id = p.client.openStream(bidi = true, StreamPriority.Default)
            var written = 0
            val echoed = ByteArray(data.size)
            var echoedLen = 0
            val buf = ByteArray(16384)
            var serverRead = 0
            var serverDone = false
            assertTrue(
                p.runUntil(limit = 60_000.milliseconds()) {
                    if (written <
                        data.size
                    ) {
                        written +=
                            p.client.writeStream(
                                id,
                                data,
                                written,
                                minOf(65536, data.size - written),
                                fin =
                                    written + minOf(65536, data.size - written) == data.size,
                            )
                    }
                    val s = p.server!!
                    while (true) {
                        val n = s.readStream(id, buf, 0, buf.size)
                        if (n >
                            0
                        ) {
                            s.writeStream(id, buf, 0, n, false)
                            serverRead += n
                        } else {
                            if (n < 0 &&
                                !serverDone
                            ) {
                                serverDone = true
                                s.writeStream(id, buf, 0, 0, true)
                            }
                            break
                        }
                    }
                    while (true) {
                        val n = p.client.readStream(id, echoed, echoedLen, echoed.size - echoedLen)
                        if (n >
                            0
                        ) {
                            echoedLen += n
                        } else {
                            break
                        }
                    }
                    echoedLen == data.size
                },
                "echoed $echoedLen of ${data.size}, server read $serverRead",
            )
            assertContentEquals(data, echoed)
        } finally {
            p.close()
        }
    }

    /** RFC 9002 section 6.2.4 in practice (interop `handshakeloss`): a server whose Initial PTO fires while Handshake data is also unacknowledged resends both, coalesced, instead of leaving the client waiting for the Handshake flight. */
    @Test fun serverInitialPtoAlsoProbesHandshakeSpace() {
        val p = CorePair()
        p.filterToClient = { _, _ -> false } // the client never sees the server: no ACKs reach the server
        assertTrue(
            p.runUntil(2_000.milliseconds()) {
                p.server?.loss?.space(io.kuicksilver.quic.recovery.SpaceId.Handshake)?.let {
                    it.ackElicitingInFlight >
                        0
                } ==
                    true
            },
            "server sent its Initial and Handshake flight",
        )
        val s = p.server!!
        val hsBefore =
            s.loss
                .space(io.kuicksilver.quic.recovery.SpaceId.Handshake)
                .sent.size
        p.filterToServer = { _, _ -> false } // and the client's probes stop too: only the server's own PTO can move things
        assertTrue(p.runUntil(3_000.milliseconds()) { s.loss.ptoCount >= 1 }, "the server's PTO fired")
        assertTrue(
            s.loss
                .space(io.kuicksilver.quic.recovery.SpaceId.Handshake)
                .sent.size > hsBefore,
            "the PTO probe carried a Handshake packet, not only the Initial one",
        )
    }
}

private fun Int.milliseconds() = kotlin.time.Duration.parse("${this}ms")
