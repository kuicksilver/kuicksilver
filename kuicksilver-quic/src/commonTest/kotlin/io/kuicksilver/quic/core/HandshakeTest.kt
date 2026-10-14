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
import io.kuicksilver.tls.EncryptionLevel
import io.kuicksilver.tls.QuicCrypto
import io.kuicksilver.tls.QuicTlsSession
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsEvent
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsRole
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
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class HandshakeTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** RFC 9001 section 8.4: a server treats a ClientHello with a non-empty legacy_session_id as a PROTOCOL_VIOLATION. */
    @Test fun negative_clientHelloWithLegacySessionIdIsProtocolViolation() {
        val p = CorePair(crypto = WithLegacySessionId(ksl))
        try {
            p.runUntil(limit = 2.seconds) { p.closedReason(p.serverEvents) != null }
            val r = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x0aL, r.code, r.reason)
        } finally {
            p.close()
        }
    }

    /** RFC 9001 section 8.2: a peer without the quic_transport_parameters extension is closed with 0x016d (missing_extension). */
    @Test fun negative_missingTransportParametersIsMissingExtension() {
        for (role in listOf(TlsRole.Server, TlsRole.Client)) {
            // the session of [role] never reports the peer's transport parameters, as if the extension were absent
            val p = CorePair(crypto = WithoutPeerTransportParameters(ksl, role))
            try {
                p.runUntil(limit = 2.seconds) {
                    (if (role == TlsRole.Server) p.closedReason(p.serverEvents) else p.closedReason(p.clientEvents)) != null
                }
                val events = if (role == TlsRole.Server) p.serverEvents else p.clientEvents
                val r = p.closedReason(events)
                assertIs<QuicException.ConnectionLost.TransportClosed>(r, "$role")
                assertEquals(0x16dL, r.code, "$role")
                assertFalse(events.any { it is ConnectionEvent.HandshakeCompleted }, "$role")
            } finally {
                p.close()
            }
        }
    }

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

/** Hides the peer's transport parameters from the sessions of [role] (a peer that sent no quic_transport_parameters). */
private class WithoutPeerTransportParameters(
    private val inner: QuicCrypto,
    private val role: TlsRole,
) : QuicCrypto by inner {
    override fun newSession(config: TlsConfig): QuicTlsSession = wrap(config, inner.newSession(config))

    override fun newSession(
        config: TlsConfig,
        earlyData: Boolean,
    ): QuicTlsSession = wrap(config, inner.newSession(config, earlyData))

    private fun wrap(
        config: TlsConfig,
        s: QuicTlsSession,
    ): QuicTlsSession =
        if (config.role != role) {
            s
        } else {
            object : QuicTlsSession by s {
                override fun nextEvent(): TlsEvent? {
                    while (true) {
                        val e = s.nextEvent() ?: return null
                        if (e !is TlsEvent.PeerTransportParameters) return e
                    }
                }
            }
        }
}

/** A client whose ClientHello carries a 32-byte legacy_session_id (TLS 1.3 middlebox compatibility mode, RFC 8446 appendix D.4). */
private class WithLegacySessionId(
    private val inner: QuicCrypto,
) : QuicCrypto by inner {
    override fun newSession(config: TlsConfig): QuicTlsSession = wrap(config, inner.newSession(config))

    override fun newSession(
        config: TlsConfig,
        earlyData: Boolean,
    ): QuicTlsSession = wrap(config, inner.newSession(config, earlyData))

    private fun wrap(
        config: TlsConfig,
        s: QuicTlsSession,
    ): QuicTlsSession =
        if (config.role != TlsRole.Client) {
            s
        } else {
            object : QuicTlsSession by s {
                private var done = false

                override fun nextEvent(): TlsEvent? {
                    val e = s.nextEvent()
                    if (done || e !is TlsEvent.CryptoData || e.level != EncryptionLevel.Initial || e.data[38].toInt() != 0) return e
                    done = true
                    // handshake header (4), legacy_version (2), random (32), then the session ID length byte at 38
                    val d = e.data
                    val out = d.copyOfRange(0, 38) + byteArrayOf(32) + ByteArray(32) { 0x5a } + d.copyOfRange(39, d.size)
                    val len = ((d[1].toInt() and 0xff) shl 16) or ((d[2].toInt() and 0xff) shl 8) or (d[3].toInt() and 0xff)
                    val n = len + 32
                    out[1] = (n ushr 16).toByte()
                    out[2] = (n ushr 8).toByte()
                    out[3] = n.toByte()
                    return TlsEvent.CryptoData(e.level, out)
                }
            }
        }
}
