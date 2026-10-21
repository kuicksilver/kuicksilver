// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeoutKind
import io.kuicksilver.quic.ksl
import io.kuicksilver.quic.quicConfig
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class LifecycleTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun silence(
        p: CorePair,
        d: kotlin.time.Duration,
        tick: kotlin.time.Duration = 50.milliseconds,
    ) {
        val end =
            p.now + d
        while (p.now < end) {
            p.advance(tick)
            p.step()
        }
    }

    @Test fun idleTimeoutIsMinOfPeers() {
        val p = CorePair(serverQuic = quicConfig { maxIdleTimeout = 10.seconds })
        try {
            assertTrue(p.handshake())
            silence(p, 11.seconds)
            val c = p.closedReason(p.clientEvents)
            assertIs<QuicException.ConnectionLost.Timeout>(c)
            assertEquals(TimeoutKind.Idle, c.kind)
            assertEquals(10.seconds, c.duration)
            val s = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.Timeout>(s)
            assertEquals(10.seconds, s.duration)
            assertEquals(ConnectionState.Closed, p.client.state)
        } finally {
            p.close()
        }
    }

    @Test fun idleTimeoutAtLeastThreePto() {
        // peer idle 100 ms, but RTT samples of ~300 ms make the PTO ≈ 1 s: the effective idle timeout is 3 x PTO (RFC 9000 section 10.1)
        val p = CorePair(serverQuic = quicConfig { maxIdleTimeout = 100.milliseconds })
        try {
            assertTrue(
                p.runUntil(tick = 300.milliseconds) {
                    p.clientEvents.any { it is io.kuicksilver.quic.ConnectionEvent.HandshakeCompleted } &&
                        p.serverEvents.any { it is io.kuicksilver.quic.ConnectionEvent.HandshakeCompleted }
                },
                "handshake: client=${p.closedReason(p.clientEvents)} server=${p.closedReason(p.serverEvents)}",
            )
            p.runUntil(limit = 1.seconds, tick = 300.milliseconds) { false }
            val pto = p.client.stats.smoothedRtt + p.client.stats.rttVar * 4 + 25.milliseconds
            assertTrue(pto >= 500.milliseconds, "PTO $pto")
            p.advance(2.seconds)
            p.step()
            assertNull(p.closedReason(p.clientEvents), "alive after 2 s of silence (3 x PTO = ${pto * 3})")
            silence(p, pto * 3 + 100.milliseconds)
            assertIs<QuicException.ConnectionLost.Timeout>(p.closedReason(p.clientEvents))
        } finally {
            p.close()
        }
    }

    @Test fun idleRestartsOnReceive() {
        val p =
            CorePair(
                serverQuic = quicConfig { maxIdleTimeout = 2.seconds },
                clientQuic =
                    quicConfig {
                        maxIdleTimeout = 2.seconds
                        keepAlive =
                            1.seconds
                    },
            )
        ; try {
            assertTrue(p.handshake())
            silence(p, 6.seconds)
            assertNull(p.closedReason(p.serverEvents), "client keep-alive traffic restarts the server's idle timer")
        } finally {
            p.close()
        }
    }

    @Test fun handshakeTimeout10s() {
        val p = CorePair(crypto = ksl)
        p.filterToClient = { _, _ -> false }
        try {
            p.runUntil(limit = 11.seconds, tick = 100.milliseconds) { p.closedReason(p.clientEvents) != null }
            val c = p.closedReason(p.clientEvents)
            assertIs<QuicException.ConnectionLost.Timeout>(c)
            assertEquals(TimeoutKind.Handshake, c.kind)
            assertEquals(10.seconds, c.duration)
        } finally {
            p.close()
        }
    }

    /** Keep-alive with our idle timeout off holds a connection whose peer has one. */
    @Test fun keepAliveWithoutLocalIdleTimeoutKeepsPeerAlive() {
        val p =
            CorePair(
                serverQuic = quicConfig { maxIdleTimeout = 2.seconds },
                clientQuic =
                    quicConfig {
                        maxIdleTimeout = kotlin.time.Duration.ZERO
                        keepAlive = 1.seconds
                    },
            )
        try {
            assertTrue(p.handshake())
            silence(p, 10.seconds)
            assertNull(p.closedReason(p.clientEvents))
            assertNull(p.closedReason(p.serverEvents))
        } finally {
            p.close()
        }
    }

    /**
     * A peer whose idle timeout is shorter than our keep-alive interval: PINGs go out at least every half of the effective
     * idle timeout (as quic-go's KeepAlivePeriod), so the connection lives; it timed out at the peer's 2 s before.
     */
    @Test fun keepAliveFollowsAShorterPeerIdleTimeout() {
        val p =
            CorePair(
                serverQuic = quicConfig { maxIdleTimeout = 2.seconds },
                clientQuic = quicConfig { keepAlive = 20.seconds },
            )
        try {
            assertTrue(p.handshake())
            silence(p, 30.seconds)
            assertNull(p.closedReason(p.clientEvents))
            assertNull(p.closedReason(p.serverEvents))
        } finally {
            p.close()
        }
    }

    @Test fun keepAliveOffByDefault() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            silence(p, 1.seconds)
            val sent = p.client.stats.packetsSent
            silence(p, 28.seconds)
            assertEquals(sent, p.client.stats.packetsSent, "no PING without keepAlive")
        } finally {
            p.close()
        }
    }

    @Test fun keepAlivePingsKeepConnectionAlive() {
        val p = CorePair(clientQuic = quicConfig { keepAlive = 20.seconds })
        try {
            assertTrue(p.handshake())
            silence(p, 120.seconds, tick = 1.seconds)
            assertNull(p.closedReason(p.clientEvents))
            assertNull(p.closedReason(p.serverEvents))
        } finally {
            p.close()
        }
    }

    @Test fun applicationCloseBeforeConfirmedCarriesCodeIn1Rtt() {
        // RFC 9000 section 10.2.3: Initial/Handshake copies become 0x1c APPLICATION_ERROR without the reason; the 1-RTT copy keeps the application's code.
        // The server here has confirmed and dropped its Handshake keys, so it reads the 1-RTT copy (pre-release review leftover: the code was lost everywhere).
        val p = CorePair(crypto = ksl)
        try {
            p.runUntil { p.client.hasHandshakeKeys && p.server?.state == ConnectionState.Confirmed }
            p.client.close(7, "bye", p.now)
            p.runUntil(limit = 500.milliseconds) {
                p.closedReason(p.serverEvents) !=
                    null
            }
            val s = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.ApplicationClosed>(s, "server saw: $s")
            assertEquals(7L, s.code)
            assertEquals("bye", s.reason)
            assertEquals(Initiator.Peer, s.initiator)
        } finally {
            p.close()
        }
    }

    @Test fun applicationCloseInHandshakeSpaceIsDowngraded() {
        // a peer that still only has Handshake keys sees APPLICATION_ERROR without a reason
        val p = CorePair(crypto = ksl)
        p.filterToClient = { _, _ -> false } // the client never gets the server's flight: it stays unconfirmed and keeps Handshake keys
        try {
            p.runUntil(limit = 2.seconds) { p.server != null && p.server!!.hasHandshakeKeys }
            p.server!!.close(9, "server bye", p.now)
            p.filterToClient = { _, _ -> true }
            p.runUntil(limit = 2.seconds) { p.closedReason(p.clientEvents) != null }
            val c = p.closedReason(p.clientEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(c, "client saw: $c")
            assertEquals(0x0cL, c.code)
            assertEquals("", c.reason)
        } finally {
            p.close()
        }
    }

    @Test fun applicationCloseAfterConfirmed() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.runUntil { p.client.state == ConnectionState.Confirmed }
            p.client.close(7, "bye", p.now)
            p.runUntil(limit = 500.milliseconds) {
                p.closedReason(p.serverEvents) !=
                    null
            }
            val s = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.ApplicationClosed>(s)
            assertEquals(7L, s.code)
            assertEquals("bye", s.reason)
            assertEquals(Initiator.Peer, s.initiator)
            val c = p.closedReason(p.clientEvents)
            assertIs<QuicException.ConnectionLost.ApplicationClosed>(c)
            assertEquals(Initiator.Local, c.initiator)
        } finally {
            p.close()
        }
    }

    @Test fun closingStateLastsThreePto() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.runUntil { p.client.state == ConnectionState.Confirmed }
            p.filterToServer = {
                _,
                _,
                ->
                false
            }
            p.client.close(1, "", p.now)
            assertEquals(ConnectionState.Closing, p.client.state)
            val pto =
                p.client.stats.smoothedRtt + p.client.stats.rttVar * 4 + 25.milliseconds
            silence(p, pto * 2, tick = 10.milliseconds)
            assertEquals(ConnectionState.Closing, p.client.state)
            silence(p, pto * 2, tick = 10.milliseconds)
            assertEquals(ConnectionState.Closed, p.client.state)
        } finally {
            p.close()
        }
    }

    @Test fun drainingSendsNothing() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.client.close(1, "", p.now)
            p.runUntil(limit = 200.milliseconds) {
                p.closedReason(p.serverEvents) !=
                    null
            }
            assertEquals(ConnectionState.Draining, p.server!!.state)
            val sent = p.sentToClient
            silence(p, 2.seconds)
            assertEquals(sent, p.sentToClient)
        } finally {
            p.close()
        }
    }

    @Test fun reasonTruncatedTo1KiBLossyUtf8() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.runUntil { p.client.state == ConnectionState.Confirmed }
            val raw = ByteArray(2000) { 0xff.toByte() }
            p.client.close(1, raw.decodeToString(), p.now)
            p.runUntil(limit = 500.milliseconds) { p.closedReason(p.serverEvents) != null }
            val s = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.ApplicationClosed>(s)
            assertTrue(s.reason.encodeToByteArray().size <= 1024, "${s.reason.encodeToByteArray().size}")
            p.client.testInjectCloseReasonBytes = raw // a transport close with raw invalid bytes
        } finally {
            p.close()
        }
        val q = CorePair()
        try {
            assertTrue(q.handshake())
            q.client.testInjectCloseReasonBytes = ByteArray(2000) { 0xff.toByte() }
            q.runUntil(limit = 500.milliseconds) {
                q.closedReason(q.serverEvents) !=
                    null
            }
            val s = q.closedReason(q.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(s)
            assertTrue(s.reason.encodeToByteArray().size <= 1024)
            assertEquals(1024, s.reasonBytes.size)
            assertTrue(
                s.reasonBytes.all {
                    it ==
                        0xff.toByte()
                },
            )
        } finally {
            q.close()
        }
    }

    @Test fun errorCodeAbove2Pow62Rejected() {
        val p = CorePair()
        try {
            assertFailsWith<IllegalArgumentException> {
                p.client.close(1L shl 62, "", p.now)
            }
            assertEquals(ConnectionState.Handshaking, p.client.state)
        } finally {
            p.close()
        }
    }

    @Test fun statsReflectRecovery() {
        val p = CorePair()
        try {
            assertTrue(p.handshake(), "client=${p.closedReason(p.clientEvents)} server=${p.closedReason(p.serverEvents)}")
            val s = p.client.stats
            assertEquals(1200, s.pathMtu)
            assertTrue(s.smoothedRtt >= 0.milliseconds && s.minRtt <= s.smoothedRtt, "srtt")
            assertTrue(s.cwnd >= 2400, "cwnd ${s.cwnd}")
            assertEquals(0L, s.lostPackets)
            assertEquals(0, s.ptoCount)
        } finally {
            p.close()
        }
    }

    @Test fun memoryCeilingIsSumOfCeilings() {
        val c = QuicConfig.Default
        val p = CorePair()
        try {
            assertEquals(
                c.maxConnectionWindow + c.maxSendBuffer + 3L * c.limits.cryptoOutOfOrderPerLevel + c.limits.cryptoPostHandshake +
                    c.limits.undecryptablePackets * 1200L +
                    c.limits.qlogBytes,
                p.client.stats.memoryCeiling,
            )
        } finally {
            p.close()
        }
    }

    // ---- final review fix pass ----
    @Test fun keepAliveDoesNotHideDeadPeer() {
        // RFC 9000 section 10.1: only the first ack-eliciting packet after receiving restarts the idle timer, so our own PINGs cannot keep a dead peer "alive"
        val p =
            CorePair(
                clientQuic =
                    quicConfig {
                        maxIdleTimeout = 4.seconds
                        keepAlive = 1.seconds
                    },
                serverQuic =
                    quicConfig {
                        maxIdleTimeout =
                            4.seconds
                    },
            )
        ; try {
            assertTrue(p.handshake())
            silence(p, 500.milliseconds)
            p.filterToClient = { _, _ -> false } // the server vanishes
            silence(p, 12.seconds, tick = 100.milliseconds)
            val r = p.closedReason(p.clientEvents)
            assertIs<QuicException.ConnectionLost.Timeout>(r, "client closed by idle timeout despite keep-alive")
            assertEquals(TimeoutKind.Idle, r.kind)
        } finally {
            p.close()
        }
    }

    @Test fun closedConnectionReleasesTlsSessionAndKeys() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.client.close(0, "bye", p.now)
            p.runUntil(limit = 5.seconds, tick = 50.milliseconds) {
                p.client.state ==
                    ConnectionState.Closed &&
                    p.server!!.state == ConnectionState.Closed
            }
            assertTrue(
                p.client.state == ConnectionState.Closed && p.server!!.state == ConnectionState.Closed,
                "both reached Closed: ${p.client.state} / ${p.server!!.state}",
            )
            assertTrue(p.client.releasedForTest, "client released its TLS session and keys")
            assertTrue(p.server!!.releasedForTest, "server released its TLS session and keys")
        } finally {
            p.close()
        }
    }

    @Test fun idleClosedConnectionReleasesTlsSessionAndKeys() {
        val p = CorePair(clientQuic = quicConfig { maxIdleTimeout = 2.seconds }, serverQuic = quicConfig { maxIdleTimeout = 2.seconds })
        try {
            assertTrue(p.handshake())
            silence(p, 8.seconds)
            assertIs<QuicException.ConnectionLost.Timeout>(p.closedReason(p.clientEvents))
            assertTrue(p.client.releasedForTest)
        } finally {
            p.close()
        }
    }
}
