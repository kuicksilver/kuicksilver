// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeoutKind
import io.kuicksilver.quic.ksl
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
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

    /** The frames of the 1-RTT packet in a Null-protected datagram (short header behind any long ones), or null without one. */
    private fun nullOneRttPayload(
        d: ByteArray,
        dcidLen: Int,
    ): ByteArray? {
        val hv = PacketHeaderView()
        val b = PacketBuffer.of(d)
        try {
            var off = 0
            while (off < d.size && PacketHeaderCodec.parse(b, off, d.size, dcidLen, hv)) {
                if (d[off].toInt() and 0x80 == 0) {
                    val pnLen = (d[off].toInt() and 0x03) + 1
                    return d.copyOfRange(hv.pnOffset + pnLen, hv.packetEnd - 16)
                }
                if (hv.packetEnd <= off) break
                off = hv.packetEnd
            }
            return null
        } finally {
            b.close()
        }
    }

    /** A QUIC variable-length integer at [off]: its value and its size. */
    private fun varint(
        b: ByteArray,
        off: Int,
    ): Pair<Long, Int> {
        val len = 1 shl ((b[off].toInt() and 0xc0) ushr 6)
        var v = (b[off].toLong() and 0x3f)
        for (i in 1 until len) v = (v shl 8) or (b[off + i].toLong() and 0xff)
        return v to len
    }

    /**
     * RFC 9000 section 10.2.3 / 10.2.1: the CONNECTION_CLOSE is what a closing endpoint sends. A server below its
     * anti-amplification budget with 1-RTT keys closed with a 1024-byte reason: the 0x1d frame did not fit the 1-RTT packet and
     * was skipped, while the packet (padding only) still counted as the close. The reason is now cut to fit.
     */
    @Test fun closeReasonIsTruncatedToFitTheBudget() {
        val p = CorePair()
        p.filterToServer = { i, _ -> i == 0 } // only the ClientHello: the client's address stays unvalidated
        try {
            p.step()
            p.step()
            val s = p.server!!
            assertTrue(s.writeKeys[3] != null && !s.addressValidated, "the server holds 1-RTT keys, unvalidated")
            // as if probes had spent all but 300 bytes of the 3x budget (RFC 9000 section 8.1)
            val a = s.amplification
            a.restore(a.received, 3 * a.received - 300, validated = false)
            s.close(7, "x".repeat(1024), p.now)
            p.batch.clear()
            val n = s.poll(p.batch, p.now)
            assertEquals(1, n, "one datagram within the budget")
            val d = p.batch.buffer(0).toByteArray(p.batch.length(0))
            assertTrue(d.size <= 300, "${d.size} bytes")
            val f = nullOneRttPayload(d, p.client.localCid.length)
            assertTrue(f != null, "a 1-RTT packet in the ${d.size}-byte datagram")
            assertEquals(0x1d, f[0].toInt(), "the 1-RTT packet carries CONNECTION_CLOSE (application)")
            val (code, cl) = varint(f, 1)
            assertEquals(7L, code)
            val (len, ll) = varint(f, 1 + cl)
            assertTrue(len in 1..1023, "reason cut to $len bytes")
            val reason = f.copyOfRange(1 + cl + ll, 1 + cl + ll + len.toInt())
            assertTrue(reason.all { it == 'x'.code.toByte() })
            assertTrue(s.closeSent, "the close counts as sent")
        } finally {
            p.close()
        }
    }

    /** The reason bytes of the CONNECTION_CLOSE (0x1d) leading the 1-RTT packet of [d]. */
    private fun appCloseReason(
        d: ByteArray,
        dcidLen: Int,
    ): ByteArray {
        val f = nullOneRttPayload(d, dcidLen)
        assertTrue(f != null && f[0].toInt() == 0x1d, "a 1-RTT CONNECTION_CLOSE in the ${d.size}-byte datagram")
        val (_, cl) = varint(f, 1)
        val (len, ll) = varint(f, 1 + cl)
        return f.copyOfRange(1 + cl + ll, 1 + cl + ll + len.toInt())
    }

    /**
     * RFC 9000 section 19.19: the Reason Phrase "SHOULD be a UTF-8 encoded string". The 1024-byte cap and the cut to fit a packet
     * split the encoded bytes anywhere, so a reason ending in a multi-byte character went out with half of it.
     */
    @Test fun sentReasonTruncatedOnACodePointBoundary() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.runUntil { p.client.state == ConnectionState.Confirmed }
            p.client.close(1, "a".repeat(1023) + "\u00e9", p.now) // 1025 bytes
            p.batch.clear()
            check(p.client.poll(p.batch, p.now) >= 1)
            val r = appCloseReason(p.batch.buffer(0).toByteArray(p.batch.length(0)), p.server!!.localCid.length)
            assertEquals(1023, r.size, "cut before the 2-byte character")
            assertEquals("a".repeat(1023), r.decodeToString())
        } finally {
            p.close()
        }
        // the cut to fit an anti-amplification budget (closeReasonIsTruncatedToFitTheBudget) keeps whole characters too
        for (budget in 299L..301L) {
            val q = CorePair()
            q.filterToServer = { i, _ -> i == 0 }
            try {
                q.step()
                q.step()
                val s = q.server!!
                val a = s.amplification
                a.restore(a.received, 3 * a.received - budget, validated = false)
                s.close(7, "\u00e9".repeat(512), q.now)
                q.batch.clear()
                check(s.poll(q.batch, q.now) == 1)
                val r = appCloseReason(q.batch.buffer(0).toByteArray(q.batch.length(0)), q.client.localCid.length)
                assertTrue(r.isNotEmpty() && r.size < 1024, "budget $budget: ${r.size} bytes")
                assertEquals(0, r.size % 2, "budget $budget: ${r.size} bytes split a character")
                assertEquals("\u00e9".repeat(r.size / 2), r.decodeToString())
            } finally {
                q.close()
            }
        }
    }

    /**
     * RFC 9000 section 12.3: "If the packet number for sending reaches 2^62-1, the sender MUST close the connection without
     * sending a CONNECTION_CLOSE frame or any further packets." Unreachable in practice (146 000 years at 1 Mpps), so the
     * test starts the client's 1-RTT space just below the limit. Null protection: a packet's last 8 bytes are its number.
     */
    @Test fun packetNumberExhaustionClosesSilently() {
        val limit = (1L shl 62) - 1
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.runUntil { p.client.state == ConnectionState.Confirmed }
            p.client.loss
                .space(io.kuicksilver.quic.recovery.SpaceId.Application)
                .nextPn = limit - 4
            val id = p.client.openStream(true)
            val numbers = ArrayList<Long>()
            for (round in 0 until 8) {
                if (p.client.state != ConnectionState.Closed) p.client.writeStream(id, ByteArray(100), 0, 100, false)
                p.batch.clear()
                val n = p.client.poll(p.batch, p.now)
                for (i in 0 until n) {
                    val d = p.batch.buffer(i).toByteArray(p.batch.length(i))
                    var pn = 0L
                    for (k in d.size - 8 until d.size) pn = (pn shl 8) or (d[k].toLong() and 0xff)
                    numbers += pn
                }
            }
            assertTrue(numbers.isNotEmpty() && numbers.all { it < limit }, "packet numbers sent: $numbers")
            assertEquals(ConnectionState.Closed, p.client.state, "closed at the limit")
            val r = p.closedReason(generateSequence { p.client.nextEvent() }.toList())
            assertIs<QuicException.ConnectionLost.Internal>(r, "closed silently: $r")
        } finally {
            p.close()
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
