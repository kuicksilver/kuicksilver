// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.EcnState
import io.kuicksilver.quic.IoCapabilities
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeoutKind
import io.kuicksilver.quic.endpoint.EndpointPair
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.recovery.SentFrames
import io.kuicksilver.quic.recovery.SentPacket
import io.kuicksilver.quic.recovery.SpaceId
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * Timers of [ConnectionCore] driven the way a runtime drives them: the clock jumps to the earliest [ConnectionCore.nextTimeout] and
 * [ConnectionCore.onTimeout] runs at exactly that instant. Property: a timer due at T fires when `onTimeout(T)` runs, so after
 * `onTimeout(T)` and `poll` no core asks to be woken at T again (a timer that stays due would spin its event loop).
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class ConnectionCoreTimersGapsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** One step at the earliest deadline (or 1 ms on while datagrams are in transit); false when nothing is left to do. */
    private fun exactStep(p: CorePair): Boolean {
        var t = listOfNotNull(p.client.nextTimeout(), p.server?.nextTimeout()).minOrNull()
        if (p.toServer.isNotEmpty() || p.toClient.isNotEmpty()) t = minOf(t ?: (p.now + 1.milliseconds), p.now + 1.milliseconds)
        if (t == null) return false
        if (t > p.now) p.now = t
        p.step()
        for (c in listOfNotNull(p.client, p.server)) {
            val next = c.nextTimeout() ?: continue
            assertTrue(next > p.now, "${c.role} still due at ${p.now} after onTimeout and poll (state ${c.state})")
        }
        return true
    }

    private fun runExact(
        p: CorePair,
        steps: Int = 20_000,
        done: () -> Boolean,
    ): Boolean {
        repeat(steps) {
            if (done()) return true
            if (!exactStep(p)) return done()
        }
        return done()
    }

    private fun bothConfirmed(p: CorePair) = p.client.state == ConnectionState.Confirmed && p.server?.state == ConnectionState.Confirmed

    /**
     * RFC 9000 section 10.1: an idle connection "is silently closed and its state discarded when it remains idle for longer than the
     * minimum of the max_idle_timeout value advertised by both endpoints"; the timer fires when the runtime calls at its deadline.
     */
    @Test fun idleTimerFiresAtItsDeadline() {
        val p = CorePair(serverQuic = quicConfig { maxIdleTimeout = 2.seconds })
        try {
            assertTrue(runExact(p) { bothConfirmed(p) })
            assertTrue(runExact(p) { p.client.state == ConnectionState.Closed && p.server!!.state == ConnectionState.Closed })
            val c = assertIs<QuicException.ConnectionLost.Timeout>(p.closedReason(p.clientEvents))
            assertEquals(TimeoutKind.Idle, c.kind)
        } finally {
            p.close()
        }
    }

    /**
     * Keep-alive PINGs, a transfer and the closing period (RFC 9000 section 10.2: "at least three times the current PTO"), all on
     * exact deadlines.
     */
    @Test fun keepAliveTransferAndClosingFireAtTheirDeadlines() {
        val p =
            CorePair(
                clientQuic = quicConfig { keepAlive = 500.milliseconds },
                serverQuic = quicConfig { maxIdleTimeout = 2.seconds },
            )
        try {
            assertTrue(runExact(p) { bothConfirmed(p) })
            val start = p.now
            assertTrue(runExact(p) { p.now > start + 5.seconds }, "keep-alive holds the connection")
            assertNull(p.closedReason(p.serverEvents))
            val id = p.client.openStream(true)
            var written = 0
            assertTrue(
                runExact(p) {
                    if (written < 100_000) written += p.client.writeStream(id, ByteArray(100_000 - written), 0, 100_000 - written, true)
                    written == 100_000 && p.client.stats.bytesInFlight == 0L
                },
            )
            p.client.close(1, "", p.now)
            assertTrue(runExact(p) { p.client.state == ConnectionState.Closed && p.server!!.state == ConnectionState.Closed })
        } finally {
            p.close()
        }
    }

    /** RFC 9000 section 10.2: a closing connection waits only for its closing period; loss and ACK timers of its spaces are over. */
    @Test fun negative_closingConnectionArmsOnlyTheClosePeriod() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.runUntil { bothConfirmed(p) }
            p.filterToServer = { _, _ -> false }
            val id = p.client.openStream(true)
            p.client.writeStream(id, ByteArray(5000), 0, 5000, false)
            p.step() // in flight, never acknowledged: the loss timer is armed
            assertTrue(p.client.stats.bytesInFlight > 0)
            p.client.close(1, "", p.now)
            val pto = p.client.stats.smoothedRtt + p.client.stats.rttVar * 4 + 25.milliseconds
            val deadline = p.client.nextTimeout()
            assertTrue(
                deadline != null && deadline >= p.now + pto * 3 - 1.milliseconds,
                "close period ${deadline?.let { it - p.now }}, PTO $pto",
            )
        } finally {
            p.close()
        }
    }

    /** The handshake timeout (QuicConfig.handshakeTimeout) fires at its deadline when the server never answers. */
    @Test fun handshakeTimeoutFiresAtItsDeadline() {
        val p = CorePair()
        p.filterToClient = { _, _ -> false }
        try {
            assertTrue(runExact(p) { p.client.state == ConnectionState.Closed })
            assertEquals(TimeoutKind.Handshake, assertIs<QuicException.ConnectionLost.Timeout>(p.closedReason(p.clientEvents)).kind)
        } finally {
            p.close()
        }
    }

    /** QuicEndpointConfig.maxConnectionLifetime: the connection closes with NO_ERROR at exactly its lifetime deadline. */
    @Test fun lifetimeDeadlineFiresAtItsDeadline() {
        val p = CorePair(clientQuic = quicConfig { keepAlive = 200.milliseconds })
        try {
            assertTrue(runExact(p) { bothConfirmed(p) })
            p.client.lifetimeDeadline = p.now + 1.seconds
            assertTrue(runExact(p) { p.client.state != ConnectionState.Confirmed })
            val r = assertIs<QuicException.ConnectionLost.TransportClosed>(p.closedReason(p.clientEvents))
            assertEquals(0L, r.code)
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 appendix A.4: an endpoint "can also mark the ECN state for a path as 'failed' if marked packets are all declared lost";
     * with every datagram vanishing no ACK ever declares them lost, so the first 1-RTT PTO with the test still unanswered ends it
     * (EcnValidator.onPto) and the probes go unmarked.
     */
    @Test fun ecnBlackHoleFailsAtTheFirstOneRttPto() {
        val ecn = IoCapabilities(ecnSend = true, ecnReceive = true, gsoMaxSegments = 1, gro = false, df = false, batch = 1)
        val p = EndpointPair()
        p.serverEcnReceive = true
        p.clientEcnReceive = true
        val c = p.connect()
        c.setPathCapabilities(PathId.Initial, IoCapabilities.Portable)
        try {
            assertTrue(p.confirmed(c))
            c.setPathCapabilities(PathId.Initial, ecn)
            val reported = ArrayList<PathId>()
            c.onEcnFailed = { reported += it }
            p.filterToServer = { _, _ -> false }
            val id = c.openStream(true)
            c.writeStream(id, ByteArray(20_000), 0, 20_000, false)
            assertTrue(p.runUntil(5.seconds) { c.stats.ptoCount >= 1 })
            assertEquals(EcnState.Failed, c.stats.ecnState, "no ACK at all: the PTO ends the test")
            assertEquals(listOf(PathId.Initial), reported, "the runtime hears of the failure once")
        } finally {
            p.close()
        }
    }

    /** A packet the server "sent" in the Application space that carried only MAX_DATA (no stream data, no per-stream frames). */
    private fun maxDataOnlyPacket(c: ConnectionCore): SentPacket {
        val sp = c.loss.space(SpaceId.Application)
        val pk = sp.newSentPacket()
        pk.pn = sp.takePn(c.random)
        pk.timeSent = c.now
        pk.size = 50
        pk.ackEliciting = true
        pk.inFlight = true
        pk.frames.flags = SentFrames.MAX_DATA
        c.loss.onPacketSent(SpaceId.Application, pk, c.now)
        return pk
    }

    private fun quietServer(p: CorePair): ConnectionCore {
        assertTrue(p.handshake())
        p.runUntil(1.seconds) { false }
        val s = p.server!!
        assertTrue(!s.streams.hasControlFrames(), "nothing queued after a quiet second")
        return s
    }

    /**
     * RFC 9000 section 13.3: "An updated value is sent in a MAX_DATA frame if the packet containing the most recently sent MAX_DATA
     * frame is declared lost". A lost packet that carried only MAX_DATA queues it again.
     */
    @Test fun lostMaxDataOnlyPacketQueuesMaxDataAgain() {
        val p = CorePair()
        try {
            val s = quietServer(p)
            val pk = maxDataOnlyPacket(s)
            ConnectionLossListener(s).onLost(SpaceId.Application, pk)
            assertTrue(s.streams.hasControlFrames(), "MAX_DATA queued again")
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9002 section 6.2.4: "An endpoint SHOULD include new data in packets that are sent on PTO expiration. Previously sent data
     * MAY be sent if no new data can be sent." A PTO taking a packet that carried only MAX_DATA sends the update again (KDoc of
     * requeueForProbe), not a bare PING.
     */
    @Test fun ptoProbeOfAMaxDataOnlyPacketCarriesMaxData() {
        val p = CorePair()
        try {
            val s = quietServer(p)
            maxDataOnlyPacket(s)
            s.requeueForProbe(SpaceId.Application, 1)
            assertTrue(s.streams.hasControlFrames(), "the probe carries MAX_DATA")
        } finally {
            p.close()
        }
    }

    /** The *_BLOCKED repeat timer (RFC 9000 section 4.1) of a sender the receiver never unblocks fires at each of its deadlines. */
    @Test fun blockedRepeatTimerFiresAtItsDeadlines() {
        val p =
            CorePair(serverQuic = quicConfig { initialConnectionWindow = 4000 })
        try {
            assertTrue(runExact(p) { bothConfirmed(p) })
            val id = p.client.openStream(true)
            p.client.writeStream(id, ByteArray(20_000), 0, 20_000, false) // the server never reads: blocked at 4000 bytes
            val start = p.now
            assertTrue(runExact(p) { p.now > start + 3.seconds })
            assertNull(p.closedReason(p.clientEvents))
        } finally {
            p.close()
        }
    }

    /** RFC 9000 section 13.3: "NEW_TOKEN frames are retransmitted if the packet containing them is lost" (the current token only). */
    @Test fun lostNewTokenIsSentAgain() {
        val p = CorePair()
        try {
            val s = quietServer(p)
            s.newToken = ByteArray(16) { 7 }
            s.newTokenSeq = 1
            s.sendNewToken = false
            val pk = maxDataOnlyPacket(s)
            pk.frames.flags = 0
            pk.frames.idCount = 1
            pk.frames.idKind[0] = SentFrames.ID_NEW_TOKEN
            pk.frames.idValue[0] = 1
            ConnectionLossListener(s).onLost(SpaceId.Application, pk)
            assertTrue(s.sendNewToken, "the token goes again")
            // only the loss of the current token resends it: not an older token's, not another frame's
            s.sendNewToken = false
            for ((kind, seq) in listOf(SentFrames.ID_NEW_TOKEN to 0L, SentFrames.ID_MAX_STREAM_DATA to 1L)) {
                val other = maxDataOnlyPacket(s)
                other.frames.flags = 0
                other.frames.idCount = 1
                other.frames.idKind[0] = kind
                other.frames.idValue[0] = seq
                ConnectionLossListener(s).onLost(SpaceId.Application, other)
                assertTrue(!s.sendNewToken, "kind $kind value $seq lost")
            }
            // the acknowledgment of an older token leaves the current one to be delivered
            val older = maxDataOnlyPacket(s)
            older.frames.flags = 0
            older.frames.idCount = 1
            older.frames.idKind[0] = SentFrames.ID_NEW_TOKEN
            older.frames.idValue[0] = 0
            ConnectionLossListener(s).onAcked(SpaceId.Application, older)
            assertTrue(s.newToken != null, "token 1 is still unacknowledged")
        } finally {
            p.close()
        }
    }

    /** RFC 9221 section 5: a lost DATAGRAM is reported to the sender, also the one with id 0. */
    @Test fun lossOfDatagramIdZeroIsReported() {
        val p = CorePair()
        try {
            val s = quietServer(p)
            val lost = ArrayList<Long>()
            s.datagramSender =
                object : io.kuicksilver.quic.DatagramSender {
                    override fun onTransmit(packet: io.kuicksilver.quic.DatagramPacketWriter) {}

                    override fun hasPending(): Boolean = false

                    override fun onLost(id: Long) {
                        lost += id
                    }
                }
            val pk = maxDataOnlyPacket(s)
            pk.frames.flags = 0
            pk.frames.dgCount = 2
            pk.frames.dgId[0] = 0
            pk.frames.dgId[1] = -1 // not the application's: not reported
            ConnectionLossListener(s).onLost(SpaceId.Application, pk)
            assertEquals(listOf(0L), lost)
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 appendix A.4 ("if marked packets are all declared lost"): ECN fails through loss detection too, and the runtime hears
     * of the failure (onEcnFailed) on that path as well.
     */
    @Test fun negative_ecnFailureByDeclaredLossIsReported() {
        val ecn = IoCapabilities(ecnSend = true, ecnReceive = true, gsoMaxSegments = 1, gro = false, df = false, batch = 1)
        val p = EndpointPair()
        p.serverEcnReceive = true
        p.clientEcnReceive = true
        val c = p.connect()
        c.setPathCapabilities(PathId.Initial, IoCapabilities.Portable)
        try {
            assertTrue(p.confirmed(c))
            c.setPathCapabilities(PathId.Initial, ecn)
            val reported = ArrayList<PathId>()
            c.onEcnFailed = { reported += it }
            p.filterToServer = { i, _ -> p.clientEcnSentAt(i) != io.kuicksilver.quic.Ecn.Ect0 } // marked datagrams vanish
            val id = c.openStream(true)
            var w = 0
            assertTrue(
                p.runUntil(10.seconds) {
                    if (w < 100_000) w += c.writeStream(id, ByteArray(minOf(16384, 100_000 - w)), 0, minOf(16384, 100_000 - w), false)
                    c.stats.ecnState == EcnState.Failed
                },
            )
            assertEquals(listOf(PathId.Initial), reported)
        } finally {
            p.close()
        }
    }
}
