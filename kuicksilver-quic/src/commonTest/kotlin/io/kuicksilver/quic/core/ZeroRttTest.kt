// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.endpoint.ZeroRttReplayRegister
import io.kuicksilver.quic.ksl
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.serverWithKeys
import io.kuicksilver.quic.wire.TransportParametersCodec
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.QuicSessionTicket
import io.kuicksilver.tls.TlsRole
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** 0-RTT in the sans-IO core with the real OpenSSL handshake (RFC 9000 sections 4.6.1, 7.4.1; RFC 9001 sections 4.6, 4.9.3; ADR-0015). */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class ZeroRttTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val register = ZeroRttReplayRegister(Random(5))

    private fun early(
        quic: QuicConfig = QuicConfig.Default,
        app: ByteArray? = null,
    ) = ServerEarlyData.of(quic, CoreFixtures.server().alpn, app, register)

    /** A full handshake that leaves the client a ticket. */
    private fun ticket(serverQuic: QuicConfig = QuicConfig.Default): QuicSessionTicket {
        val p = CorePair(crypto = ksl, clientEarly = EarlyDataState.Allowed, serverEarly = early(serverQuic), serverQuic = serverQuic)
        assertTrue(
            p.handshake(),
            "handshake: ${p.closedReason(p.clientEvents)} / ${p.closedReason(p.serverEvents)} ${p.client.state} ${p.server?.state}",
        )
        assertTrue(p.runUntil(limit = 2.seconds) { p.clientEvents.any { it is ConnectionEvent.SessionTicket } })
        val tickets = p.clientEvents.filterIsInstance<ConnectionEvent.SessionTicket>().map { it.ticket }
        tickets.drop(1).forEach { it.close() }
        p.close()
        return tickets.last().also { assertNotNull(it.remembered, "the server's transport parameters travel with the ticket") }
    }

    private fun streamText(
        core: ConnectionCore,
        id: Long,
    ): String {
        val b = ByteArray(65536)
        var s = ""
        while (true) {
            val n = core.readStream(id, b, 0, b.size)
            if (n <= 0) break
            s += b.decodeToString(0, n)
        }
        return s
    }

    /** Second connection: the request rides 0-RTT; returns the pair and the stream id. */
    private fun resumed(
        ticket: QuicSessionTicket,
        request: String = "GET /index.html",
        serverEarly: ServerEarlyData? = early(),
        serverQuic: QuicConfig = QuicConfig.Default,
        mode: EarlyDataState = EarlyDataState.Allowed,
    ): Pair<CorePair, Long> {
        var id = -1L
        val p =
            CorePair(
                crypto = ksl,
                clientEarly = mode,
                serverEarly = serverEarly,
                serverQuic = serverQuic,
                clientSetup = { c ->
                    assertTrue(c.useTicket(ticket), "0-RTT available with this ticket")
                    id = c.openStream(bidi = true)
                    assertTrue(id >= 0, "remembered stream limits allow a stream before the handshake")
                    assertEquals(request.length, c.writeStream(id, request.encodeToByteArray(), 0, request.length, fin = true))
                },
            )
        return p to id
    }

    @Test fun zeroRttDataAnsweredBeforeHandshakeCompletes() {
        val (p, id) = resumed(ticket())
        var answeredWhile: ConnectionState? = null
        var got = ""
        assertTrue(
            p.runUntil(limit = 3.seconds) {
                val s = p.server
                if (s != null && answeredWhile == null && p.serverEvents.any { it is ConnectionEvent.StreamReadable && it.id == id }) {
                    assertEquals("GET /index.html", streamText(s, id))
                    answeredWhile = s.state
                    s.writeStream(id, "200 OK".encodeToByteArray(), 0, 6, fin = true)
                }
                got += streamText(p.client, id)
                got == "200 OK"
            },
        )
        assertEquals(
            ConnectionState.Handshaking,
            answeredWhile,
            "the server read and answered the 0-RTT request before the client's Finished",
        )
        assertEquals(true, p.client.earlyDataAccepted)
        assertEquals(true, p.server!!.earlyDataAccepted)
        val firstReadable = p.serverEvents.indexOfFirst { it is ConnectionEvent.StreamReadable }
        val accepted = p.serverEvents.indexOfFirst { it is ConnectionEvent.EarlyDataAccepted }
        val completed = p.serverEvents.indexOfFirst { it is ConnectionEvent.HandshakeCompleted }
        assertTrue(accepted in 0 until firstReadable && (completed < 0 || firstReadable < completed), p.serverEvents.toString())
        assertTrue(p.server!!.streamReceivedEarly(id), "the server sees the stream as received in 0-RTT")
        // RFC 9001 section 4.9.3: the client drops its 0-RTT key with the 1-RTT key; the server within 3 PTO of its first 1-RTT packet
        assertNull(p.client.writeKeys[1])
        assertTrue(p.runUntil(limit = 5.seconds) { p.server!!.readKeys[1] == null }, "server 0-RTT read key discarded")
        assertTrue(p.runUntil(limit = 2.seconds) { p.server!!.state == ConnectionState.Confirmed }, "server state ${p.server!!.state}")
        // a stream opened after the handshake still flows
        val id2 = p.client.openStream(bidi = true)
        p.client.writeStream(id2, "later".encodeToByteArray(), 0, 5, fin = true)
        assertTrue(
            p.runUntil(limit = 2.seconds) { p.serverEvents.any { it is ConnectionEvent.StreamReadable && it.id == id2 } },
            "late stream",
        )
        p.close()
    }

    @Test fun zeroRttRejectedRetransmitsIn1Rtt() {
        // the server's application context changed: TLS refuses the early data (RFC 9001 section 4.6.3), the stream goes again in 1-RTT
        val (p, id) = resumed(ticket(), serverEarly = early(app = byteArrayOf(9)))
        var got = ""
        var readWhile: ConnectionState? = null
        assertTrue(
            p.runUntil(limit = 3.seconds) {
                val s = p.server
                if (s != null && readWhile == null && p.serverEvents.any { it is ConnectionEvent.StreamReadable && it.id == id }) {
                    assertEquals("GET /index.html", streamText(s, id))
                    readWhile = s.state
                    s.writeStream(id, "200 OK".encodeToByteArray(), 0, 6, fin = true)
                }
                got += streamText(p.client, id)
                got == "200 OK"
            },
        )
        assertTrue(readWhile != ConnectionState.Handshaking, "a rejected 0-RTT packet is never processed: the data arrived in 1-RTT")
        assertEquals(false, p.client.earlyDataAccepted)
        assertEquals(false, p.server!!.earlyDataAccepted)
        assertTrue(!p.server!!.streamReceivedEarly(id))
        assertNull(p.closedReason(p.clientEvents))
        p.close()
    }

    @Test fun negative_0rttReplayRejected() {
        val (p, id) = resumed(ticket())
        val captured = ArrayList<ByteArray>()
        p.filterToServer = { _, b ->
            captured += b
            true
        }
        assertTrue(p.handshake())
        assertEquals(true, p.server!!.earlyDataAccepted)
        // an attacker replays the client's first flight to the same server: a new connection, the same ClientHello and 0-RTT packets
        val first = PacketBuffer.of(captured[0])
        val replay =
            ConnectionCore.serverWithKeys(
                QuicConfig.Default,
                CoreFixtures.server(),
                ksl,
                CoreFixtures.clientAddr,
                Random(7),
                p.now,
                first,
                captured[0].size,
                null,
                null,
                early = early(),
            )!!
        first.close()
        val events = ArrayList<ConnectionEvent>()
        for (b in captured.take(4)) {
            val buf = PacketBuffer.of(b)
            replay.handleDatagram(buf, b.size, CoreFixtures.clientAddr, Ecn.NotEct, p.now)
            buf.close()
            while (true) events += replay.nextEvent() ?: break
        }
        assertEquals(false, replay.earlyDataAccepted, "the replayed ClientHello gets no early data")
        assertTrue(
            events.none {
                it is ConnectionEvent.StreamOpened || it is ConnectionEvent.StreamReadable
            },
            "nothing of the replay reaches the application",
        )
        assertTrue(!replay.isStreamOpenForTest(id))
        p.close()
    }

    @Test fun negative_0rttTransportParamsReduced() {
        val t = ticket()
        // the client remembers more than the server will grant (as if the server lowered its limits while accepting 0-RTT)
        val tp = TransportParametersCodec.decode(rememberedTp(t.remembered!!), TlsRole.Server)
        tp.initialMaxData = tp.initialMaxData * 4
        t.remembered = withTp(t.remembered!!, TransportParametersCodec.encode(tp, TlsRole.Server, 27))
        val (p, _) = resumed(t)
        assertTrue(p.runUntil(limit = 3.seconds) { p.closedReason(p.clientEvents) != null })
        val r = assertIs<QuicException.ConnectionLost.TransportClosed>(p.closedReason(p.clientEvents))
        assertEquals(TransportError.PROTOCOL_VIOLATION, r.code, r.reason)
        p.close()
    }

    @Test fun rejectedWithSmallerLimitsFailsZeroRttRejected() {
        val big = "x".repeat(4000)
        val (p, _) =
            resumed(
                ticket(),
                request = big,
                serverQuic = quicConfig { initialConnectionWindow = 1000 },
                serverEarly =
                    early(
                        quicConfig {
                            initialConnectionWindow =
                                1000
                        },
                    ),
            )
        assertTrue(p.runUntil(limit = 3.seconds) { p.closedReason(p.clientEvents) != null })
        assertIs<QuicException.ConnectionLost.ZeroRttRejected>(p.closedReason(p.clientEvents))
        p.close()
    }

    @Test fun requiredModeFailsOnRejection() {
        val (p, _) = resumed(ticket(), serverEarly = early(app = byteArrayOf(3)), mode = EarlyDataState.Required)
        assertTrue(p.runUntil(limit = 3.seconds) { p.closedReason(p.clientEvents) != null })
        assertIs<QuicException.ConnectionLost.ZeroRttRejected>(p.closedReason(p.clientEvents))
        p.close()
    }

    @Test fun noEarlyDataWithoutServerOption() {
        val t = ticket()
        val (p, id) = resumed(t, serverEarly = null)
        assertTrue(p.handshake())
        assertEquals(false, p.client.earlyDataAccepted, "a server without 0-RTT refuses (and cannot resume: it has no ticket keys)")
        assertTrue(p.runUntil(limit = 2.seconds) { p.serverEvents.any { it is ConnectionEvent.StreamReadable && it.id == id } })
        p.close()
    }
}
