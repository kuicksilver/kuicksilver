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
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.endpoint.ZeroRttReplayRegister
import io.kuicksilver.quic.ksl
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.serverWithKeys
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.quic.wire.TransportParametersCodec
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.EncryptionLevel
import io.kuicksilver.tls.QuicCrypto
import io.kuicksilver.tls.QuicSessionTicket
import io.kuicksilver.tls.QuicTlsSession
import io.kuicksilver.tls.SessionTicketConfig
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsEvent
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
    private fun ticket(
        serverQuic: QuicConfig = QuicConfig.Default,
        serverTls: TlsConfig = CoreFixtures.server(),
        clientQuic: QuicConfig = QuicConfig.Default,
    ): QuicSessionTicket {
        val p =
            CorePair(
                clientQuic = clientQuic,
                serverTls = serverTls,
                crypto = ksl,
                clientEarly = EarlyDataState.Allowed,
                serverEarly = early(serverQuic),
                serverQuic = serverQuic,
            )
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
        clientQuic: QuicConfig = QuicConfig.Default,
    ): Pair<CorePair, Long> {
        var id = -1L
        val p =
            CorePair(
                clientQuic = clientQuic,
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

    /**
     * Fuzzing finding (rememberedTicket): `QuicSessionTicket.remembered` is a public property, and a blob whose ALPN length
     * runs past its end (or an empty one) threw out of the ticket's use instead of giving no 0-RTT.
     */
    @Test fun negative_malformedRememberedBlobGivesNoEarlyData() {
        assertNull(rememberedParameters(ByteArray(0)))
        assertNull(rememberedParameters(byteArrayOf(5, 'h'.code.toByte(), '3'.code.toByte())))
        assertNull(rememberedParameters(byteArrayOf(0xff.toByte())))
        assertNull(rememberedParameters(byteArrayOf(0, 0, 0, 1, 5, 'h'.code.toByte(), '3'.code.toByte())))
        assertNotNull(rememberedParameters(rememberedBlob(1, "h3", ByteArray(0))))
    }

    /**
     * RFC 9000 section 14.1: a client MUST expand every datagram carrying Initial packets to 1200 bytes. With 0-RTT stream data
     * queued, the ClientHello is grown (as a long ALPN or SNI list would) so its last Initial ends at offsets throughout the last
     * 64 bytes before 1200, where the 0-RTT packet no longer fits behind it: the datagram must still reach 1200 bytes.
     */
    @Test fun negative_initialFollowedByZeroRttThatDoesNotFitIsPadded() {
        // the client's first flight with [extra] CRYPTO bytes added to the ClientHello: the long-header packets of each datagram
        fun firstFlight(extra: Int): List<Pair<Int, List<Pair<PacketType?, Int>>>> {
            val (p, _) = resumed(ticket())
            try {
                p.client.testInjectCrypto = Triple(0, 20_000L, extra)
                p.poll(p.client, p.toServer, CoreFixtures.clientAddr, toServer = true)
                return p.toServer.map { d -> d.bytes.size to longHeaderPackets(d.bytes) }
            } finally {
                p.close()
            }
        }
        // where the last Initial ends when it has room for the 0-RTT packet behind it (the Length field is not protected)
        val base = firstFlight(100).last().second
        assertEquals(PacketType.ZeroRtt, base.last().first, "0-RTT data rides with the Initial: $base")
        val initialEnd = base.last { it.first == PacketType.Initial }.second
        for (end in listOf(1137, 1170, 1199)) {
            val flight = firstFlight(100 + end - initialEnd)
            for ((size, packets) in flight) {
                if (packets.any { it.first == PacketType.Initial }) {
                    assertTrue(size >= 1200, "Initial meant to end at $end: datagram of $size bytes, $packets")
                }
            }
        }
    }

    /** The type and end offset of each coalesced long-header packet in [bytes]. */
    private fun longHeaderPackets(bytes: ByteArray): List<Pair<PacketType?, Int>> {
        val b = PacketBuffer.of(bytes)
        try {
            val v = PacketHeaderView()
            val out = ArrayList<Pair<PacketType?, Int>>()
            var off = 0
            while (off < bytes.size && bytes[off].toInt() and 0x80 != 0 && PacketHeaderCodec.parse(b, off, bytes.size, 8, v)) {
                out += v.type to v.packetEnd
                off = v.packetEnd
            }
            return out
        } finally {
            b.close()
        }
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

    /** RFC 9221 section 3: a stored max_datagram_frame_size must not shrink when the server accepts 0-RTT. */
    @Test fun negative_0rttMaxDatagramFrameSizeReduced() {
        val t = ticket()
        val tp = TransportParametersCodec.decode(rememberedTp(t.remembered!!), TlsRole.Server)
        tp.maxDatagramFrameSize = tp.maxDatagramFrameSize + 1200
        t.remembered = withTp(t.remembered!!, TransportParametersCodec.encode(tp, TlsRole.Server, 27))
        val (p, _) = resumed(t)
        assertTrue(p.runUntil(limit = 3.seconds) { p.closedReason(p.clientEvents) != null })
        val r = assertIs<QuicException.ConnectionLost.TransportClosed>(p.closedReason(p.clientEvents))
        assertEquals(TransportError.PROTOCOL_VIOLATION, r.code, r.reason)
        p.close()
    }

    /**
     * RFC 9000 section 7.4.1: "When sending frames in 0-RTT packets, a client MUST only use remembered transport parameters";
     * the server's new ones apply from 1-RTT on.
     */
    @Test fun zeroRttKeepsRememberedLimitsUntilOneRtt() {
        val t = ticket()
        val tp = TransportParametersCodec.decode(rememberedTp(t.remembered!!), TlsRole.Server)
        tp.initialMaxData = 2000
        t.remembered = withTp(t.remembered!!, TransportParametersCodec.encode(tp, TlsRole.Server, 27))
        val (p, _) = resumed(t, request = "x")
        try {
            val c = p.client
            p.filterToServer = { _, _ -> false }
            p.step() // the client drives TLS: ClientHello and the 0-RTT key
            assertEquals(2000L, c.connSend.maxLimit)
            // the server's EncryptedExtensions before its Finished: 0-RTT keeps the remembered limit
            tp.initialMaxData = 1_000_000
            tp.originalDestinationConnectionId = c.odcid
            tp.initialSourceConnectionId = c.remoteCid
            ConnectionHandshakeSink(c).onPeerTransportParameters(TransportParametersCodec.encode(tp, TlsRole.Server, 27), c.version.version)
            assertTrue(c.writeKeys[1] != null && c.writeKeys[3] == null, "still sending 0-RTT")
            assertEquals(2000L, c.connSend.maxLimit, "0-RTT uses only the remembered limit")
        } finally {
            p.close()
        }
        val (q, _) = resumed(t2(), request = "x")
        try {
            assertTrue(q.handshake())
            assertEquals(true, q.client.earlyDataAccepted)
            assertEquals(QuicConfig.Default.initialConnectionWindow, q.client.connSend.maxLimit, "1-RTT gets the server's new limit")
        } finally {
            q.close()
        }
    }

    private fun t2(): QuicSessionTicket {
        val t = ticket()
        val tp = TransportParametersCodec.decode(rememberedTp(t.remembered!!), TlsRole.Server)
        tp.initialMaxData = 2000
        t.remembered = withTp(t.remembered!!, TransportParametersCodec.encode(tp, TlsRole.Server, 27))
        return t
    }

    private val v1v2 = quicConfig { versions = listOf(VersionProfile.V1, VersionProfile.V2) }
    private val v2v1 = quicConfig { versions = listOf(VersionProfile.V2, VersionProfile.V1) }

    /**
     * RFC 9369 section 4.1: across a compatible upgrade from v1 to v2 the client keeps sending 0-RTT in v1 ("MUST NOT send
     * 0-RTT packets using the negotiated version") and the server takes it with v1 keys.
     */
    @Test fun zeroRttStaysInTheOriginalVersionAcrossAnUpgrade() {
        val t = ticket() // a v1 server: a v1 ticket
        val (p, id) = resumed(t, clientQuic = v1v2, serverQuic = v2v1, serverEarly = early(v2v1))
        try {
            assertTrue(p.handshake(), "${p.closedReason(p.clientEvents)} / ${p.closedReason(p.serverEvents)}")
            assertEquals(VersionProfile.V2, p.server!!.version, "upgraded to v2")
            assertEquals(VersionProfile.V2, p.client.version)
            assertEquals(true, p.client.earlyDataAccepted)
            assertTrue(p.server!!.streamReceivedEarly(id), "the request arrived in 0-RTT")
            assertEquals("GET /index.html", streamText(p.server!!, id))
        } finally {
            p.close()
        }
    }

    /** RFC 9369 section 5: a ticket belongs to the negotiated version of its connection and is not used to start another. */
    @Test fun negative_ticketOfAnotherVersionIsNotUsed() {
        for ((start, used) in listOf(v1v2 to false, v2v1 to true)) {
            val t = ticket(serverQuic = v2v1, clientQuic = v1v2) // upgraded to v2: a v2 ticket
            var took: Boolean? = null
            val p =
                CorePair(
                    clientQuic = start,
                    serverQuic = v2v1,
                    crypto = ksl,
                    clientEarly = EarlyDataState.Allowed,
                    serverEarly = early(v2v1),
                    clientSetup = { c -> took = c.useTicket(t) },
                )
            try {
                assertEquals(used, took, "a v2 ticket for a connection starting in ${start.versions.first()}")
                assertTrue(p.handshake())
                assertEquals(used, p.client.earlyDataAccepted == true, "0-RTT only with the ticket of our version")
            } finally {
                p.close()
            }
        }
    }

    /**
     * RFC 9001 section 4.6.1: a NewSessionTicket whose early_data extension carries any max_early_data_size other than
     * 0xffffffff is a PROTOCOL_VIOLATION (OpenSSL reports it as illegal_parameter).
     */
    @Test fun negative_invalidMaxEarlyDataIsProtocolViolation() {
        val p =
            CorePair(
                crypto = WithMaxEarlyData(ksl, 0x4000),
                clientEarly = EarlyDataState.Allowed,
                serverEarly = early(),
            )
        try {
            p.runUntil(limit = 3.seconds) { p.closedReason(p.clientEvents) != null }
            val r = assertIs<QuicException.ConnectionLost.TransportClosed>(p.closedReason(p.clientEvents))
            assertEquals(TransportError.PROTOCOL_VIOLATION, r.code, r.reason)
        } finally {
            p.close()
        }
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

    /** The client's first flight of a 0-RTT connection with [ticket], captured and kept from the server. */
    private fun firstFlight(ticket: QuicSessionTicket): List<ByteArray> {
        val (p, _) = resumed(ticket)
        val captured = ArrayList<ByteArray>()
        p.filterToServer = { _, b ->
            captured += b
            false
        }
        p.step()
        p.close()
        return captured
    }

    /** A new server connection fed [flight] (as an endpoint would create it) and the events it raised. */
    private fun serverFor(
        flight: List<ByteArray>,
        early: ServerEarlyData,
        now: TimeMark = TimeMark(1_000_000_000L),
    ): Pair<ConnectionCore, List<ConnectionEvent>> {
        val first = PacketBuffer.of(flight[0])
        val s =
            ConnectionCore.serverWithKeys(
                QuicConfig.Default,
                CoreFixtures.server(),
                ksl,
                CoreFixtures.clientAddr,
                Random(9),
                now,
                first,
                flight[0].size,
                null,
                null,
                early = early,
            )!!
        first.close()
        val events = ArrayList<ConnectionEvent>()
        for (b in flight) {
            val buf = PacketBuffer.of(b)
            s.handleDatagram(buf, b.size, CoreFixtures.clientAddr, Ecn.NotEct, now)
            buf.close()
            while (true) events += s.nextEvent() ?: break
        }
        return s to events
    }

    @Test fun negative_forgedHellosDoNotFillTheRegister() {
        // a hello whose ticket this server cannot decrypt (another key set: a forged identity) gets no early data and leaves no entry
        val foreign = ticket(serverTls = CoreFixtures.server { sessionTickets = SessionTicketConfig(keys = listOf(ByteArray(80) { 7 })) })
        val (forged, _) = serverFor(firstFlight(foreign), early())
        assertEquals(false, forged.earlyDataAccepted)
        assertEquals(0, register.liveForTest(), "the forged identity left the register when TLS refused its early data")
        forged.close(0, "", TimeMark(1_000_000_000L))
        // a flood of forged identities, each refused by TLS after the register saw it (the scan precedes ticket decryption)
        val r = Random(11)
        repeat(100_000) {
            val id = r.nextBytes(32)
            assertTrue(register.admit(id, TimeMark(1_000_000_000L)), "a fresh identity is admitted until TLS refuses it")
            register.release(id)
        }
        // a legitimate 0-RTT connection still gets its early data
        val (p, id) = resumed(ticket())
        assertTrue(p.runUntil(limit = 3.seconds) { p.server?.streamReceivedEarly(id) == true || p.client.earlyDataAccepted != null })
        assertEquals(true, p.server!!.earlyDataAccepted, "the register still has room for real tickets")
        p.close()
    }

    @Test fun concurrentSameTicketGetsEarlyDataOnce() {
        // two hellos with the same valid ticket (the original and a replay racing it to two loops or endpoints): one gets early data
        val flight = firstFlight(ticket())
        val (a, aEvents) = serverFor(flight, early())
        val (b, bEvents) = serverFor(flight, early())
        assertEquals(listOf(true, false), listOf(a.earlyDataAccepted, b.earlyDataAccepted), "exactly one connection gets early data")
        assertTrue(aEvents.any { it is ConnectionEvent.StreamReadable }, "the admitted one reads its request")
        assertTrue(bEvents.none { it is ConnectionEvent.StreamOpened || it is ConnectionEvent.StreamReadable }, "the other reads nothing")
    }

    @Test fun rejectedZeroRttAdoptsLowerLimits() {
        // the server restarted with lower limits (so it also refuses the ticket's early data): the client must not keep the
        // remembered ones (RFC 9000 section 7.4.1), or it would exceed the new limits (FLOW_CONTROL_ERROR / STREAM_LIMIT_ERROR)
        val lower =
            quicConfig {
                initialConnectionWindow = 1000
                initialStreamWindow = 1500
                maxBidiStreams = 2
            }
        val (p, id) = resumed(ticket(), request = "GET /a", serverQuic = lower, serverEarly = early(lower))
        assertTrue(p.handshake())
        assertEquals(false, p.client.earlyDataAccepted)
        // the application never reads: only the transport's limits hold the client back
        val big = ByteArray(3000) { 'y'.code.toByte() }
        val more = List(3) { p.client.openStream(bidi = true) }
        assertEquals(listOf(true, false, false), more.map { it >= 0 }, "one more stream than the early one: the new limit is 2")
        p.client.writeStream(more[0], big, 0, big.size, fin = false) // more than the new 1500-byte stream window
        p.runUntil(limit = 2.seconds) { p.closedReason(p.serverEvents) != null || p.closedReason(p.clientEvents) != null }
        assertNull(p.closedReason(p.serverEvents), "the server saw no limit violation")
        assertNull(p.closedReason(p.clientEvents))
        assertTrue(
            p.serverEvents.any { it is ConnectionEvent.StreamReadable && it.id == more[0] },
            "traffic continues within the new limits",
        )
        p.close()
    }
}

/** A server whose NewSessionTickets announce [max] in their early_data extension instead of 0xffffffff. */
private class WithMaxEarlyData(
    private val inner: QuicCrypto,
    private val max: Int,
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
        if (config.role != TlsRole.Server) {
            s
        } else {
            object : QuicTlsSession by s {
                override fun nextEvent(): TlsEvent? {
                    val e = s.nextEvent()
                    if (e !is TlsEvent.CryptoData || e.level != EncryptionLevel.Application) return e
                    return TlsEvent.CryptoData(e.level, patch(e.data.copyOf()))
                }
            }
        }

    /** Walks the NewSessionTicket messages (RFC 8446 section 4.6.1) and rewrites each early_data extension's value. */
    private fun patch(d: ByteArray): ByteArray {
        fun u(
            at: Int,
            n: Int,
        ): Int {
            var v = 0
            for (i in 0 until n) v = (v shl 8) or (d[at + i].toInt() and 0xff)
            return v
        }
        var m = 0
        while (m + 4 <= d.size) {
            val end = m + 4 + u(m + 1, 3)
            if (d[m].toInt() == 4) {
                var p = m + 4 + 8
                p += 1 + u(p, 1) // nonce
                p += 2 + u(p, 2) // ticket
                val extEnd = p + 2 + u(p, 2)
                p += 2
                while (p + 4 <= extEnd) {
                    val type = u(p, 2)
                    val len = u(p + 2, 2)
                    if (type == 0x2a && len == 4) {
                        for (i in 0 until 4) d[p + 4 + i] = (max ushr (24 - 8 * i)).toByte()
                    }
                    p += 4 + len
                }
            }
            m = end
        }
        return d
    }
}
