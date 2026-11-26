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
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.quic.wire.TransportParameters
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
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
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

    /** Server cores a test made on their own (no pair closes them): released after it, with their TLS sessions and keys. */
    private val made = ArrayList<ConnectionCore>()

    @AfterTest fun releaseCores() {
        for (c in made) c.release()
    }

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
        tickets.dropLast(1).forEach { it.close() }
        p.keep(tickets.last())
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
        // a parameters length that runs past the end
        assertNull(rememberedParameters(byteArrayOf(0, 0, 0, 1, 0, 0, 0, 0, 9)))
    }

    /**
     * What the application keeps with a ticket (HTTP/3: the server's SETTINGS, RFC 9114 section 7.2.4.2) rides after the
     * transport parameters: it survives replacing them, it can be set afterwards, and the parameters still parse.
     */
    @Test fun applicationDataRidesWithTheRememberedParameters() {
        val tp = TransportParametersCodec.encode(TransportParameters().also { it.initialMaxData = 1234 }, TlsRole.Server, 27)
        val plain = rememberedBlob(1, "h3", tp)
        assertNull(rememberedApplication(plain))
        val app = byteArrayOf(1, 2, 3)
        val blob = withApplication(plain, app)
        assertContentEquals(app, rememberedApplication(blob!!))
        assertEquals(1234L, rememberedParameters(blob)!!.third.initialMaxData)
        assertEquals("h3", rememberedParameters(blob)!!.second)
        val tp2 = TransportParametersCodec.encode(TransportParameters().also { it.initialMaxData = 99 }, TlsRole.Server, 27)
        // a blob that is not ours (`remembered` is public) is left alone, never a failure on the loop
        for (foreign in listOf(
            ByteArray(0),
            byteArrayOf(1, 2, 3),
            byteArrayOf(0, 0, 0, 1, 9, 'h'.code.toByte()),
            byteArrayOf(0, 0, 0, 1, 0, 0, 0, 0, 9),
        )) {
            assertNull(withApplication(foreign, app))
            assertNull(rememberedApplication(foreign))
        }
        val replaced = withTp(blob, tp2)
        assertContentEquals(app, rememberedApplication(replaced))
        assertEquals(99L, rememberedParameters(replaced)!!.third.initialMaxData)
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
            p.use { _ ->
                p.client.testInjectCrypto = Triple(0, 20_000L, extra)
                p.poll(p.client, p.toServer, CoreFixtures.clientAddr, toServer = true)
                return p.toServer.map { d -> d.bytes.size to longHeaderPackets(d.bytes) }
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

    /**
     * The final size of a stream sent in 0-RTT stands only once the server accepted it: reported then, once (the FIN went
     * out in 0-RTT).
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun zeroRttFinalSizeReportedOnceAccepted() {
        val (p, id) = resumed(ticket())
        assertTrue(p.handshake())
        assertEquals(true, p.client.earlyDataAccepted)
        val finals = p.clientEvents.filterIsInstance<ConnectionEvent.StreamFinalSize>().filter { it.id == id && it.sending }
        assertEquals(listOf(15L), finals.map { it.size })
        p.close()
    }

    /**
     * A uni stream reset in 0-RTT is done on our side at once, but its size stands only with the server's answer: the
     * StreamFinished waits with it, so the runtime still holds the stream when the size stands or falls.
     */
    private fun resetEarlyUni(
        ticket: QuicSessionTicket,
        serverEarly: ServerEarlyData? = early(),
        serverQuic: QuicConfig = QuicConfig.Default,
        clientQuic: QuicConfig = QuicConfig.Default,
        mode: EarlyDataState = EarlyDataState.Allowed,
        reliable: Long? = null,
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
                    assertTrue(c.useTicket(ticket))
                    id = c.openStream(bidi = false)
                    c.writeStream(id, "early".encodeToByteArray(), 0, 5, fin = false)
                },
            )
        // the bytes go out in 0-RTT, then the reset, before the handshake completes
        p.step()
        if (reliable == null) p.client.resetStream(id, 4) else p.client.resetStreamAt(id, 4, reliable)
        p.step()
        assertTrue(p.clientEvents.none { it is ConnectionEvent.StreamFinished && it.id == id }, "nothing of the stream before the answer")
        return p to id
    }

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private fun List<ConnectionEvent>.ofStream(id: Long): List<String> =
        mapNotNull {
            when {
                it is ConnectionEvent.StreamFinalSize && it.id == id && it.sending -> "size ${it.size}"
                it is ConnectionEvent.StreamFinished && it.id == id -> "finished"
                else -> null
            }
        }

    @Test fun earlyStreamResetBeforeTheAnswerReportsItsSizeThenItsEndOnAccept() {
        val (p, id) = resetEarlyUni(ticket())
        p.use { _ ->
            assertTrue(p.handshake())
            assertEquals(true, p.client.earlyDataAccepted)
            assertTrue(p.runUntil(limit = 2.seconds) { p.clientEvents.ofStream(id).isNotEmpty() })
            assertEquals(listOf("size 5", "finished"), p.clientEvents.ofStream(id))
        }
    }

    @Test fun negative_earlyStreamResetBeforeTheAnswerReportsNothingOnReject() {
        val (p, id) = resetEarlyUni(ticket(), serverEarly = early(app = byteArrayOf(9)))
        p.use { _ ->
            assertTrue(p.handshake())
            assertEquals(false, p.client.earlyDataAccepted)
            p.runUntil(limit = 1.seconds) { false }
            assertEquals(emptyList(), p.clientEvents.ofStream(id))
            assertEquals(0, p.client.streams.sizesForTest()[5], "nothing held after the answer")
        }
    }

    /**
     * The held final size and StreamFinished of a 0-RTT stream are in the 0-RTT answer's one queue (`heldUntilAnswer`), in
     * order, so the 0-RTT invariant counts them: what [held] returns, before the answer. A stream we reset is reported
     * finished only once the reset is acknowledged, which a 0-RTT packet's never is before the answer: before it only the
     * size is held.
     */
    private fun heldOf(
        p: CorePair,
        id: Long,
    ): List<String> {
        assertEquals(null, p.client.earlyDataAccepted, "no answer yet")
        assertTrue(p.client.streams.zeroRttPending)
        val held = p.client.streams.heldUntilAnswer
        return held.ofStream(id)
    }

    /** After the answer or the end: nothing held, no stream named by a hold, and the hold is over. */
    private fun assertNothingHeld(p: CorePair) {
        assertEquals(0, p.client.zeroRttHeldForTest(), "nothing held for the answer")
        assertEquals(0, p.client.streams.sizesForTest()[5], "no held event and no stream named by one")
        assertFalse(p.client.streams.zeroRttPending, "the hold is over")
    }

    @Test fun heldFinalSizeOfA0RttStreamIsSettledInOrderByAnAcceptance() {
        val (p, id) = resetEarlyUni(ticket())
        p.use { _ ->
            assertEquals(listOf("size 5"), heldOf(p, id))
            assertTrue(p.handshake())
            assertEquals(true, p.client.earlyDataAccepted)
            assertNothingHeld(p)
            assertEquals(listOf("size 5"), p.clientEvents.ofStream(id), "the size stands at the answer")
            // the stream is finished once the server acknowledged our reset, after the answer
            assertTrue(p.runUntil(limit = 2.seconds) { "finished" in p.clientEvents.ofStream(id) })
            assertNothingHeld(p)
            assertEquals(listOf("size 5", "finished"), p.clientEvents.ofStream(id))
        }
    }

    /**
     * A 0-RTT stream retired by our reset before the answer, the reset never acknowledged (nothing of ours reaches the server
     * after the first flight): the runtime keeps its wrapper while the size is held, so it skips the stream that
     * `takeRetiredAwaitingAck` offered at the reset. The acceptance reports the size and offers the stream once more, so the
     * wrapper goes then and not only at the acknowledgment or the connection's end; the reset still waits for its
     * acknowledgment (RFC 9000 section 13.3), and the stream is reported finished only then.
     */
    @Test fun earlyStreamRetiredBeforeTheAnswerIsOfferedAgainAtTheAcceptance() {
        var id = -1L
        val p =
            CorePair(
                crypto = ksl,
                clientEarly = EarlyDataState.Allowed,
                serverEarly = early(),
                clientSetup = { c ->
                    assertTrue(c.useTicket(ticket()))
                    id = c.openStream(bidi = false)
                    c.writeStream(id, "early".encodeToByteArray(), 0, 5, fin = false)
                },
            )
        p.use { _ ->
            p.step() // the ClientHello and the 0-RTT bytes go out
            p.filterToServer = { _, _ -> false }
            p.client.resetStream(id, 4)
            p.step()
            assertEquals(listOf(id), p.client.streams.takeRetiredAwaitingAck(), "retired at the reset")
            assertTrue(p.client.streams.heldForAnswer(id), "its size is held for the answer: the runtime keeps the wrapper")
            assertTrue(p.runUntil(limit = 2.seconds) { p.client.earlyDataAccepted != null })
            assertEquals(true, p.client.earlyDataAccepted)
            assertEquals(listOf("size 5"), p.clientEvents.ofStream(id), "the size stands at the answer")
            assertFalse(p.client.streams.heldForAnswer(id))
            assertEquals(listOf(id), p.client.streams.takeRetiredAwaitingAck(), "offered again once its size stood")
            assertEquals(null, p.client.streams.takeRetiredAwaitingAck(), "offered once")
            assertEquals(1, p.client.streams.resetAcksPendingForTest()[1], "the report still waits for the acknowledgment")
            p.runUntil(limit = 1.seconds) { false }
            assertEquals(listOf("size 5"), p.clientEvents.ofStream(id), "not finished while the reset is unacknowledged")
        }
    }

    /** Splits a datagram into its long header packets (QUIC v1) and the short header packet that ends it, if any. */
    private fun splitPackets(d: ByteArray): Pair<ByteArray, ByteArray> {
        var off = 0

        fun varint(): Long {
            val first = d[off].toInt() and 0xff
            val len = 1 shl (first ushr 6)
            var v = (first and 0x3f).toLong()
            for (i in 1 until len) v = (v shl 8) or (d[off + i].toLong() and 0xff)
            off += len
            return v
        }
        while (off < d.size && d[off].toInt() and 0x80 != 0) {
            val type = (d[off].toInt() ushr 4) and 3
            off += 5
            off += 1 + (d[off].toInt() and 0xff)
            off += 1 + (d[off].toInt() and 0xff)
            if (type == 0) off += varint().toInt()
            off += varint().toInt()
        }
        return d.copyOfRange(0, off) to d.copyOfRange(off, d.size)
    }

    /**
     * The server's acknowledgment of our 0-RTT reset arrives in a 1-RTT packet the client reads before the handshake completes
     * (it came ahead of the server's Handshake flight and waited for the 1-RTT keys, which come with the server's Finished,
     * before the answer is settled): the StreamFinished the acknowledgment raises is held after the size, and both are
     * reported, in that order, by the acceptance.
     */
    @Test fun earlyResetAcknowledgedBeforeTheAnswerHasItsEndHeldAfterItsSize() {
        var id = -1L
        val p =
            CorePair(
                crypto = ksl,
                clientEarly = EarlyDataState.Allowed,
                serverEarly = early(),
                clientSetup = { c ->
                    assertTrue(c.useTicket(ticket()))
                    id = c.openStream(bidi = false)
                    c.writeStream(id, "early".encodeToByteArray(), 0, 5, fin = false)
                },
            )
        p.use { _ ->
            val toClient = ArrayList<ByteArray>()
            p.filterToClient = { _, bytes ->
                toClient += bytes
                false
            }
            p.step()
            p.client.resetStream(id, 4)
            assertTrue(p.runUntil(limit = 2.seconds) { p.serverEvents.any { it is ConnectionEvent.StreamReset && it.id == id } })
            p.runUntil(limit = 100.milliseconds) { false } // the server's acknowledgment goes out (max_ack_delay)
            assertEquals(null, p.client.earlyDataAccepted, "no answer yet")
            assertEquals(
                listOf("size 5"),
                p.client.streams.heldUntilAnswer
                    .ofStream(id),
            )
            val parts = toClient.map { splitPackets(it) }
            val reordered = parts.map { it.second }.filter { it.isNotEmpty() } + parts.map { it.first }.filter { it.isNotEmpty() }
            for (d in reordered) {
                val b = PacketBuffer.of(d)
                try {
                    p.client.handleDatagram(b, d.size, CoreFixtures.serverAddr, Ecn.NotEct, p.now)
                } finally {
                    b.close()
                }
            }
            p.drainEvents(p.client, p.clientEvents)
            val info =
                "short=${parts.count { it.second.isNotEmpty() }} long=${parts.count { it.first.isNotEmpty() }} " +
                    "buffered=${p.client.receiver.bufferedCount} state=${p.client.state}"
            // the rest of the handshake as it comes
            p.filterToClient = { _, _ -> true }
            if (p.client.earlyDataAccepted == null) assertTrue(p.runUntil(limit = 2.seconds) { p.client.earlyDataAccepted != null }, info)
            assertEquals(true, p.client.earlyDataAccepted, "${p.closedReason(p.clientEvents)} $info")
            // raised before the size was reported, the end would come first: held after it, it comes second
            assertEquals(listOf("size 5", "finished"), p.clientEvents.ofStream(id), info)
            assertNothingHeld(p)
            assertEquals(
                0,
                p.client.streams
                    .resetAcksPendingForTest()
                    .sum(),
                "the reset was acknowledged",
            )
        }
    }

    @Test fun negative_heldFinalSizeOfA0RttStreamIsDroppedByARejection() {
        val (p, id) = resetEarlyUni(ticket(), serverEarly = early(app = byteArrayOf(9)))
        p.use { _ ->
            assertEquals(listOf("size 5"), heldOf(p, id))
            assertTrue(p.handshake())
            assertEquals(false, p.client.earlyDataAccepted)
            assertNothingHeld(p)
            p.runUntil(limit = 1.seconds) { false }
            assertEquals(emptyList(), p.clientEvents.ofStream(id))
            assertNothingHeld(p)
        }
    }

    /** Accepted with lower limits: the connection fails before what was held stands; it is dropped once, never reported. */
    @Test fun negative_heldFinalSizeOfA0RttStreamIsDroppedWhenTheAcceptanceFails() {
        val (p, id) = resetEarlyUni(t2Lowered())
        p.use { _ ->
            assertEquals(listOf("size 5"), heldOf(p, id))
            assertTrue(p.runUntil(limit = 3.seconds) { p.closedReason(p.clientEvents) != null })
            assertIs<QuicException.ConnectionLost.TransportClosed>(p.closedReason(p.clientEvents))
            assertNothingHeld(p)
            assertEquals(emptyList(), p.clientEvents.ofStream(id))
        }
    }

    /**
     * The connection ends before the server answers: the answer never comes and counts as no acceptance, so the held size
     * and end are dropped and the hold ends (before, they stayed held, and a later final size was held too).
     */
    @Test fun negative_heldFinalSizeOfA0RttStreamIsDroppedWhenTheConnectionEndsBeforeTheAnswer() {
        val (p, id) = resetEarlyUni(ticket())
        p.use { _ ->
            assertEquals(listOf("size 5"), heldOf(p, id))
            p.client.close(0, "end", p.now)
            assertNothingHeld(p)
            p.runUntil(limit = 2.seconds) { false }
            assertEquals(emptyList(), p.clientEvents.ofStream(id))
            assertNothingHeld(p)
        }
    }

    /**
     * A Stateless Reset can end the connection before the 0-RTT answer: the server's stateless_reset_token arrives in
     * EncryptedExtensions, the answer only with the handshake's end (its Finished), and a server flight split over datagrams (here
     * a full handshake with its certificate: a server without 0-RTT cannot resume) leaves a gap between the two in which a reset
     * matches (RFC 9000 section 10.3: a reset may answer a long header packet too). The answer never comes and counts as no
     * acceptance: what the 0-RTT stream held is dropped and the hold ends.
     */
    @Test fun negative_heldFinalSizeOfA0RttStreamIsDroppedByAStatelessResetBeforeTheAnswer() {
        var id = -1L
        val p =
            CorePair(
                crypto = ksl,
                clientEarly = EarlyDataState.Allowed,
                serverEarly = null,
                serverTls =
                    CoreFixtures.server(
                        chain =
                            listOf(io.kuicksilver.quic.TestCerts.server) + List(4) { io.kuicksilver.quic.TestCerts.testCa },
                    ) {
                        // the repeated certificates compress to one datagram (RFC 8879): the flight must stay split
                        certificateCompression = false
                    },
                clientSetup = { c ->
                    assertTrue(c.useTicket(ticket()))
                    id = c.openStream(bidi = false)
                    c.writeStream(id, "early".encodeToByteArray(), 0, 5, fin = false)
                },
            )
        p.use { _ ->
            val toClient = ArrayList<ByteArray>()
            p.filterToClient = { _, bytes ->
                toClient += bytes
                false
            }
            p.step()
            p.client.resetStream(id, 4)
            p.step()
            assertEquals(listOf("size 5"), heldOf(p, id)) // finished only once the reset is acknowledged
            // the server's datagrams one by one, until the client knows the reset token but not the answer
            var fed = 0
            while (p.client.peerTp?.statelessResetToken == null && fed < 50) {
                // more of the server's flight comes as the client's acknowledgements lift its amplification limit
                if (fed == toClient.size && !p.runUntil(limit = 1.seconds) { toClient.size > fed }) break
                val d = toClient[fed++]
                val b = PacketBuffer.of(d)
                try {
                    p.client.handleDatagram(b, d.size, CoreFixtures.serverAddr, Ecn.NotEct, p.now)
                } finally {
                    b.close()
                }
                p.step() // the client acknowledges: it sends to the server's connection ID, whose reset token then counts
            }
            val token = assertNotNull(p.client.peerTp?.statelessResetToken, "EncryptedExtensions arrived (fed $fed of ${toClient.size})")
            // TLS may know the refusal already (ServerHello without the PSK); the hold ends only with the handshake (settleZeroRtt)
            assertEquals(ConnectionState.Handshaking, p.client.state, "after $fed of ${toClient.size} datagrams")
            assertTrue(p.client.streams.zeroRttPending)
            assertEquals(
                listOf("size 5"),
                p.client.streams.heldUntilAnswer
                    .ofStream(id),
            )
            val reset = ByteArray(40) { (0x40 + it).toByte() } // a short header the client cannot read, ending with the token
            token.copyInto(reset, reset.size - 16)
            val b = PacketBuffer.of(reset)
            try {
                p.client.handleDatagram(b, reset.size, CoreFixtures.serverAddr, Ecn.NotEct, p.now)
            } finally {
                b.close()
            }
            p.drainEvents(p.client, p.clientEvents)
            assertIs<QuicException.ConnectionLost.StatelessReset>(p.closedReason(p.clientEvents))
            assertNothingHeld(p)
            assertEquals(emptyList(), p.clientEvents.ofStream(id))
        }
    }

    /** RESET_STREAM_AT with reliable size 0 (WebTransport's reset of a stream without header) waits the same way. */
    @Test fun earlyStreamResetAtZeroReportsItsSizeThenItsEndOnAccept() {
        val withAt = quicConfig { resetStreamAt = true }
        val (p, id) = resetEarlyUni(ticket(serverQuic = withAt, clientQuic = withAt), early(withAt), withAt, withAt, reliable = 0)
        p.use { _ ->
            assertTrue(p.handshake())
            assertEquals(true, p.client.earlyDataAccepted)
            assertTrue(p.runUntil(limit = 2.seconds) { "finished" in p.clientEvents.ofStream(id) })
            assertEquals(listOf("size 5", "finished"), p.clientEvents.ofStream(id))
        }
    }

    /** Accepted with lower limits: the connection fails, and nothing of the 0-RTT stream is reported. */
    @Test fun negative_earlyStreamOfAnAcceptedThenFailedConnectionReportsNothing() {
        val (p, id) = resetEarlyUni(t2Lowered())
        p.use { _ ->
            p.runUntil(limit = 3.seconds) { p.closedReason(p.clientEvents) != null }
            assertIs<QuicException.ConnectionLost.TransportClosed>(p.closedReason(p.clientEvents))
            assertEquals(emptyList(), p.clientEvents.ofStream(id))
        }
    }

    /** Required mode and a rejection: the connection closes, nothing of the stream is reported. */
    @Test fun negative_earlyStreamOfARequiredRejectionReportsNothing() {
        val (p, id) = resetEarlyUni(ticket(), serverEarly = early(app = byteArrayOf(3)), mode = EarlyDataState.Required)
        p.use { _ ->
            assertTrue(p.runUntil(limit = 3.seconds) { p.closedReason(p.clientEvents) != null })
            assertEquals(emptyList(), p.clientEvents.ofStream(id))
        }
    }

    /** Across a compatible version upgrade (RFC 9369) the held size and end come once, in order. */
    @Test fun earlyStreamResetAcrossAVersionUpgradeIsReportedOnce() {
        val (p, id) = resetEarlyUni(ticket(), early(v2v1), v2v1, v1v2)
        p.use { _ ->
            assertTrue(p.handshake(), "${p.closedReason(p.clientEvents)} / ${p.closedReason(p.serverEvents)}")
            assertEquals(VersionProfile.V2, p.client.version)
            assertTrue(p.runUntil(limit = 2.seconds) { "finished" in p.clientEvents.ofStream(id) })
            assertEquals(listOf("size 5", "finished"), p.clientEvents.ofStream(id))
        }
    }

    /** A bidi stream sent and reset in 0-RTT; with [stop], its receiving half is stopped before the answer too. */
    private fun resetEarlyBidi(
        ticket: QuicSessionTicket,
        serverEarly: ServerEarlyData? = early(),
        stop: Boolean,
    ): Pair<CorePair, Long> {
        var id = -1L
        val p =
            CorePair(
                crypto = ksl,
                clientEarly = EarlyDataState.Allowed,
                serverEarly = serverEarly,
                clientSetup = { c ->
                    assertTrue(c.useTicket(ticket))
                    id = c.openStream(bidi = true)
                    c.writeStream(id, "early".encodeToByteArray(), 0, 5, fin = false)
                },
            )
        p.step()
        p.client.resetStream(id, 4)
        if (stop) p.client.stopSending(id, 5)
        p.step()
        assertTrue(p.clientEvents.none { it is ConnectionEvent.StreamFinished && it.id == id })
        return p to id
    }

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private fun List<ConnectionEvent>.bidiOf(id: Long): List<String> =
        mapNotNull {
            when {
                it is ConnectionEvent.StreamFinalSize && it.id == id -> if (it.sending) "sent ${it.size}" else "received ${it.size}"
                it is ConnectionEvent.StreamFinished && it.id == id -> "finished"
                else -> null
            }
        }

    /** The receiving half ends after the answer (the server's reply read to its FIN): both sizes, then the end. */
    @Test fun earlyBidiResetThenAnsweredReportsBothSizesBeforeItsEnd() {
        val (p, id) = resetEarlyBidi(ticket(), stop = false)
        p.use { _ ->
            var answered = false
            assertTrue(
                p.runUntil(limit = 3.seconds) {
                    val s = p.server
                    if (s != null && !answered && p.serverEvents.any { it is ConnectionEvent.StreamOpened && it.id == id }) {
                        s.writeStream(id, "ok".encodeToByteArray(), 0, 2, fin = true)
                        answered = true
                    }
                    streamText(p.client, id)
                    "finished" in p.clientEvents.bidiOf(id)
                },
            )
            assertEquals(true, p.client.earlyDataAccepted)
            val got = p.clientEvents.bidiOf(id)
            assertEquals("finished", got.last(), "$got")
            assertEquals(listOf("sent 5"), got.filter { it.startsWith("sent") })
            assertEquals(listOf("received 2"), got.filter { it.startsWith("received") })
        }
    }

    /** Its receiving half stopped before the answer: on accept the sizes, then the end; nothing raised before. */
    @Test fun earlyBidiResetAndStoppedReportsAfterTheAccept() {
        val (p, id) = resetEarlyBidi(ticket(), stop = true)
        p.use { _ ->
            assertTrue(p.handshake())
            assertEquals(true, p.client.earlyDataAccepted)
            assertTrue(p.runUntil(limit = 3.seconds) { "finished" in p.clientEvents.bidiOf(id) })
            val got = p.clientEvents.bidiOf(id)
            assertEquals("finished", got.last())
            assertEquals(listOf("sent 5"), got.filter { it.startsWith("sent") })
            assertEquals(1, got.count { it.startsWith("received") })
        }
    }

    @Test fun negative_earlyBidiResetBeforeARejectionReportsNothing() {
        for (stop in listOf(false, true)) {
            val (p, id) = resetEarlyBidi(ticket(), serverEarly = early(app = byteArrayOf(9)), stop = stop)
            p.use { _ ->
                assertTrue(p.handshake())
                assertEquals(false, p.client.earlyDataAccepted)
                p.runUntil(limit = 1.seconds) { false }
                assertEquals(emptyList(), p.clientEvents.bidiOf(id), "stop=$stop")
                assertEquals(0, p.client.streams.sizesForTest()[5])
            }
        }
    }

    /** A rejected 0-RTT drops the stream: no final size is ever reported for it (its FIN went out in 0-RTT). */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun negative_rejectedZeroRttStreamHasNoFinalSize() {
        val (p, id) = resumed(ticket(), serverEarly = early(app = byteArrayOf(9)))
        assertTrue(p.handshake())
        assertEquals(false, p.client.earlyDataAccepted)
        p.runUntil(limit = 1.seconds) { false }
        assertTrue(p.clientEvents.none { it is ConnectionEvent.StreamFinalSize && it.id == id && it.sending }, p.clientEvents.toString())
        p.close()
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

    /**
     * RFC 9846 section 5.5: "it is not possible to perform a KeyUpdate for early data; therefore, implementations MUST NOT exceed
     * the limits when sending early data"; for QUIC the limit is RFC 9001 section 6.6's per key. With the 0-RTT key's limit
     * lowered to 4 packets, a 20 000-byte request sends at most 4 0-RTT packets, and the rest arrives in 1-RTT.
     */
    @Test fun negative_zeroRttStopsAtTheAeadLimit() {
        val t = ticket()
        val request = "x".repeat(20_000)
        var zeroRttPackets = 0
        var id = -1L
        val p =
            CorePair(
                crypto = ksl,
                clientEarly = EarlyDataState.Allowed,
                serverEarly = early(),
                clientSetup = { c ->
                    c.testZeroRttConfidentialityLimit = 4
                    assertTrue(c.useTicket(t))
                    id = c.openStream(bidi = true)
                    assertEquals(request.length, c.writeStream(id, request.encodeToByteArray(), 0, request.length, fin = true))
                },
            )
        val hv = PacketHeaderView()
        p.filterToServer = { _, b ->
            val buf = PacketBuffer.of(b)
            try {
                var off = 0
                while (off < b.size && PacketHeaderCodec.parse(buf, off, b.size, 8, hv)) {
                    if (hv.type == PacketType.ZeroRtt) zeroRttPackets++
                    if (hv.packetEnd <= off) break
                    off = hv.packetEnd
                }
            } finally {
                buf.close()
            }
            true
        }
        p.use { _ ->
            var got = ""
            assertTrue(
                p.runUntil(limit = 5.seconds) {
                    p.server?.let { got += streamText(it, id) }
                    got.length == request.length
                },
                "the whole request arrives: ${got.length} bytes",
            )
            assertTrue(zeroRttPackets in 1..4, "0-RTT packets sent: $zeroRttPackets")
            assertEquals(zeroRttPackets.toLong(), p.client.zeroRttPacketsSealed)
            assertNull(p.closedReason(p.clientEvents))
        }
    }

    /**
     * 0.3.0 cross-review, RFC 9001 section 4.6.2: "When 0-RTT is rejected, ... a client SHOULD treat receipt of an acknowledgment for
     * a 0-RTT packet as a connection error of type PROTOCOL_VIOLATION, if it is able to detect the condition." The client knows
     * which packet numbers its 0-RTT packets took; an acknowledgment of one after the rejection closes the connection.
     */
    @Test fun negative_ackOfARejectedZeroRttPacketIsProtocolViolation() {
        val (p, _) = resumed(ticket(), serverEarly = early(app = byteArrayOf(9)))
        p.use { _ ->
            assertTrue(p.handshake())
            val c = p.client
            assertEquals(false, c.earlyDataAccepted)
            assertTrue(
                c.zeroRttFirstPn >= 0 && c.zeroRttLastPn >= c.zeroRttFirstPn,
                "0-RTT went out: ${c.zeroRttFirstPn}..${c.zeroRttLastPn}",
            )
            val ack =
                io.kuicksilver.quic.wire
                    .AckFrameView()
            ack.reset()
            ack.addRange(c.zeroRttLastPn + 1, c.zeroRttLastPn + 5)
            c.checkAckAfterRejection(ack) // 1-RTT packets only: fine
            ack.reset()
            ack.addRange(c.zeroRttLastPn + 3, c.zeroRttLastPn + 5)
            ack.addRange(c.zeroRttLastPn, c.zeroRttLastPn + 1)
            val e = assertFailsWith<io.kuicksilver.quic.wire.QuicWireException> { c.checkAckAfterRejection(ack) }
            assertEquals(io.kuicksilver.quic.TransportError.PROTOCOL_VIOLATION, e.code)
            p.runUntil(limit = 1.seconds) { false }
            assertNull(p.closedReason(p.clientEvents), "an honest server never acknowledges them")
        }
        // end to end: the server's 1-RTT packet carries an ACK frame of the rejected 0-RTT packet numbers
        val (e, _) = resumed(ticket(), serverEarly = early(app = byteArrayOf(9)))
        try {
            assertTrue(e.handshake())
            val c = e.client
            assertEquals(false, c.earlyDataAccepted)
            val first = c.zeroRttFirstPn
            val last = c.zeroRttLastPn
            assertTrue(first in 0..63 && last in first..63, "small packet numbers: $first..$last")
            e.server!!.testInjectFrames += 3 to byteArrayOf(0x02, last.toByte(), 0, 0, (last - first).toByte())
            assertTrue(e.runUntil(limit = 1.seconds) { e.closedReason(e.clientEvents) != null })
            val r = assertIs<io.kuicksilver.quic.QuicException.ConnectionLost.TransportClosed>(e.closedReason(e.clientEvents))
            assertEquals(io.kuicksilver.quic.TransportError.PROTOCOL_VIOLATION, r.code)
        } finally {
            e.close()
        }
        val (q, _) = resumed(ticket())
        try {
            assertTrue(q.handshake())
            assertEquals(true, q.client.earlyDataAccepted)
            val ack =
                io.kuicksilver.quic.wire
                    .AckFrameView()
            ack.reset()
            ack.addRange(q.client.zeroRttFirstPn, q.client.zeroRttLastPn)
            q.client.checkAckAfterRejection(ack) // accepted: 0-RTT packets are acknowledged as any other
        } finally {
            q.close()
        }
    }

    /** A QUIC variable-length integer (RFC 9000 section 16), for frames a test injects. */
    private fun vi(v: Long): ByteArray =
        when {
            v < 64 -> byteArrayOf(v.toByte())
            v < 16384 -> byteArrayOf((0x40 or (v shr 8).toInt()).toByte(), v.toByte())
            v < 1L shl 30 -> byteArrayOf((0x80 or (v shr 24).toInt()).toByte(), (v shr 16).toByte(), (v shr 8).toByte(), v.toByte())
            else -> error("test values stay below 2^30")
        }

    /**
     * A rejected 0-RTT whose server puts [frames] (made from the client once the server exists: it knows the client's 0-RTT
     * packet numbers then) into its first 1-RTT packet, the 0.5-RTT flight the client reads in the same round as the server's
     * Finished. Returns the pair after the handshake.
     */
    private fun rejectedWithHalfRttFrames(frames: (ConnectionCore) -> ByteArray): CorePair {
        val (p, _) = resumed(ticket(), serverEarly = early(app = byteArrayOf(9)))
        p.onServerCreated = { s -> s.testInjectFrames += 3 to frames(p.client) }
        p.runUntil(limit = 3.seconds) { p.clientEvents.any { it is ConnectionEvent.HandshakeCompleted } || p.client.state.isClosedForTest() }
        assertEquals(false, p.client.earlyDataAccepted)
        return p
    }

    private fun ConnectionState.isClosedForTest() = this == ConnectionState.Closing || this == ConnectionState.Draining || this == ConnectionState.Closed

    /**
     * RFC 9001 section 4.6.2, "The client therefore MUST reset the state of all streams": the client in 0-RTT holds the server's
     * 1-RTT packets until the handshake's end settled the 0-RTT (as ngtcp2's client buffers them until its handshake completed),
     * so a stream the server opened in its 0.5-RTT flight is reported after the rejection, never before it, where the
     * application would read it while the rejected streams still looked alive. Red before: the packet held for the 1-RTT key
     * was replayed when the key arrived, a step before the handshake's end, and its StreamOpened came first.
     */
    @Test fun aServerStreamOfTheHalfRttFlightIsReportedAfterTheRejection() {
        val p = rejectedWithHalfRttFrames { byteArrayOf(0x0b, 0x03, 0x02, 'h'.code.toByte(), 'i'.code.toByte()) }
        p.use {
            val events = p.clientEvents
            val rejected = events.indexOfFirst { it === ConnectionEvent.EarlyDataRejected }
            val completed = events.indexOfFirst { it is ConnectionEvent.HandshakeCompleted }
            val opened = events.indexOfFirst { it is ConnectionEvent.StreamOpened && it.id == 3L }
            assertTrue(rejected >= 0 && opened >= 0, events.toString())
            assertTrue(rejected < completed && completed < opened, "rejection, handshake's end, then the server's stream: $events")
            assertEquals("hi", streamText(p.client, 3))
            assertNull(p.closedReason(p.clientEvents))
        }
    }

    /**
     * RFC 9000 section 7.4.1 with RFC 9001 section 4.6.2: a rejection replaces the remembered limits with the server's
     * transport parameters, and the MAX_DATA and MAX_STREAMS of the server's 0.5-RTT flight raise them from there. Red
     * before: those frames were read before the rejection, which then restarted the connection's credit and stream limits at
     * the transport parameters and lost them.
     */
    @Test fun halfRttMaxDataAndMaxStreamsSurviveTheRejection() {
        val window = QuicConfig.Default.initialConnectionWindow
        val bidi = QuicConfig.Default.maxBidiStreams
        val p =
            rejectedWithHalfRttFrames {
                byteArrayOf(0x10) + vi(window * 4) + byteArrayOf(0x12) + vi(bidi + 50) + byteArrayOf(0x13) + vi(QuicConfig.Default.maxUniStreams + 7)
            }
        p.use {
            assertTrue(p.clientEvents.any { it === ConnectionEvent.EarlyDataRejected })
            assertEquals(window * 4, p.client.connSend.maxLimit, "the server's MAX_DATA")
            assertEquals(bidi + 50, p.client.streams.localMaxStreamsAllowed(bidi = true), "the server's MAX_STREAMS (bidirectional)")
            assertEquals(
                QuicConfig.Default.maxUniStreams + 7,
                p.client.streams.localMaxStreamsAllowed(bidi = false),
                "the server's MAX_STREAMS (unidirectional)",
            )
            assertNull(p.closedReason(p.clientEvents))
        }
    }

    /**
     * RFC 9001 section 4.6.2: after a rejection "a client SHOULD treat receipt of an acknowledgment for a 0-RTT packet as a
     * connection error of type PROTOCOL_VIOLATION". The check comes before the acknowledgment is applied (FrameDispatcher),
     * so the forged acknowledgment gives no RTT sample and frees no congestion window. Red before: the ACK in the server's
     * 0.5-RTT flight was read before the rejection was known and taken as an acknowledgment of the 0-RTT packets.
     */
    @Test fun negative_aHalfRttAckOfARejectedZeroRttPacketIsProtocolViolation() {
        val p =
            rejectedWithHalfRttFrames { c ->
                val first = c.zeroRttFirstPn
                val last = c.zeroRttLastPn
                assertTrue(first in 0..63 && last in first..63, "0-RTT went out: $first..$last")
                byteArrayOf(0x02, last.toByte(), 0, 0, (last - first).toByte())
            }
        p.use {
            assertTrue(p.runUntil(limit = 1.seconds) { p.closedReason(p.clientEvents) != null })
            val r = assertIs<io.kuicksilver.quic.QuicException.ConnectionLost.TransportClosed>(p.closedReason(p.clientEvents))
            assertEquals(io.kuicksilver.quic.TransportError.PROTOCOL_VIOLATION, r.code)
        }
    }

    /**
     * The accepted 0-RTT keeps its order: the client holds the server's 0.5-RTT flight until the handshake's end as after a
     * rejection, reports EarlyDataAccepted and HandshakeCompleted first, then the server's stream, and takes its MAX_DATA.
     */
    @Test fun anAcceptedZeroRttReadsTheHalfRttFlightAfterTheAcceptance() {
        val window = QuicConfig.Default.initialConnectionWindow
        val (p, _) = resumed(ticket())
        p.onServerCreated = { s ->
            s.testInjectFrames += 3 to (byteArrayOf(0x0b, 0x03, 0x02, 'h'.code.toByte(), 'i'.code.toByte()) + byteArrayOf(0x10) + vi(window * 4))
        }
        p.use {
            assertTrue(p.runUntil(limit = 3.seconds) { p.clientEvents.any { it is ConnectionEvent.StreamOpened && it.id == 3L } })
            assertEquals(true, p.client.earlyDataAccepted)
            val events = p.clientEvents
            val accepted = events.indexOfFirst { it === ConnectionEvent.EarlyDataAccepted }
            val completed = events.indexOfFirst { it is ConnectionEvent.HandshakeCompleted }
            val opened = events.indexOfFirst { it is ConnectionEvent.StreamOpened && it.id == 3L }
            assertTrue(accepted in 0 until completed && completed < opened, events.toString())
            assertEquals("hi", streamText(p.client, 3))
            assertEquals(window * 4, p.client.connSend.maxLimit)
            assertNull(p.closedReason(p.clientEvents))
        }
    }

    /**
     * RFC 9001 section 4.6.2: "When 0-RTT is rejected, all connection characteristics that the client assumed might be
     * incorrect ... The client therefore MUST reset the state of all streams". The stream opened in 0-RTT is gone (nothing
     * of it is sent again), its ID and its flow-control credit are free again (as ngtcp2's `conn_discard_early_data_state`
     * and quic-go's `streamsMap.ResetFor0RTT`), and the application sends what it still wants on a new stream.
     */
    @Test fun zeroRttRejectedResetsStreams() {
        // the server's application context changed: TLS refuses the early data (RFC 9001 section 4.6.3)
        val (p, id) = resumed(ticket(), serverEarly = early(app = byteArrayOf(9)))
        assertTrue(p.handshake())
        assertEquals(false, p.client.earlyDataAccepted)
        assertEquals(false, p.server!!.earlyDataAccepted)
        assertTrue(p.clientEvents.any { it === ConnectionEvent.EarlyDataRejected })
        assertTrue(!p.client.isStreamOpenForTest(id), "the stream opened in 0-RTT is reset with the rejection")
        assertEquals(0L, p.client.connSend.used, "no connection credit stays used by the rejected 0-RTT data")
        p.runUntil(limit = 1.seconds) { false }
        assertTrue(
            p.serverEvents.none { it is ConnectionEvent.StreamReadable || it is ConnectionEvent.StreamOpened },
            "nothing of the rejected stream is sent again",
        )
        // the application opens its stream again: the same ID, since the server never saw the first one
        val again = p.client.openStream(bidi = true)
        assertEquals(id, again)
        p.client.writeStream(again, "GET /index.html".encodeToByteArray(), 0, 15, fin = true)
        var got = ""
        assertTrue(
            p.runUntil(limit = 3.seconds) {
                val s = p.server!!
                if (p.serverEvents.any { it is ConnectionEvent.StreamReadable && it.id == again }) {
                    val req = streamText(s, again)
                    if (req.isNotEmpty()) {
                        assertEquals("GET /index.html", req)
                        s.writeStream(again, "200 OK".encodeToByteArray(), 0, 6, fin = true)
                    }
                }
                got += streamText(p.client, again)
                got == "200 OK"
            },
        )
        assertTrue(!p.server!!.streamReceivedEarly(again))
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
            ConnectionCore
                .serverWithKeys(
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
                .also { made += it }
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

    /** A ticket that remembers more than the server will grant: the server accepts 0-RTT with lower limits. */
    private fun t2Lowered(): QuicSessionTicket {
        val t = ticket()
        val tp = TransportParametersCodec.decode(rememberedTp(t.remembered!!), TlsRole.Server)
        tp.initialMaxData = tp.initialMaxData * 4
        t.remembered = withTp(t.remembered!!, TransportParametersCodec.encode(tp, TlsRole.Server, 27))
        return t
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
        p.use { _ ->
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

    /**
     * 0.3.0 cross-review, RFC 9000 section 7.4.1: "a client MUST only use remembered transport parameters" in 0-RTT. The
     * server's new reset_stream_at was applied as soon as its EncryptedExtensions arrived, so with the Finished still missing
     * a RESET_STREAM_AT could leave in a 0-RTT packet on an offer the ticket did not carry. The remembered offer counts until
     * 1-RTT, the new one after.
     */
    @Test fun negative_zeroRttUsesTheRememberedResetStreamAt() {
        val withAt = quicConfig { resetStreamAt = true }
        val t = ticket(clientQuic = withAt)
        val tp = TransportParametersCodec.decode(rememberedTp(t.remembered!!), TlsRole.Server)
        assertEquals(false, tp.resetStreamAt, "the ticket's server did not offer reset_stream_at")
        val (p, id) = resumed(t, request = "x", clientQuic = withAt)
        p.use { _ ->
            val c = p.client
            p.filterToServer = { _, _ -> false }
            p.step()
            assertEquals(false, c.streams.peerResetStreamAt)
            tp.resetStreamAt = true // the server's EncryptedExtensions offer it now, its Finished has not arrived
            tp.originalDestinationConnectionId = c.odcid
            tp.initialSourceConnectionId = c.remoteCid
            ConnectionHandshakeSink(c).onPeerTransportParameters(TransportParametersCodec.encode(tp, TlsRole.Server, 27), c.version.version)
            assertTrue(c.zeroRttWritable, "still sending 0-RTT")
            assertEquals(false, c.streams.peerResetStreamAt, "0-RTT uses only the remembered (absent) offer")
            c.streams.resetAt(id, 3, 0)
            val kinds = generateSequence { c.streams.takeControlFrame() }.map { it.kind }.toList()
            assertTrue(io.kuicksilver.quic.stream.ControlKind.ResetStream in kinds, "a plain RESET_STREAM: $kinds")
        }
        val remembered = ticket(serverQuic = withAt, clientQuic = withAt)
        val (q, _) = resumed(remembered, request = "x", clientQuic = withAt, serverQuic = withAt, serverEarly = early(withAt))
        try {
            assertEquals(true, q.client.streams.peerResetStreamAt, "a remembered offer counts in 0-RTT")
            assertTrue(q.handshake())
            assertEquals(true, q.client.earlyDataAccepted)
            assertEquals(true, q.client.streams.peerResetStreamAt)
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
        p.use { _ ->
            assertTrue(p.handshake(), "${p.closedReason(p.clientEvents)} / ${p.closedReason(p.serverEvents)}")
            assertEquals(VersionProfile.V2, p.server!!.version, "upgraded to v2")
            assertEquals(VersionProfile.V2, p.client.version)
            assertEquals(true, p.client.earlyDataAccepted)
            assertTrue(p.server!!.streamReceivedEarly(id), "the request arrived in 0-RTT")
            assertEquals("GET /index.html", streamText(p.server!!, id))
        }
    }

    /**
     * Found by the 0-RTT connection fuzzer. A Version Negotiation answers a first flight with 0-RTT in it; the new attempt in
     * v2 has no ticket (RFC 9369 section 5), so its 0-RTT counts as rejected, and its packet numbers start again (RFC 9368
     * section 2.1: "a new first flight"). The server's acknowledgment of the new attempt's first 1-RTT packets covered the
     * numbers the abandoned 0-RTT packets had had, and the client closed with PROTOCOL_VIOLATION (RFC 9001 section 4.6.2 lets
     * it do so only for "an acknowledgment for a 0-RTT packet", and those packets belong to the abandoned attempt).
     */
    @Test fun negative_versionNegotiationAfterZeroRttKeepsTheConnection() {
        val t = ticket() // a v1 ticket
        val v2 = quicConfig { versions = listOf(VersionProfile.V2) } // offering v1 too would make the VN a downgrade
        val (p, id) = resumed(t, clientQuic = v1v2, serverQuic = v2, serverEarly = early(v2))
        var vn = false
        p.filterToServer = { _, b ->
            // the v1-only first flight, 0-RTT included, is answered with a Version Negotiation offering v2
            if (p.client.version == VersionProfile.V1) {
                if (!vn && b[0].toInt() and 0xf0 == 0xc0) {
                    vn = true
                    p.toClient += io.kuicksilver.quic.Dgram(versionNegotiation(b, VersionProfile.V2.version), CoreFixtures.serverAddr)
                }
                false
            } else {
                true
            }
        }
        p.use { _ ->
            assertTrue(p.handshake(), "${p.closedReason(p.clientEvents)} / ${p.closedReason(p.serverEvents)}")
            assertTrue(vn && p.client.zeroRttPacketsSealed > 0, "0-RTT went out before the Version Negotiation")
            assertEquals(VersionProfile.V2, p.client.version)
            assertEquals(false, p.client.earlyDataAccepted, "the restarted attempt had no ticket")
            assertTrue(p.clientEvents.any { it === ConnectionEvent.EarlyDataRejected })
            val again = p.client.openStream(bidi = true)
            assertEquals(id, again)
            p.client.writeStream(again, "GET /".encodeToByteArray(), 0, 5, fin = true)
            assertTrue(
                p.runUntil(limit = 2.seconds) { p.serverEvents.any { it is ConnectionEvent.StreamReadable && it.id == again } },
                "the new request arrives: ${p.closedReason(p.clientEvents)} / ${p.closedReason(p.serverEvents)}",
            )
            assertEquals("GET /", streamText(p.server!!, again))
            // the server acknowledges the client's 1-RTT packets, whose numbers the abandoned 0-RTT packets had too
            p.runUntil(limit = 1.seconds) { false }
            assertNull(p.closedReason(p.clientEvents))
            assertNull(p.closedReason(p.serverEvents))
        }
    }

    /** A Version Negotiation packet answering the client's Initial [initial] with [versions]. */
    private fun versionNegotiation(
        initial: ByteArray,
        vararg versions: Int,
    ): ByteArray {
        val b = PacketBuffer.of(initial)
        val out = PacketBuffer.allocate(1200)
        try {
            val v = PacketHeaderView()
            check(PacketHeaderCodec.parse(b, 0, initial.size, 8, v))
            val n =
                io.kuicksilver.quic.wire.VersionNegotiationPacket
                    .write(out, b, v.scidOff, v.scidLen, b, v.dcidOff, v.dcidLen, versions, 0x12, 1200)
            return ByteArray(n).also { out.copyTo(it, 0, 0, n) }
        } finally {
            b.close()
            out.close()
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
            p.use { _ ->
                assertEquals(used, took, "a v2 ticket for a connection starting in ${start.versions.first()}")
                assertTrue(p.handshake())
                assertEquals(used, p.client.earlyDataAccepted == true, "0-RTT only with the ticket of our version")
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
        p.use { _ ->
            p.runUntil(limit = 3.seconds) { p.closedReason(p.clientEvents) != null }
            val r = assertIs<QuicException.ConnectionLost.TransportClosed>(p.closedReason(p.clientEvents))
            assertEquals(TransportError.PROTOCOL_VIOLATION, r.code, r.reason)
        }
    }

    /** Rejected with lower limits than the 0-RTT data used: nothing is resent, so the connection goes on with the reset streams. */
    @Test fun rejectedWithSmallerLimitsResetsStreamsAndContinues() {
        val big = "x".repeat(4000)
        val small = quicConfig { initialConnectionWindow = 1000 }
        val (p, id) = resumed(ticket(), request = big, serverQuic = small, serverEarly = early(small))
        assertTrue(p.handshake())
        assertTrue(p.clientEvents.any { it === ConnectionEvent.EarlyDataRejected })
        assertTrue(!p.client.isStreamOpenForTest(id))
        p.runUntil(limit = 1.seconds) { false }
        assertNull(p.closedReason(p.clientEvents))
        assertNull(p.closedReason(p.serverEvents), "the server saw no flow-control violation")
        p.close()
    }

    @Test fun requiredModeFailsOnRejection() {
        val (p, _) = resumed(ticket(), serverEarly = early(app = byteArrayOf(3)), mode = EarlyDataState.Required)
        assertTrue(p.runUntil(limit = 3.seconds) { p.closedReason(p.clientEvents) != null })
        assertIs<QuicException.ConnectionLost.ZeroRttRejected>(p.closedReason(p.clientEvents))
        p.close()
    }

    /**
     * draft-ietf-quic-reliable-stream-reset section 3: "When the server accepts 0-RTT data, the server MUST NOT disable this
     * extension on the resumed connection." The parameter is bound into the tickets' early-data context, so a server that
     * turned `resetStreamAt` off refuses the 0-RTT of tickets issued with it on (and the other way round).
     */
    @Test fun negative_resetStreamAtIsPartOfTheEarlyDataContext() {
        val off = early(QuicConfig.Default).context
        val on = early(quicConfig { resetStreamAt = true }).context
        assertTrue(!off.contentEquals(on), "a change of reset_stream_at refuses earlier tickets' 0-RTT")
    }

    @Test fun noEarlyDataWithoutServerOption() {
        val t = ticket()
        val (p, id) = resumed(t, serverEarly = null)
        assertTrue(p.handshake())
        assertEquals(false, p.client.earlyDataAccepted, "a server without 0-RTT refuses (and cannot resume: it has no ticket keys)")
        assertTrue(!p.client.isStreamOpenForTest(id), "the early stream was reset with the rejection (RFC 9001 section 4.6.2)")
        val again = p.client.openStream(bidi = true)
        p.client.writeStream(again, "GET /".encodeToByteArray(), 0, 5, fin = true)
        assertTrue(p.runUntil(limit = 2.seconds) { p.serverEvents.any { it is ConnectionEvent.StreamReadable && it.id == again } })
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
        made += s
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
        assertEquals(listOf(true, true, false), more.map { it >= 0 }, "the early stream was reset: two streams within the new limit of 2")
        assertEquals(id, more[0], "stream IDs start again after the reset")
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

    /**
     * RFC 9001 sections 6 and 6.4 after each 0-RTT outcome: the key phase state and the 1-RTT CRYPTO stream check start with the
     * 1-RTT keys, untouched by what 0-RTT did. Both sides update in turn (each packet number opened with the right generation, no
     * KEY_UPDATE_ERROR), then a TLS KeyUpdate from the client is still 0x010a. The tickets these connections resume came through the
     * transport's KeyUpdate check of the 1-RTT CRYPTO stream (its control: NewSessionTickets pass). These three are coverage of the
     * 0-RTT outcomes for the new state, not RED tests: they passed before the change too.
     */
    private fun keyUpdatesAfter(p: CorePair) {
        assertTrue(p.handshake())
        assertTrue(
            p.runUntil(limit = 2.seconds) { p.client.state == ConnectionState.Confirmed && p.server!!.state == ConnectionState.Confirmed },
        )
        assertTrue(p.client.initiateKeyUpdate(p.now))
        assertTrue(p.runUntil(limit = 3.seconds) { p.server!!.keyPhaseForTest!!.generation == 1L })
        // a packet of the server's phase 1 to be acknowledged (section 6.1), then 3 x PTO (section 6.5)
        val id = p.server!!.openStream(bidi = false)
        p.server!!.writeStream(id, ByteArray(100), 0, 100, fin = true)
        assertTrue(p.runUntil(limit = 5.seconds) { p.server!!.initiateKeyUpdate(p.now) }, "the server's turn")
        val id2 = p.server!!.openStream(bidi = false) // something to carry phase 0 again
        p.server!!.writeStream(id2, ByteArray(100), 0, 100, fin = true)
        assertTrue(p.runUntil(limit = 3.seconds) { p.client.keyPhaseForTest!!.generation == 2L })
        assertNull(p.closedReason(p.clientEvents))
        assertNull(p.closedReason(p.serverEvents))
        p.client.testInjectFrames.addLast(3 to byteArrayOf(0x06, 0, 5, 24, 0, 0, 1, 0)) // CRYPTO at 0: a KeyUpdate
        assertTrue(p.runUntil(limit = 2.seconds) { p.closedReason(p.serverEvents) != null })
        assertEquals(0x010aL, (p.closedReason(p.serverEvents) as QuicException.ConnectionLost.TransportClosed).code)
    }

    @Test fun keyUpdatesAfterAcceptedZeroRtt() {
        val (p, _) = resumed(ticket())
        p.use { _ ->
            keyUpdatesAfter(p)
            assertEquals(true, p.client.earlyDataAccepted)
        }
    }

    @Test fun keyUpdatesAfterRejectedZeroRtt() {
        val (p, _) = resumed(ticket(), serverEarly = early(app = byteArrayOf(9)))
        p.use { _ ->
            keyUpdatesAfter(p)
            assertEquals(false, p.client.earlyDataAccepted)
        }
    }

    /** Lost before the answer: no 1-RTT key, so no key phase and nothing of it left. */
    @Test fun noKeyPhaseWhenTheConnectionEndsBeforeTheZeroRttAnswer() {
        val (p, _) = resumed(ticket())
        p.use { _ ->
            p.client.close(0, "end", p.now)
            p.runUntil(limit = 2.seconds) { false }
            assertNull(p.client.keyPhaseForTest)
        }
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

    /** Walks the NewSessionTicket messages (RFC 9846 section 4.7.1) and rewrites each early_data extension's value. */
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
