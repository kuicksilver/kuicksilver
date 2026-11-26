// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.IoCapabilities
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.endpoint.ZeroRttReplayRegister
import io.kuicksilver.quic.ksl
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.KeyExchangeGroups
import io.kuicksilver.tls.QuicSessionTicket
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * `initialUdpPayloadSize` with resumption and 0-RTT (RFC 9000 sections 7.4.1, 14; RFC 8899 section 4.3): datagrams that coalesce
 * several packets, each of them 1200 bytes or less, still count as large for black-hole detection, and a client's 0-RTT flight stays
 * within the `max_udp_payload_size` the ticket remembers.
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class PmtudStartResumptionTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val register = ZeroRttReplayRegister(Random(7))
    private val df = IoCapabilities(ecnSend = false, ecnReceive = false, gsoMaxSegments = 1, gro = false, df = true, batch = 1)

    private fun quic(block: QuicConfig.Builder.() -> Unit = {}): QuicConfig =
        quicConfig {
            maxIdleTimeout = null
            block()
        }

    /**
     * A ClientHello that fits one Initial packet (X25519 alone; the default X25519MLKEM768 share alone fills more than 1200
     * bytes), so the datagrams coalesce packets of 1200 bytes or less; [small] false keeps the default groups.
     */
    private fun clientTls(small: Boolean = true) =
        if (small) {
            CoreFixtures.client {
                keyExchangeGroups =
                    KeyExchangeGroups(
                        listOf(KeyExchangeGroups.X25519),
                    )
            }
        } else {
            CoreFixtures.client()
        }

    private fun early(serverQuic: QuicConfig) = ServerEarlyData.of(serverQuic, CoreFixtures.server().alpn, null, register)

    /** A full handshake (on a link that carries anything) that leaves the client a ticket. */
    private fun ticket(
        serverQuic: QuicConfig,
        small: Boolean = true,
    ): QuicSessionTicket {
        val p =
            CorePair(
                clientTls = clientTls(small),
                clientQuic = quic(),
                crypto = ksl,
                clientEarly = EarlyDataState.Allowed,
                serverEarly = early(serverQuic),
                serverQuic = serverQuic,
            )
        assertTrue(p.handshake(), "first handshake")
        assertTrue(p.runUntil(limit = 2.seconds) { p.clientEvents.any { it is ConnectionEvent.SessionTicket } })
        val tickets = p.clientEvents.filterIsInstance<ConnectionEvent.SessionTicket>().map { it.ticket }
        tickets.dropLast(1).forEach { it.close() }
        // the pair closes the tickets it heard (the leak sentinel's CorePair): the one returned is kept
        p.keep(tickets.last())
        p.close()
        return tickets.last().also { assertNotNull(it.remembered) }
    }

    /** The resumed connection on a DF path whose link carries at most [link] bytes each way; [zeroRtt] sends a request in 0-RTT. */
    private fun resumed(
        ticket: QuicSessionTicket,
        clientQuic: QuicConfig,
        serverQuic: QuicConfig,
        link: Int,
        zeroRtt: Boolean = true,
        small: Boolean = true,
    ): CorePair {
        val p =
            CorePair(
                clientTls = clientTls(small),
                clientQuic = clientQuic,
                crypto = ksl,
                clientEarly = EarlyDataState.Allowed,
                serverEarly = early(serverQuic),
                serverQuic = serverQuic,
                clientSetup = { c ->
                    c.setPathCapabilities(PathId.Initial, df)
                    assertTrue(c.useTicket(ticket), "0-RTT with this ticket")
                    if (zeroRtt) {
                        val id = c.openStream(bidi = true)
                        val req = ByteArray(100) { 'x'.code.toByte() }
                        c.writeStream(id, req, 0, req.size, fin = true)
                    }
                },
            )
        p.onServerCreated = { it.setPathCapabilities(PathId.Initial, df) }
        p.filterToServer = { _, b -> b.size <= link }
        p.filterToClient = { _, b -> b.size <= link }
        return p
    }

    private fun clientSizes(p: CorePair): MutableList<Int> {
        val sizes = ArrayList<Int>()
        val keep = p.filterToServer
        p.filterToServer = { i, b ->
            sizes += b.size
            keep(i, b)
        }
        return sizes
    }

    private fun serverSizes(p: CorePair): MutableList<Int> {
        val sizes = ArrayList<Int>()
        val keep = p.filterToClient
        p.filterToClient = { i, b ->
            sizes += b.size
            keep(i, b)
        }
        return sizes
    }

    /**
     * RFC 8899 sections 4.3 and 5.1.1 (Pmtud.waitsForData): a client that sent its request in 0-RTT and afterwards only acknowledges
     * the answer (the interop runner's zerortt case) sends no probe: 0-RTT data goes before the handshake is confirmed, so it does
     * not begin the search. The server, which sends, still searches.
     */
    @Test fun negative_zeroRttDataThenAcknowledgementsOnlySendsNoProbe() {
        val serverQuic = quic()
        val t = ticket(serverQuic)
        val p = resumed(t, quic(), serverQuic, link = 1500)
        p.use { _ ->
            val sizes = clientSizes(p)
            assertTrue(p.runUntil { p.client.state == io.kuicksilver.quic.ConnectionState.Confirmed }, "confirmed: ${p.client.state}")
            val s = p.server!!
            val id = s.openStream(bidi = false)
            val body = ByteArray(200_000)
            var w = 0
            val done =
                p.runUntil(limit = 20.seconds) {
                    if (w < body.size) {
                        val n = minOf(16384, body.size - w)
                        w += s.writeStream(id, body, w, n, w + n == body.size)
                    }
                    w == body.size && s.stats.bytesInFlight == 0L
                }
            assertTrue(done, "the download is acknowledged")
            p.runUntil(limit = 5.seconds) { false }
            assertTrue(
                sizes.drop(1).none { it > 1200 },
                "the client probed after 0-RTT data and acknowledgements: ${sizes.filter { it > 1200 }}",
            )
            assertEquals(1200, p.client.stats.pathMtu)
            assertTrue(s.stats.pathMtu > 1200, "the sending server searched: ${s.stats.pathMtu}")
        }
    }

    /**
     * The other gap before confirmation: 1-RTT data the client sends once its handshake completed but before HANDSHAKE_DONE arrived
     * (state Established) does not begin the search either; confirmation is the reference point (docs/spec/rfc/8899.md). A client
     * that sends nothing more afterwards sends no probe; its next application data would begin the search.
     */
    @Test fun negative_oneRttDataBeforeHandshakeDoneThenNothingSendsNoProbe() {
        val serverQuic = quic()
        val t = ticket(serverQuic)
        val p = resumed(t, quic(), serverQuic, link = 1500, zeroRtt = false)
        p.use { _ ->
            val sizes = clientSizes(p)
            assertTrue(p.runUntil { p.client.state == io.kuicksilver.quic.ConnectionState.Established }, "established: ${p.client.state}")
            val id = p.client.openStream(bidi = true)
            val req = ByteArray(100) { 'y'.code.toByte() }
            p.client.writeStream(id, req, 0, req.size, fin = true)
            assertTrue(p.runUntil { p.client.state == io.kuicksilver.quic.ConnectionState.Confirmed }, "confirmed: ${p.client.state}")
            p.runUntil(limit = 5.seconds) { false }
            assertTrue(sizes.none { it > 1200 }, "the client probed after data sent before confirmation: ${sizes.filter { it > 1200 }}")
            assertTrue(
                p.client.paths.active.pmtud!!
                    .waitsForData,
                "the search still waits for data",
            )
        }
    }

    @Test fun negative_aClientZeroRttStartAboveTheLinkFallsBackAlthoughEveryPacketIsSmall() {
        // every datagram coalesces an Initial (with the ticket) and a padded 0-RTT packet: no single packet above 1200
        val serverQuic = quic()
        val t = ticket(serverQuic)
        val p = resumed(t, quic { pathMtu { initial = 1300 } }, serverQuic, link = 1250)
        p.use { _ ->
            val sizes = clientSizes(p)
            p.step()
            // the first datagram: 1300 bytes, an Initial with the ticket and a padded 0-RTT packet, each below 1200; unanswered, it is a
            // large packet for the PTO rule (RFC 8899 section 4.3 judges what the path carries: the datagram)
            assertEquals(listOf(1300), sizes)
            val packets =
                io.kuicksilver.quic.recovery.SpaceId.entries
                    .flatMap { sp ->
                        p.client.loss
                            .space(sp)
                            .sent
                            .map { it.size }
                    }
            assertTrue(packets.size >= 2 && packets.all { it <= 1200 }, "coalesced packets: $packets")
            assertTrue(p.client.largePacketUnanswered(p.client.paths.active), "the 1300-byte datagram counts as large")
            assertTrue(p.handshake(), "the handshake completes: ${p.client.state}, sizes ${sizes.take(6)}")
            assertEquals(1300, sizes.first(), "it started at 1300")
            assertEquals(1200, p.client.stats.pathMtu)
        }
    }

    @Test fun negative_aServerStartAboveTheLinkFallsBackOnAResumedHandshake() {
        // resumption: no certificate, so the server's Initial and Handshake packets share one datagram, each below 1200
        val serverQuic = quic { pathMtu { initial = 1300 } }
        val t = ticket(serverQuic)
        val p = resumed(t, quic(), serverQuic, link = 1250, zeroRtt = false)
        p.use { _ ->
            val sizes = serverSizes(p)
            p.runUntil { sizes.isNotEmpty() }
            val s = p.server!!
            val packets =
                io.kuicksilver.quic.recovery.SpaceId.entries
                    .flatMap { sp ->
                        s.loss
                            .space(sp)
                            .sent
                            .map { it.size }
                    }
            assertEquals(1300, sizes.first())
            assertTrue(packets.size >= 2 && packets.all { it <= 1200 }, "coalesced packets: $packets")
            assertTrue(s.largePacketUnanswered(s.paths.active), "the 1300-byte datagram counts as large")
            assertTrue(p.handshake(), "the handshake completes: ${p.server?.state}, sizes ${sizes.take(6)}")
            assertEquals(1300, sizes.first(), "the server started at 1300")
            assertEquals(1200, p.server!!.stats.pathMtu)
        }
    }

    @Test fun aPacketTooBigAboutACoalescedDatagramIsAccepted() {
        // the 1300-byte first datagram holds packets of 1200 bytes or less: a Packet Too Big claiming 1250 bytes is about a
        // datagram this path did send larger (RFC 9000 section 14.2.1, RFC 8899 section 4.6.1), not one it never sent
        val serverQuic = quic()
        val t = ticket(serverQuic)
        val p = resumed(t, quic { pathMtu { initial = 1300 } }, serverQuic, link = 1500)
        p.use { _ ->
            val datagrams = ArrayList<ByteArray>()
            val keep = p.filterToServer
            p.filterToServer = { i, b ->
                datagrams += b
                keep(i, b)
            }
            p.step()
            val first = datagrams.first()
            assertEquals(1300, first.size)
            val packets =
                io.kuicksilver.quic.recovery.SpaceId.entries
                    .flatMap { sp ->
                        p.client.loss
                            .space(sp)
                            .sent
                            .map { it.size }
                    }
            assertTrue(packets.all { it <= 1200 }, "coalesced packets: $packets")
            val quote = first.copyOf(64)
            assertTrue(
                p.client.acceptPacketTooBig(quote, quote.size, CoreFixtures.serverAddr, 1250, PathId.Initial),
                "a valid Packet Too Big about the 1300-byte datagram is taken as a hint",
            )
            assertEquals(1200, p.client.stats.pathMtu, "the size drops to the base, provisionally")
        }
    }

    @Test fun negative_zeroRttStaysWithinTheRememberedMaxUdpPayloadSize() {
        // RFC 9000 section 7.4.1: the client uses the remembered max_udp_payload_size for 0-RTT
        val serverQuic = quic { pathMtu { maxReceive = 1250 } }
        val t = ticket(serverQuic)
        val p = resumed(t, quic { pathMtu { initial = 1400 } }, serverQuic, link = 1500)
        p.use { _ ->
            assertEquals(1250, p.client.stats.pathMtu, "lowered as the ticket is used")
            val sizes = clientSizes(p)
            assertTrue(p.handshake())
            assertTrue(sizes.isNotEmpty() && sizes.all { it <= 1250 }, "every datagram within the remembered limit: $sizes")
        }
    }

    /**
     * The randomized property of [PmtudStartTest] over resumption: whatever the starts on each side, the link each way, 0-RTT or
     * not, the resumed handshake completes and each side's size ends within its link.
     */
    @Test fun negative_randomStartsWithResumptionAndZeroRttNeverBreakTheHandshake() {
        val rnd = Random(0x52455355)
        repeat(16) { round ->
            val clientStart = 1200 + rnd.nextInt(301)
            val serverStart = 1200 + rnd.nextInt(301)
            val link = 1200 + rnd.nextInt(301)
            val zeroRtt = rnd.nextBoolean()
            val pmtud = rnd.nextBoolean()
            val small = rnd.nextBoolean()
            val what = "round $round: client $clientStart server $serverStart link $link 0-RTT $zeroRtt pmtud $pmtud small $small"
            val serverQuic =
                quic {
                    pathMtu { initial = serverStart }
                    pathMtu { discovery = pmtud }
                }
            val t = ticket(serverQuic, small)
            val p =
                resumed(
                    t,
                    quic {
                        pathMtu { initial = clientStart }
                        pathMtu { discovery = pmtud }
                    },
                    serverQuic,
                    link,
                    zeroRtt,
                    small,
                )
            p.use { _ ->
                assertTrue(p.handshake(), "$what: ${p.client.state} / ${p.server?.state}")
                checkWithin(p.client, link, what)
                checkWithin(p.server!!, link, what)
            }
        }
    }

    private fun checkWithin(
        c: ConnectionCore,
        link: Int,
        what: String,
    ) {
        assertTrue(c.stats.pathMtu <= maxOf(1200, link), "$what: mtu ${c.stats.pathMtu} above the link")
    }
}
