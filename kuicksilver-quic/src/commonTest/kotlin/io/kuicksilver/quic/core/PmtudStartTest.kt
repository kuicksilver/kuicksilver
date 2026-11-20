// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.IoCapabilities
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.endpoint.EndpointPair
import io.kuicksilver.quic.quicConfig
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * `QuicConfig.initialUdpPayloadSize` and `maxSendUdpPayloadSize` (RFC 9000 section 14, RFC 8899): a connection may start above
 * 1200 bytes, Initial padding included, never above its own or the peer's limits; a start the path cannot carry falls back to
 * 1200 by black-hole detection, during the handshake too; DPLPMTUD searches on from the start, or with `pmtud` off keeps it as
 * the ceiling.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class PmtudStartTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val df = IoCapabilities(ecnSend = false, ecnReceive = false, gsoMaxSegments = 1, gro = false, df = true, batch = 1)

    /** A pair that has not run yet: [EndpointPair.confirmed] runs the handshake. */
    private fun start(
        clientQuic: QuicConfig = quic { },
        serverQuic: QuicConfig = quic { },
        linkToServer: Int = 1500,
        linkToClient: Int = 1500,
        caps: IoCapabilities = df,
    ): Pair<EndpointPair, ConnectionCore> {
        val p = EndpointPair(serverQuic = serverQuic)
        p.linkMtuToServer = linkToServer
        p.linkMtuToClient = linkToClient
        val c = p.connect(clientQuic)
        c.setPathCapabilities(PathId.Initial, caps)
        p.onServerCreated = { it.setPathCapabilities(PathId.Initial, caps) }
        return p to c
    }

    private fun quic(block: QuicConfig.Builder.() -> Unit): QuicConfig =
        quicConfig {
            maxIdleTimeout = Duration.ZERO // the long scenarios outlive the 30 s idle timer
            block()
        }

    private fun transfer(
        p: EndpointPair,
        c: ConnectionCore,
        bytes: Int = 200_000,
    ) {
        val id = c.openStream(true)
        var w = 0
        assertTrue(
            p.runUntil(30.seconds) {
                if (w < bytes) {
                    val n = minOf(16384, bytes - w)
                    w += c.writeStream(id, ByteArray(n), 0, n, w + n == bytes)
                }
                w == bytes && c.stats.bytesInFlight == 0L
            },
            "upload done: state ${c.state}, mtu ${c.stats.pathMtu}",
        )
    }

    private fun download(
        p: EndpointPair,
        s: ConnectionCore,
        bytes: Int = 200_000,
    ) {
        val id = s.openStream(false)
        var w = 0
        assertTrue(
            p.runUntil(30.seconds) {
                if (w < bytes) {
                    val n = minOf(16384, bytes - w)
                    w += s.writeStream(id, ByteArray(n), 0, n, w + n == bytes)
                }
                w == bytes && s.stats.bytesInFlight == 0L
            },
            "download done: state ${s.state}, mtu ${s.stats.pathMtu}",
        )
    }

    // configuration

    @Test fun negative_aStartBelow1200IsRefused() {
        // RFC 9000 section 14.1: datagrams carrying Initial packets are at least 1200 bytes; section 14: "QUIC MUST NOT be used if the
        // network path cannot support a maximum datagram size of at least 1200 bytes"
        val e = assertFailsWith<IllegalArgumentException> { quicConfig { initialUdpPayloadSize = 1199 } }
        assertEquals("initialUdpPayloadSize must be 1200..65527", e.message)
        assertFailsWith<IllegalArgumentException> { quicConfig { initialUdpPayloadSize = 0 } }
        assertFailsWith<IllegalArgumentException> { quicConfig { initialUdpPayloadSize = 65528 } }
        assertFailsWith<IllegalArgumentException> { quicConfig { maxSendUdpPayloadSize = 1199 } }
        assertFailsWith<IllegalArgumentException> { quicConfig { maxSendUdpPayloadSize = 65528 } }
        assertEquals(1200, QuicConfig.Default.initialUdpPayloadSize)
        assertEquals(65527, QuicConfig.Default.maxSendUdpPayloadSize)
        val c =
            quicConfig {
                initialUdpPayloadSize = 1350
                maxSendUdpPayloadSize = 1380
            }
        assertEquals(1350, c.toBuilder().build().initialUdpPayloadSize, "toBuilder keeps it")
        assertEquals(1380, c.toBuilder().build().maxSendUdpPayloadSize)
    }

    // the start and Initial padding

    @Test fun theClientsInitialIsPaddedToTheConfiguredStart() {
        val (p, c) = start(clientQuic = quic { initialUdpPayloadSize = 1350 })
        p.use { _ ->
            assertEquals(1350, c.stats.pathMtu, "the first path starts there")
            assertTrue(p.confirmed(c))
            // RFC 9000 section 14.1: every datagram carrying an Initial is expanded, here to the configured size
            assertEquals(1350, p.clientDatagramSizes.first(), "the first Initial: ${p.clientDatagramSizes.take(4)}")
            assertTrue(p.clientDatagramSizes.all { it <= 1350 }, "nothing above the start before PMTUD: ${p.clientDatagramSizes}")
        }
    }

    @Test fun theServersFirstFlightUsesItsConfiguredStart() {
        val (p, c) = start(serverQuic = quic { initialUdpPayloadSize = 1350 })
        p.use { _ ->
            assertTrue(p.confirmed(c))
            val first = p.serverSent.first().second
            assertTrue(first[0].toInt() and 0x80 != 0, "a long header: the server's Initial")
            assertEquals(1350, first.size, "the server's Initial datagram is padded to its start")
            assertEquals(1200, p.clientDatagramSizes.first(), "the client keeps the default")
        }
    }

    @Test fun negative_withoutDfTheStartStaysAt1200() {
        // RFC 9000 section 14: "UDP datagrams MUST NOT be fragmented at the IP layer"; a socket that cannot set DF stays at 1200
        val (p, c) = start(clientQuic = quic { initialUdpPayloadSize = 1400 }, caps = IoCapabilities.Portable)
        p.use { _ ->
            assertTrue(p.confirmed(c))
            transfer(p, c)
            assertEquals(1200, c.stats.pathMtu)
            assertTrue(p.clientDatagramSizes.all { it <= 1200 }, "${p.clientDatagramSizes.filter { it > 1200 }}")
        }
    }

    // clamping

    @Test fun negative_theStartIsClampedToOurOwnLimits() {
        val (p, c) =
            start(
                clientQuic =
                    quic {
                        initialUdpPayloadSize = 1450
                        maxUdpPayloadSize = 1300
                    },
            )
        p.use { _ ->
            assertTrue(p.confirmed(c))
            assertEquals(1300, p.clientDatagramSizes.first(), "never above our own max_udp_payload_size")
        }
        val (p2, c2) =
            start(
                clientQuic =
                    quic {
                        initialUdpPayloadSize = 1450
                        maxSendUdpPayloadSize = 1380
                        pmtud = true
                    },
            )
        p2.use { _ ->
            assertTrue(p2.confirmed(c2))
            assertEquals(1380, p2.clientDatagramSizes.first(), "nor above maxSendUdpPayloadSize")
            transfer(p2, c2)
            assertTrue(p2.runUntil(30.seconds) { c2.pmtudSearchDoneForTest }, "mtu ${c2.stats.pathMtu}")
            assertEquals(1380, c2.stats.pathMtu, "the search stops at the send cap")
            assertTrue(p2.clientDatagramSizes.all { it <= 1380 }, "no probe above it: ${p2.clientDatagramSizes.filter { it > 1380 }}")
        }
    }

    @Test fun negative_aStartAboveThePeersLimitComesDownWhenItsParametersArrive() {
        // RFC 9000 section 18.2: max_udp_payload_size "does act as an additional constraint on datagram size in the same way as the
        // path MTU"; the first flight goes before the client knows it
        val (p, c) = start(clientQuic = quic { initialUdpPayloadSize = 1450 }, serverQuic = quic { maxUdpPayloadSize = 1250 })
        p.use { _ ->
            assertTrue(p.runUntil { c.peerTp != null })
            val sent = p.clientDatagramSizes.size
            assertEquals(1250, c.stats.pathMtu, "down to the peer's limit as soon as its parameters arrive")
            assertTrue(p.confirmed(c))
            transfer(p, c)
            p.runUntil(30.seconds) { false }
            val after = p.clientDatagramSizes.drop(sent)
            assertTrue(after.isNotEmpty() && after.all { it <= 1250 }, "nothing above 1250 afterwards: ${after.filter { it > 1250 }}")
            assertEquals(1250, c.stats.pathMtu)
        }
    }

    @Test fun negative_aServerStartAboveTheClientsLimitIsClampedFromItsFirstDatagram() {
        // the server reads the client's parameters from the ClientHello, before it sends anything
        val (p, c) = start(clientQuic = quic { maxUdpPayloadSize = 1250 }, serverQuic = quic { initialUdpPayloadSize = 1450 })
        p.use { _ ->
            assertTrue(p.confirmed(c))
            val s = p.server.connections().single()
            download(p, s)
            p.runUntil(30.seconds) { false }
            assertTrue(p.serverSent.all { it.second.size <= 1250 }, "${p.serverSent.map { it.second.size }.filter { it > 1250 }}")
            assertEquals(1250, s.stats.pathMtu)
        }
    }

    // black holes

    @Test fun negative_aClientStartThePathCannotCarryFallsBackTo1200DuringTheHandshake() {
        // a WireGuard-like path: 1300 bytes of UDP payload pass, the configured 1400 vanish without ICMP
        val (p, c) = start(clientQuic = quic { initialUdpPayloadSize = 1400 }, linkToServer = 1300, linkToClient = 1300)
        p.use { _ ->
            assertTrue(p.confirmed(c), "the handshake completes: state ${c.state}, mtu ${c.stats.pathMtu}")
            assertEquals(1200, c.stats.pathMtu, "back to the base")
            assertEquals(1400, p.clientDatagramSizes.first(), "it did start at 1400: ${p.clientDatagramSizes.take(4)}")
            // a PTO with the 1400-byte Initial unanswered and nothing acknowledged yet: the probes go at 1200 (about 1 s at the
            // default initial RTT), and the handshake ends long before its 10 s timeout
            assertTrue(p.clientDatagramSizes.drop(1).all { it <= 1200 }, "${p.clientDatagramSizes.take(6)}")
            transfer(p, c)
        }
    }

    @Test fun negative_bothEndsStartingAboveTheLinkStillHandshakeWithinTheTimeout() {
        // each side's fallback waits for the other's datagrams: one PTO each while nothing was acknowledged keeps the whole well
        // inside the default 10 s handshake timeout (two each did not, with 0-RTT data in flight)
        val both = quic { initialUdpPayloadSize = 1400 }
        val (p, c) = start(clientQuic = both, serverQuic = both, linkToServer = 1300, linkToClient = 1300)
        p.use { _ ->
            val t0 = p.now
            assertTrue(p.runUntil(10.seconds) { c.state == ConnectionState.Confirmed }, "state ${c.state}")
            assertTrue(p.now - t0 < 5.seconds, "handshake took ${p.now - t0}")
            assertEquals(1200, c.stats.pathMtu)
            assertEquals(
                1200,
                p.server
                    .connections()
                    .single()
                    .stats.pathMtu,
            )
        }
    }

    @Test fun negative_aSlowFirstAnswerIsNoBlackHole() {
        // a server that answers only after the client's second PTO (a long first RTT, a busy server): the fallback to 1200 is
        // undone when the 1400-byte Initial is acknowledged after all (RFC 8899 section 4.1: an acknowledged packet confirms its size)
        val (p, c) =
            start(
                clientQuic =
                    quic {
                        initialUdpPayloadSize = 1400
                        pmtud = false
                    },
            )
        p.use { _ ->
            p.serverStalled = true
            assertTrue(p.runUntil(5.seconds) { c.stats.pathMtu == 1200 }, "two PTOs without an answer: ${c.stats.pathMtu}")
            p.serverStalled = false
            assertTrue(p.confirmed(c))
            assertEquals(1400, c.stats.pathMtu, "the late acknowledgment of the 1400-byte Initial restores it")
            transfer(p, c)
            assertEquals(1400, c.stats.pathMtu)
        }
    }

    @Test fun negative_aServerStartTheClientsPathCannotCarryFallsBackTo1200() {
        val (p, c) = start(serverQuic = quic { initialUdpPayloadSize = 1400 }, linkToClient = 1300)
        p.use { _ ->
            assertTrue(p.runUntil(15.seconds) { c.state == ConnectionState.Confirmed }, "the handshake completes: state ${c.state}")
            val s = p.server.connections().single()
            assertEquals(1200, s.stats.pathMtu)
            download(p, s)
        }
    }

    @Test fun negative_aStartThatStopsPassingLaterFallsBackTo1200() {
        val (p, c) =
            start(
                clientQuic =
                    quic {
                        initialUdpPayloadSize = 1400
                        pmtud = false
                    },
            )
        p.use { _ ->
            assertTrue(p.confirmed(c))
            transfer(p, c)
            assertEquals(1400, c.stats.pathMtu)
            p.linkMtuToServer = 1300 // the route changed
            transfer(p, c)
            assertEquals(1200, c.stats.pathMtu)
        }
    }

    @Test fun negative_withPmtudOffAFallBackProbesOnlyUpToTheStartAgain() {
        val (p, c) =
            start(
                clientQuic =
                    quic {
                        initialUdpPayloadSize = 1400
                        pmtud = false
                    },
                linkToServer = 1300,
                linkToClient = 1300,
            )
        p.use { _ ->
            assertTrue(p.confirmed(c))
            assertEquals(1200, c.stats.pathMtu)
            p.linkMtuToServer = 1500
            p.linkMtuToClient = 1500
            transfer(p, c)
            // after the minute's pause the search runs again, capped at the configured start
            assertTrue(p.runUntil(120.seconds) { c.stats.pathMtu == 1400 }, "back to the start: ${c.stats.pathMtu}")
            transfer(p, c)
            assertTrue(p.clientDatagramSizes.all { it <= 1400 }, "never above it: ${p.clientDatagramSizes.filter { it > 1400 }}")
        }
    }

    /**
     * Pmtud orders non-probe packets by the datagram they travelled in, not by packet number: an acknowledgment of an older datagram
     * (here a Handshake-space packet whose number is larger than those of the 1-RTT packets lost after it) does not reset a black-hole
     * verdict, and a datagram that coalesced three packets counts as one loss.
     */
    @Test fun negative_anAckInOneSpaceDoesNotResetAnotherSpacesBlackHoleVerdict() {
        val (p, c) =
            start(
                clientQuic =
                    quic {
                        initialUdpPayloadSize = 1400
                        pmtud = false
                    },
            )
        p.use { _ ->
            assertTrue(p.confirmed(c))
            assertEquals(1400, c.stats.pathMtu)
            val l = ConnectionLossListener(c)

            fun packet(
                pn: Long,
                seq: Long,
            ) = io.kuicksilver.quic.recovery.SentPacket().also {
                it.pn = pn
                it.size = 600
                it.datagramSize = 1400
                it.datagramSeq = seq
                it.pathId = PathId.Initial.value
            }
            val base = 1_000_000L
            // one lost datagram that coalesced three packets: one loss, no verdict
            // packet numbers of their own spaces (3, 7, 11), one datagram
            for (sp in io.kuicksilver.quic.recovery.SpaceId.entries) l.onLost(sp, packet(3L + 4 * sp.ordinal, base))
            c.checkPmtuBlackHoles()
            assertEquals(1400, c.stats.pathMtu, "one lost datagram is not three")
            // two more lost 1-RTT datagrams (packet numbers 12 and 13), then the ACK of an older datagram's Handshake packet number 500
            l.onLost(io.kuicksilver.quic.recovery.SpaceId.Application, packet(12, base + 1))
            l.onLost(io.kuicksilver.quic.recovery.SpaceId.Application, packet(13, base + 2))
            l.onAcked(io.kuicksilver.quic.recovery.SpaceId.Handshake, packet(500, base - 1))
            c.checkPmtuBlackHoles()
            assertEquals(1200, c.stats.pathMtu, "the older datagram's acknowledgment does not reset the verdict")
            // and an acknowledgment of a datagram older than those the verdict rested on does not undo it
            l.onAcked(io.kuicksilver.quic.recovery.SpaceId.Initial, packet(900, base - 2))
            assertEquals(1200, c.stats.pathMtu)
            // the first lost datagram acknowledged after all does
            l.onAcked(io.kuicksilver.quic.recovery.SpaceId.Application, packet(11, base))
            assertEquals(1400, c.stats.pathMtu, "an acknowledged datagram of 1400 bytes from the verdict's range undoes it")
        }
    }

    // the search from the start

    @Test fun pmtudSearchesUpwardsFromTheConfiguredStart() {
        val (p, c) = start(clientQuic = quic { initialUdpPayloadSize = 1300 })
        p.use { _ ->
            assertTrue(p.confirmed(c))
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 }, "mtu ${c.stats.pathMtu}")
            val sizes = p.events[c]!!.filterIsInstance<ConnectionEvent.MtuUpdated>().map { it.mtu }
            assertEquals(1300, sizes.first(), "it started at 1300: $sizes")
            assertTrue(sizes.zipWithNext().all { (a, b) -> b > a }, "and only went up from there: $sizes")
            assertEquals(1452, sizes.last())
        }
    }

    @Test fun withPmtudOffTheStartIsTheCeiling() {
        val (p, c) =
            start(
                clientQuic =
                    quic {
                        initialUdpPayloadSize = 1350
                        pmtud = false
                    },
            )
        p.use { _ ->
            assertTrue(p.confirmed(c))
            transfer(p, c)
            p.runUntil(10.seconds) { false }
            assertEquals(1350, c.stats.pathMtu)
            assertEquals(0, c.pmtudProbesSentForTest, "no probes")
            assertTrue(p.clientDatagramSizes.all { it <= 1350 })
            assertTrue(p.clientDatagramSizes.count { it == 1350 } > 10, "the transfer used it")
        }
    }

    // migration

    @Test fun negative_aMoveToANarrowerRouteFallsBackAndANewAddressStartsAt1200() {
        val (p, c) =
            start(
                clientQuic = quic { },
                serverQuic =
                    quic {
                        initialUdpPayloadSize = 1400
                        pmtud = false
                    },
            )
        p.use { _ ->
            assertTrue(p.confirmed(c))
            val s = p.server.connections().single()
            download(p, s)
            assertEquals(1400, s.stats.pathMtu)
            // NAT rebinding: the same IP, a new port, a narrower route; the rebound path inherits 1400 and black-hole detection drops it
            val rebound = InetSocketAddress("10.0.0.1", 40001)
            p.clientSource = rebound
            p.clientListens += rebound
            p.linkMtuToClient = 1300
            clientSends(p, c, s)
            assertEquals(rebound, s.remoteAddressForTest)
            download(p, s)
            assertTrue(p.runUntil(30.seconds) { s.stats.pathMtu == 1200 }, "fallback on the rebound path: ${s.stats.pathMtu}")
            // a new address: its MTU is unknown, it starts at 1200 and the search stays capped at the configured start
            p.linkMtuToClient = 1500
            val moved = InetSocketAddress("10.0.0.9", 40000)
            p.clientSource = moved
            p.clientListens += moved
            val id = c.openStream(true)
            c.writeStream(id, ByteArray(2000), 0, 2000, true)
            assertTrue(p.runUntil(5.seconds) { s.remoteAddressForTest == moved }, "the server follows the client")
            assertEquals(1200, s.stats.pathMtu, "a new address starts at the base")
            assertTrue(p.runUntil(5.seconds) { c.stats.bytesInFlight == 0L })
            download(p, s)
            p.runUntil(10.seconds) { false }
            assertTrue(s.stats.pathMtu <= 1400, "never above the start with pmtud off: ${s.stats.pathMtu}")
            assertTrue(p.serverSent.all { it.second.size <= 1400 })
        }
    }

    private fun clientSends(
        p: EndpointPair,
        c: ConnectionCore,
        s: ConnectionCore,
    ) {
        val rx = s.stats.packetsReceived
        val id = c.openStream(true)
        c.writeStream(id, ByteArray(2000), 0, 2000, true)
        assertTrue(p.runUntil(5.seconds) { s.stats.packetsReceived > rx && c.stats.bytesInFlight == 0L })
        p.runUntil(200.milliseconds) { false }
    }

    // a randomized property

    /**
     * Whatever the start, the cap, the PMTUD switch and the link in each direction: the handshake completes, a transfer each way
     * completes, no datagram but a probe goes above the path's size, and in the end each side's size fits its link and every limit.
     */
    @Test fun negative_randomStartsAndLinksNeverBreakTheConnection() {
        val rnd = Random(0x4d5455)
        repeat(12) { round ->
            val start = 1200 + rnd.nextInt(301)
            val cap = if (rnd.nextBoolean()) 65527 else 1200 + rnd.nextInt(301)
            val pmtud = rnd.nextBoolean()
            val serverMax = if (rnd.nextBoolean()) 1452 else 1200 + rnd.nextInt(253)
            val toServer = 1200 + rnd.nextInt(301)
            val toClient = 1200 + rnd.nextInt(301)
            val what = "round $round: start $start cap $cap pmtud $pmtud serverMax $serverMax links $toServer/$toClient"
            val cfg =
                quic {
                    initialUdpPayloadSize = start
                    maxSendUdpPayloadSize = cap
                    this.pmtud = pmtud
                }
            val (p, c) =
                start(
                    clientQuic = cfg,
                    serverQuic = cfg.toBuilder().apply { maxUdpPayloadSize = serverMax }.build(),
                    linkToServer = toServer,
                    linkToClient = toClient,
                )
            p.use { _ ->
                assertTrue(p.runUntil(15.seconds) { c.state == ConnectionState.Confirmed }, "$what: handshake, state ${c.state}")
                val s = p.server.connections().single()
                transfer(p, c, 100_000)
                download(p, s, 100_000)
                val limitC = minOf(1452, cap, serverMax).let { if (pmtud) it else minOf(it, start) }
                val limitS = minOf(serverMax, cap, 1452).let { if (pmtud) it else minOf(it, start) }
                assertTrue(c.stats.pathMtu in 1200..limitC, "$what: client mtu ${c.stats.pathMtu} above $limitC")
                assertTrue(s.stats.pathMtu in 1200..limitS, "$what: server mtu ${s.stats.pathMtu} above $limitS")
                assertTrue(p.clientDatagramSizes.all { it <= maxOf(limitC, minOf(start, cap, 1452)) }, "$what: client sizes")
                // given time, each size fits its link (black-hole detection or the search settled it)
                transfer(p, c, 100_000)
                download(p, s, 100_000)
                assertTrue(c.stats.pathMtu <= maxOf(1200, toServer), "$what: client mtu ${c.stats.pathMtu} over the link")
                assertTrue(s.stats.pathMtu <= maxOf(1200, toClient), "$what: server mtu ${s.stats.pathMtu} over the link")
            }
        }
    }
}
