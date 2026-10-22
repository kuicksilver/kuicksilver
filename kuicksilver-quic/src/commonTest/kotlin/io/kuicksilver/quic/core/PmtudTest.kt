// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.Cubic
import io.kuicksilver.quic.IoCapabilities
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.endpoint.EndpointPair
import io.kuicksilver.quic.quicConfig
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** RFC 8899 / RFC 9000 section 14: DPLPMTUD — binary search with PING+PADDING probes, probe accounting, black-hole fallback, re-search. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class PmtudTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val df = IoCapabilities(ecnSend = false, ecnReceive = false, gsoMaxSegments = 1, gro = false, df = true, batch = 1)

    private fun pair(
        linkMtu: Int = 1500,
        clientQuic: QuicConfig = QuicConfig.Default,
        serverQuic: QuicConfig = QuicConfig.Default,
        caps: IoCapabilities = df,
    ): Pair<EndpointPair, ConnectionCore> {
        val p = EndpointPair(serverQuic = serverQuic)
        p.linkMtuToServer = linkMtu
        p.linkMtuToClient = linkMtu
        val c = p.connect(clientQuic)
        c.setPathCapabilities(PathId.Initial, caps)
        p.onServerCreated =
            { it.setPathCapabilities(PathId.Initial, caps) }
        assertTrue(p.confirmed(c))
        return p to c
    }

    private fun transfer(
        p: EndpointPair,
        c: ConnectionCore,
        bytes: Int = 300_000,
    ) {
        val id = c.openStream(true)
        var w = 0
        assertTrue(
            p.runUntil(30.seconds) {
                if (w <
                    bytes
                ) {
                    w +=
                        c.writeStream(
                            id,
                            ByteArray(minOf(16384, bytes - w)),
                            0,
                            minOf(16384, bytes - w),
                            w + minOf(16384, bytes - w) == bytes,
                        )
                }
                ; w ==
                    bytes &&
                    c.stats.bytesInFlight == 0L
            },
        )
    }

    private fun probesTo(p: EndpointPair): List<Int> = p.clientDatagramSizes.filter { it > 1200 }

    private val noIdle = quicConfig { maxIdleTimeout = kotlin.time.Duration.ZERO } // the long scenarios outlive the 30 s idle timer

    @Test fun searchConvergesTo1452OnCleanPath() {
        val (p, c) = pair()
        try {
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 }, "mtu ${c.stats.pathMtu}")
            assertTrue(
                p.clientDatagramSizes.any {
                    it ==
                        1452
                },
                "a full-size datagram was sent",
            )
        } finally {
            p.close()
        }
    }

    /** The client sends a little on a new stream, from wherever [EndpointPair.clientSource] now says, until the server has it. */
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

    /** The server sends [bytes] on a new stream and the pair runs until everything is acknowledged. */
    private fun download(
        p: EndpointPair,
        s: ConnectionCore,
        bytes: Int = 300_000,
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

    /**
     * Review finding 24, RFC 8899 section 4.3 and RFC 9000 section 14: a path the client moved the server to had no DPLPMTUD. A NAT
     * rebinding kept the old MTU (1452 here) without black-hole detection, so when the new port's route carried only 1280 bytes the
     * server kept sending datagrams that vanished; a path to a new address stayed at 1200 for life.
     */
    @Test fun serverPathsAfterClientMovesKeepPmtud() {
        val (p, c) = pair(clientQuic = noIdle, serverQuic = noIdle)
        try {
            val s = p.server.connections().single()
            download(p, s)
            assertTrue(p.runUntil(20.seconds) { s.stats.pathMtu == 1452 }, "the server's search: ${s.stats.pathMtu}")
            // NAT rebinding: same IP, new port
            val rebound = InetSocketAddress("10.0.0.1", 40001)
            p.clientSource = rebound
            p.clientListens += rebound
            clientSends(p, c, s)
            assertEquals(rebound, s.remoteAddressForTest)
            assertTrue(s.paths.active.pmtud != null, "the rebound path runs DPLPMTUD")
            assertEquals(1452, s.stats.pathMtu, "and keeps the measured MTU as its start")
            p.linkMtuToClient = 1280 // the new route is narrower
            download(p, s, 200_000)
            assertTrue(p.runUntil(30.seconds) { s.stats.pathMtu == 1200 }, "black-hole fallback on the rebound path: ${s.stats.pathMtu}")
            // a migration to a new address: the search starts again from 1200
            p.linkMtuToClient = 1500
            val moved = InetSocketAddress("10.0.0.9", 40000)
            p.clientSource = moved
            p.clientListens += moved
            clientSends(p, c, s)
            assertEquals(moved, s.remoteAddressForTest)
            assertTrue(s.paths.active.pmtud != null, "the migrated path runs DPLPMTUD")
            download(p, s)
            assertTrue(p.runUntil(20.seconds) { s.stats.pathMtu > 1200 }, "the search on the new address: ${s.stats.pathMtu}")
        } finally {
            p.close()
        }
    }

    @Test fun searchStopsBelowLinkMtu() {
        val (p, c) = pair(linkMtu = 1400)
        try {
            transfer(p, c)
            assertTrue(p.runUntil(30.seconds) { c.pmtudSearchDoneForTest }, "search done: mtu ${c.stats.pathMtu}")
            assertTrue(c.stats.pathMtu in 1380..1400, "mtu ${c.stats.pathMtu}")
        } finally {
            p.close()
        }
    }

    @Test fun atMostThreeLostProbesPerSize() {
        val (p, c) = pair(linkMtu = 1200)
        try {
            transfer(p, c)
            assertTrue(p.runUntil(60.seconds) { c.pmtudSearchDoneForTest }, "search gives up: mtu ${c.stats.pathMtu}")
            val perSize = probesTo(p).groupingBy { it }.eachCount()
            assertTrue(perSize.isNotEmpty() && perSize.values.all { it <= 3 }, "probes per size: $perSize")
            assertEquals(1200, c.stats.pathMtu)
        } finally {
            p.close()
        }
    }

    @Test fun probeLossNotCongestion() {
        // RFC 9000 section 14.4: a lost probe is not a congestion signal
        val (p, c) = pair(linkMtu = 1200)
        try {
            val cwnd = c.stats.cwnd
            assertTrue(p.runUntil(60.seconds) { c.pmtudSearchDoneForTest })
            assertTrue(probesTo(p).size >= 3, "probes were lost: ${probesTo(p)}")
            assertEquals(cwnd, c.stats.cwnd, "the window did not move for lost probes")
            assertEquals(
                0L,
                c.stats.lostPackets - c.stats.lostPackets,
            )
        } finally {
            p.close()
        }
    }

    @Test fun blackHoleFallsBackTo1200AndPauses60s() {
        val (p, c) = pair(clientQuic = noIdle, serverQuic = noIdle)
        try {
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 }, "initial search: ${c.stats.pathMtu}")
            p.linkMtuToServer = 1280
            val t0 = p.now // the path shrank under us: full-size datagrams vanish
            val id = c.openStream(true)
            var w = 0
            val bytes = 200_000
            assertTrue(
                p.runUntil(30.seconds) {
                    if (w <
                        bytes
                    ) {
                        w +=
                            c.writeStream(
                                id,
                                ByteArray(minOf(16384, bytes - w)),
                                0,
                                minOf(16384, bytes - w),
                                w + minOf(16384, bytes - w) == bytes,
                            )
                    }
                    ; c.stats.pathMtu ==
                        1200
                },
                "fell back to 1200: mtu ${c.stats.pathMtu}, state ${c.state}, pto ${c.stats.ptoCount}, lost ${c.stats.lostPackets}, inflight ${c.stats.bytesInFlight}",
            )
            val fellAt = p.now
            assertTrue(
                p.runUntil(30.seconds) {
                    if (w <
                        bytes
                    ) {
                        w +=
                            c.writeStream(
                                id,
                                ByteArray(minOf(16384, bytes - w)),
                                0,
                                minOf(16384, bytes - w),
                                w + minOf(16384, bytes - w) == bytes,
                            )
                    }
                    ; w ==
                        bytes &&
                        c.stats.bytesInFlight == 0L
                },
                "the transfer completes at 1200 (state ${c.state}, mtu ${c.stats.pathMtu})",
            )
            val probesBefore = c.pmtudProbesSentForTest
            p.runUntil(59.seconds) { false }
            assertEquals(probesBefore, c.pmtudProbesSentForTest, "no probe inside the 60 s pause")
            assertTrue(
                p.runUntil(30.seconds) { c.pmtudProbesSentForTest > probesBefore },
                "probing resumes after the pause (state ${c.state})",
            )
            assertTrue(p.now - fellAt >= 60.seconds, "resumed after ${p.now - fellAt}")
            assertTrue(c.ccMtuUpdatesForTest.contains(1200), "the congestion controller learned the new MTU: ${c.ccMtuUpdatesForTest}")
        } finally {
            p.close()
        }
    }

    @Test fun researchAfter600s() {
        val (p, c) = pair(linkMtu = 1300, clientQuic = noIdle, serverQuic = noIdle)
        try {
            transfer(p, c)
            assertTrue(p.runUntil(30.seconds) { c.pmtudSearchDoneForTest })
            val mtu = c.stats.pathMtu
            val n = c.pmtudProbesSentForTest
            p.linkMtuToServer = 1500
            p.linkMtuToClient = 1500 // the path grew; the search repeats after 600 s
            p.runUntil(590.seconds) { false }
            assertEquals(n, c.pmtudProbesSentForTest, "no probe before the re-search timer (state ${c.state})")
            assertTrue(p.runUntil(60.seconds) { c.pmtudProbesSentForTest > n }, "re-search started")
            assertTrue(
                p.runUntil(60.seconds) {
                    c.stats.pathMtu >
                        mtu
                },
                "and found more: ${c.stats.pathMtu}",
            )
        } finally {
            p.close()
        }
    }

    @Test fun noProbesWithoutDf() {
        val (p, c) = pair(caps = IoCapabilities.Portable)
        try {
            transfer(p, c)
            p.runUntil(5.seconds) { false }
            assertTrue(probesTo(p).isEmpty())
            assertEquals(1200, c.stats.pathMtu)
        } finally {
            p.close()
        }
    }

    @Test fun peerMaxUdpPayloadCapsSearch() {
        val (p, c) = pair(serverQuic = quicConfig { maxUdpPayloadSize = 1300 })
        try {
            transfer(p, c)
            assertTrue(p.runUntil(30.seconds) { c.pmtudSearchDoneForTest })
            assertTrue(c.stats.pathMtu in 1280..1300, "mtu ${c.stats.pathMtu}")
            assertTrue(probesTo(p).all { it <= 1300 })
        } finally {
            p.close()
        }
    }

    @Test fun mtuUpdatedEventAndStats() {
        val (p, c) = pair()
        try {
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            val updates = p.events[c]!!.filterIsInstance<ConnectionEvent.MtuUpdated>()
            assertTrue(updates.isNotEmpty())
            assertEquals(1452, updates.last().mtu)
            assertEquals(PathId.Initial, updates.last().path)
            assertTrue(
                updates.map { it.mtu }.zipWithNext().all { (a, b) ->
                    b >
                        a
                },
                "monotonic during the search: ${updates.map { it.mtu }}",
            )
        } finally {
            p.close()
        }
    }

    @Test fun ccNotifiedOnMtuChange() {
        val (p, c) = pair()
        try {
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            assertEquals(1452, c.ccMtuUpdatesForTest.last())
        } finally {
            p.close()
        }
    }

    @Test fun pmtudOffKeeps1200() {
        val (p, c) = pair(clientQuic = quicConfig { pmtud = false })
        try {
            transfer(p, c)
            p.runUntil(5.seconds) { false }
            assertTrue(probesTo(p).isEmpty())
            assertEquals(1200, c.stats.pathMtu)
        } finally {
            p.close()
        }
    }

    /** A black-hole pause left on a path that is no longer active must not keep the connection's deadline in the past (a timer loop that never sleeps). */
    @Test fun pauseOnFormerPathDoesNotStallTimers() {
        val (p, c) = pair(clientQuic = noIdle, serverQuic = noIdle)
        try {
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 }, "initial search: ${c.stats.pathMtu}")
            p.linkMtuToServer = 1280
            val id = c.openStream(true)
            var w = 0
            val bytes = 200_000
            assertTrue(
                p.runUntil(30.seconds) {
                    if (w <
                        bytes
                    ) {
                        w +=
                            c.writeStream(
                                id,
                                ByteArray(minOf(16384, bytes - w)),
                                0,
                                minOf(16384, bytes - w),
                                w + minOf(16384, bytes - w) == bytes,
                            )
                    }
                    ; c.stats.pathMtu ==
                        1200
                },
                "fell back to 1200",
            )
            p.linkMtuToServer = 1500
            val other = InetSocketAddress("10.0.0.7", 40000)
            val pid = c.addPath(p.serverAddr, p.now)
            p.clientSocketSources[pid] = other
            p.clientListens +=
                other
            c.probePath(pid, p.now)
            assertTrue(p.runUntil(5.seconds) { c.pathState(pid) == PathState.Validated }, "second path validated")
            c.switchPath(pid, p.now)
            p.runUntil(61.seconds) { false }
            c.onTimeout(p.now)
            assertTrue(
                c.nextTimeoutOrNever() > p.now,
                "deadline ${c.nextTimeoutOrNever()} is not in the past at ${p.now} (a stale PMTUD pause on the former path)",
            )
        } finally {
            p.close()
        }
    }

    /** A burst of lost full-size data packets on an otherwise healthy link is congestion, not a black hole: the ACK that declares them lost also acknowledges full-size packets sent after them. */
    @Test fun congestionBurstDoesNotFallBack() {
        val (p, c) = pair()
        try {
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 }, "initial search: ${c.stats.pathMtu}")
            val lostBefore = c.stats.lostPackets
            var dropped = 0
            p.filterToServer = { _, b ->
                if (dropped < 5 && b.size == 1452) {
                    dropped++
                    false
                } else {
                    true
                }
            } // five consecutive full-size datagrams vanish, the rest arrives
            transfer(p, c, 500_000)
            assertEquals(5, dropped)
            assertTrue(c.stats.lostPackets - lostBefore >= 5, "the burst was declared lost: ${c.stats.lostPackets - lostBefore}")
            assertEquals(1452, c.stats.pathMtu, "the MTU stays")
            assertTrue(
                p.events[c]!!.filterIsInstance<ConnectionEvent.MtuUpdated>().none {
                    it.mtu ==
                        1200
                },
                "no fallback to 1200: ${c.ccMtuUpdatesForTest}",
            )
        } finally {
            p.close()
        }
    }

    /**
     * A peer that stops answering for a while (a starved process: its datagrams wait in the socket, none is lost) draws
     * repeated PTOs, the black-hole answer for a path where nothing comes back. Once it answers, its ACKs cover the
     * full-size packets sent before the fallback: the path carried them, so the fallback was wrong and is undone, without
     * the 60 s pause and a new search (the 1200-byte MTU that KslDatagramIoTest saw after a 50 MiB transfer on a loaded host).
     */
    @Test fun stalledPeerIsNotABlackHole() {
        val (p, c) = pair(clientQuic = noIdle, serverQuic = noIdle)
        try {
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.pmtudSearchDoneForTest && c.stats.pathMtu == 1452 }, "initial search: ${c.stats.pathMtu}")
            val id = c.openStream(true)
            val bytes = 400_000
            var w = 0
            val write = {
                if (w < bytes) {
                    val n = minOf(16384, bytes - w)
                    w += c.writeStream(id, ByteArray(n), 0, n, w + n == bytes)
                }
            }
            p.runUntil(100.milliseconds) {
                write()
                false
            }
            p.serverStalled = true
            var maxPto = 0
            p.runUntil(1.seconds) {
                write()
                maxPto = maxOf(maxPto, c.stats.ptoCount)
                false
            }
            assertTrue(maxPto >= 2, "the stall drew repeated PTOs: $maxPto")
            assertEquals(1200, c.stats.pathMtu, "nothing came back: the sender assumed a black hole")
            p.serverStalled = false
            assertTrue(
                p.runUntil(30.seconds) {
                    write()
                    w == bytes && c.stats.bytesInFlight == 0L
                },
                "the transfer completes (state ${c.state})",
            )
            assertEquals(1452, c.stats.pathMtu, "the late ACKs of full-size packets undo the fallback: ${c.ccMtuUpdatesForTest}")
            assertTrue(c.pmtudSearchDoneForTest, "the search result stands, no pause and no new search")
        } finally {
            p.close()
        }
    }

    /**
     * Repeated PTOs mean a black hole only when packets above the base size are among the unanswered ones: a sender of
     * small packets alone (the receiving side of a transfer: ACKs, flow-control credit) whose peer stalls has lost nothing
     * to the MTU. The server of KslDatagramIoTest's upload ended at 1200 this way on a loaded host.
     */
    @Test fun unansweredSmallPacketsAreNotABlackHole() {
        val (p, c) = pair(clientQuic = noIdle, serverQuic = noIdle)
        try {
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.pmtudSearchDoneForTest && c.stats.pathMtu == 1452 }, "initial search: ${c.stats.pathMtu}")
            p.runUntil(2.seconds) { false } // the transfer's paced tail is sent and acknowledged
            assertEquals(0L, c.stats.bytesInFlight)
            p.serverStalled = true
            val mark = p.clientDatagramSizes.size
            val id = c.openStream(true)
            c.writeStream(id, ByteArray(100), 0, 100, true) // one small ack-eliciting packet the stalled peer does not answer
            var maxPto = 0
            p.runUntil(1.seconds) {
                maxPto = maxOf(maxPto, c.stats.ptoCount)
                false
            }
            assertTrue(maxPto >= 2, "the stall drew repeated PTOs: $maxPto")
            assertEquals(
                1452,
                c.stats.pathMtu,
                "no packet above 1200 went unanswered: ${c.ccMtuUpdatesForTest} sent ${p.clientDatagramSizes.drop(mark)}",
            )
            p.serverStalled = false
            assertTrue(p.runUntil(10.seconds) { c.stats.bytesInFlight == 0L })
            assertTrue(c.pmtudSearchDoneForTest, "no pause, no new search")
        } finally {
            p.close()
        }
    }

    /**
     * Threat-model 3.16: ICMP Packet Too Big is not an input of the core (quic-go CVE-2024-53259); the path MTU moves only on acknowledged probes and
     * on the loss-based black-hole detector. Whatever an off-path sender injects — a PTB-shaped datagram quoting one of our packets, a truncated copy of
     * a real packet, a forged short header carrying our CID, garbage — leaves the MTU where the probes put it.
     */
    @Test fun negative_icmpPtbIgnored() {
        val (p, c) = pair()
        try {
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 }, "initial search: ${c.stats.pathMtu}")
            val updates = p.events[c]!!.filterIsInstance<ConnectionEvent.MtuUpdated>().size
            val real = p.serverSent.last { it.second[0].toInt() and 0x80 == 0 }.second // a 1-RTT datagram of this connection
            val ptb =
                ByteArray(28 + 64).also {
                    it[0] = 0x45
                    it[9] = 17
                    it[2] = 0x05
                    it[3] = 0x00 // "MTU 1280"
                    real.copyInto(it, 28, 0, minOf(64, real.size))
                }
            val forged =
                listOf(
                    ptb,
                    real.copyOf(minOf(real.size, 1280 - 28)),
                    real.copyOf().also {
                        it[it.size - 1] =
                            (it[it.size - 1] + 1).toByte()
                    },
                    ByteArray(1280) { (it * 7).toByte() },
                )
            for (from in listOf(p.serverAddr, InetSocketAddress("10.9.9.9", 9))) for (d in forged) p.feed(p.client, d, from)
            transfer(p, c, 100_000)
            assertEquals(1452, c.stats.pathMtu)
            assertEquals(updates, p.events[c]!!.filterIsInstance<ConnectionEvent.MtuUpdated>().size, "no MTU change from injected input")
            assertEquals(null, p.closed(c))
        } finally {
            p.close()
        }
    }

    // ---- ICMP Packet Too Big and EMSGSIZE as hints (RFC 8899 section 4.6, RFC 9000 section 14.2.1) ----

    /** The start of a 1-RTT datagram [c] sends on its active path, as an ICMP message quotes it: first byte and DCID, then anything. */
    private fun quoteOf(
        c: ConnectionCore,
        dcid: ByteArray = c.remoteCid.toByteArray(),
    ): ByteArray = byteArrayOf(0x43) + dcid + ByteArray(24) { (it * 13).toByte() }

    /** A PTB to the client about its datagram to [to] reporting [mtu] (IP packet size). */
    private fun ptb(
        p: EndpointPair,
        c: ConnectionCore,
        mtu: Int,
        quote: ByteArray = quoteOf(c),
        to: InetSocketAddress = p.serverAddr,
        socket: PathId = PathId.Initial,
    ) = p.client.handlePacketTooBig(quote, quote.size, to, mtu, p.now, socket)

    /** Starts the client's DPLPMTUD now (DF granted after the handshake) and runs until it sends a probe larger than [above]; its size. */
    private fun probeAbove(
        p: EndpointPair,
        c: ConnectionCore,
        above: Int,
    ): Int {
        var seen = 0
        p.filterToServer = { _, b ->
            if (seen == 0 && b.size > above && c.path.pmtud?.probeInFlightForTest == b.size) seen = b.size
            true
        }
        c.setPathCapabilities(PathId.Initial, df)
        assertTrue(p.runUntil(10.seconds) { seen > 0 }, "no probe above $above")
        p.filterToServer = { _, _ -> true }
        return seen
    }

    @Test fun ptbQuotingAProbeEndsThatSizeAtOnce() {
        // a 1350-byte link: the probe above it is lost; a PTB reporting 1378 (payload 1350) ends it at once, and the next probe is at
        // most 1350 bytes, without the three-probe, 3 x PTO wait
        val (p, c) = pair(linkMtu = 1350, caps = IoCapabilities.Portable)
        try {
            val probe = probeAbove(p, c, 1350)
            val sizesBefore = p.clientDatagramSizes.size
            val t0 = p.now
            ptb(p, c, 1378)
            assertEquals(1L, p.client.stats.ptbAccepted)
            assertTrue(
                p.runUntil(5.seconds) { p.clientDatagramSizes.drop(sizesBefore).any { it in 1201..1350 } },
                "a probe of at most 1350 after the PTB (the lost one was $probe)",
            )
            assertTrue(p.now - t0 < c.stats.smoothedRtt * 3 + 100.milliseconds, "without waiting for the lost probe: ${p.now - t0}")
            assertTrue(p.clientDatagramSizes.drop(sizesBefore).none { it > 1350 && it != probe }, "nothing above the reported size again")
        } finally {
            p.close()
        }
    }

    @Test fun negative_ptbBelowQuicMinimumIgnored() {
        // RFC 9000 section 14.2.1: "MUST ignore an ICMP message that claims the PMTU has decreased below QUIC's smallest allowed
        // maximum datagram size": an IPv4 MTU of 1227 leaves 1199 bytes of UDP payload
        val (p, c) = pair()
        try {
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            ptb(p, c, 1227)
            assertEquals(0L, p.client.stats.ptbAccepted)
            assertEquals(1L, p.client.stats.ptbIgnored)
            assertEquals(0, c.path.pmtud!!.confirmingForTest)
            transfer(p, c, 50_000)
            assertEquals(1452, c.stats.pathMtu)
        } finally {
            p.close()
        }
    }

    @Test fun negative_ptbWithForeignCidIgnored() {
        // the quote must be one of our datagrams on that path: an off-path attacker who does not know the connection ID cannot aim one
        val (p, c) = pair()
        try {
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            ptb(p, c, 1328, quote = quoteOf(c, ByteArray(c.remoteCid.length) { 0x5a }))
            ptb(p, c, 1328, quote = byteArrayOf(0x43, 1, 2)) // too short to hold the ID
            ptb(p, c, 1328, quote = byteArrayOf(0xc3.toByte()) + ByteArray(30)) // a long header that is not ours
            assertEquals(0L, p.client.stats.ptbAccepted)
            assertEquals(3L, p.client.stats.ptbIgnored)
            assertEquals(0, c.path.pmtud!!.confirmingForTest)
        } finally {
            p.close()
        }
    }

    @Test fun negative_ptbNeverLowersMtuWithoutConfirmation() {
        // a PTB below the current size lowers nothing by itself: a probe of the current size goes out, and its ACK forgets the PTB
        val (p, c) = pair()
        try {
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            val sizesBefore = p.clientDatagramSizes.size
            ptb(p, c, 1328)
            assertEquals(1L, p.client.stats.ptbAccepted)
            assertEquals(1452, c.stats.pathMtu, "not lowered by the PTB")
            assertTrue(p.runUntil(5.seconds) { c.path.pmtud!!.confirmingForTest == 0 }, "the confirmation probe was acknowledged")
            assertTrue(p.clientDatagramSizes.drop(sizesBefore).contains(1452), "a 1452-byte confirmation probe went out")
            transfer(p, c, 50_000)
            assertEquals(1452, c.stats.pathMtu)
        } finally {
            p.close()
        }
    }

    @Test fun ptbConfirmedByLostProbesLowersToPtbSize() {
        // the link narrows to 1320 and a PTB says 1328 (payload 1300): three lost confirmation probes of 1452 lower the MTU to the
        // reported 1300 (a multiple of the 20-byte step above the base), with no 60 s black-hole pause before the search goes on
        val (p, c) = pair(clientQuic = noIdle, serverQuic = noIdle)
        try {
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            assertTrue(p.runUntil(10.seconds) { !c.streams.hasStreamData() && c.stats.bytesInFlight == 0L }, "the transfer drained")
            p.linkMtuToServer = 1320
            p.linkMtuToClient = 1320
            val before = p.events[c]!!.filterIsInstance<ConnectionEvent.MtuUpdated>().size
            ptb(p, c, 1328)
            // a trickle of small packets, as an application keeps sending: their ACKs show each confirmation probe lost within an
            // RTT (RFC 9002 section 6.1), before the PTOs or full-size losses that would call it a black hole
            val id = c.openStream(true)

            fun changes() =
                p.events[c]!!
                    .filterIsInstance<ConnectionEvent.MtuUpdated>()
                    .drop(before)
                    .map { it.mtu }
            val ok =
                p.runUntil(10.seconds) {
                    c.writeStream(id, ByteArray(100), 0, 100, false)
                    1300 in changes()
                }
            assertTrue(ok, "lowered to the PTB size: ${changes()}")
            assertEquals(1300, changes().first(), "straight to the PTB size, not to the base")
            val m = c.path.pmtud!!
            assertTrue(m.pausedForTest.not(), "no black-hole pause")
            transfer(p, c, 50_000)
            assertTrue(c.stats.pathMtu in 1300..1320, "the search goes on from there: ${c.stats.pathMtu}")
            assertEquals(null, p.closed(c))
        } finally {
            p.close()
        }
    }

    @Test fun negative_ptbFloodIsRateLimited() {
        // 10 000 valid-looking PTB messages in one second: at most 64 are looked at, the rest only counted
        val (p, c) = pair()
        try {
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            val start = p.now
            for (i in 0 until 10_000) {
                p.now = start + (i * 100).toLong().let { kotlin.time.Duration.parse("${it}us") }
                ptb(p, c, 1440)
            }
            val s = p.client.stats
            assertTrue(s.ptbAccepted + s.ptbIgnored == 10_000L, "$s")
            assertTrue(s.ptbAccepted <= 64, "at most 64 a second: ${s.ptbAccepted}")
            assertTrue(s.ptbIgnored >= 9_936, "${s.ptbIgnored}")
        } finally {
            p.close()
        }
    }

    @Test fun negative_ptbForNonActivePathIgnored() {
        // a PTB about a datagram to another address, or one that arrived on another socket, says nothing about the active path
        val (p, c) = pair()
        try {
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            ptb(p, c, 1328, to = InetSocketAddress("10.0.0.99", 443))
            ptb(p, c, 1328, socket = PathId(7))
            assertEquals(0L, p.client.stats.ptbAccepted)
            assertEquals(2L, p.client.stats.ptbIgnored)
            assertEquals(0, c.path.pmtud!!.confirmingForTest)
        } finally {
            p.close()
        }
    }

    @Test fun negative_ptbIgnoredWhenHintsAreOff() {
        val (p, c) = pair(clientQuic = quicConfig { pmtudIcmpHints = false })
        try {
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            ptb(p, c, 1328)
            assertEquals(0L, p.client.stats.ptbAccepted)
            assertEquals(1L, p.client.stats.ptbIgnored)
        } finally {
            p.close()
        }
    }

    @Test fun emsgsizeOnProbeCountsAsLost() {
        // the kernel refused the probe as larger than the MTU it knows (EMSGSIZE): that size is settled at once, like a probe lost
        // three times, and the next probe is smaller
        val (p, c) = pair(linkMtu = 1350, caps = IoCapabilities.Portable)
        try {
            val probe = probeAbove(p, c, 1350)
            val sizesBefore = p.clientDatagramSizes.size
            val t0 = p.now
            c.onEmsgsize(probe)
            assertTrue(
                p.runUntil(5.seconds) { p.clientDatagramSizes.drop(sizesBefore).any { it in 1201 until probe } },
                "a smaller probe next",
            )
            assertTrue(p.now - t0 < c.stats.smoothedRtt * 3 + 100.milliseconds, "without waiting: ${p.now - t0}")
            assertTrue(p.clientDatagramSizes.drop(sizesBefore).none { it >= probe }, "the refused size is not tried again")
        } finally {
            p.close()
        }
    }
}
