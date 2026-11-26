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

    private val noIdle = quicConfig { maxIdleTimeout = null } // the long scenarios outlive the 30 s idle timer

    @Test fun searchConvergesTo1452OnCleanPath() {
        val (p, c) = pair()
        p.use { _ ->
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 }, "mtu ${c.stats.pathMtu}")
            assertTrue(
                p.clientDatagramSizes.any {
                    it ==
                        1452
                },
                "a full-size datagram was sent",
            )
        }
    }

    /**
     * RFC 8899 sections 4.3 and 5.1.1: "A PL MAY inhibit sending probe packets when no application data has been sent since the
     * previous probe packet". A connection's first search begins with its first application data after the handshake was confirmed:
     * a client that only downloads, or idles or closes after its handshake, sends no full-size probe (the interop runner's zerortt
     * case counted three of them, 3.8 KB, against the client's 1-RTT budget, int37). The data that follows begins the search, which
     * still raises the size, and the server that sends the download searches on its own.
     */
    @Test fun negative_noProbeBeforeApplicationDataAfterConfirmation() {
        val (p, c) = pair()
        p.use { _ ->
            assertTrue(!p.runUntil(5.seconds) { probesTo(p).isNotEmpty() }, "an idle client probed: ${probesTo(p)}")
            val s = p.server.connections().single()
            download(p, s) // the client only acknowledges
            assertTrue(probesTo(p).isEmpty(), "a downloading client probed: ${probesTo(p)}")
            assertEquals(1200, c.stats.pathMtu)
            assertTrue(p.runUntil(20.seconds) { s.stats.pathMtu == 1452 }, "the sender searched: server mtu ${s.stats.pathMtu}")
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 }, "its data began the client's search: mtu ${c.stats.pathMtu}")
        }
    }

    /**
     * RFC 8899 section 4.3 (Pmtud.waitsForData), an application's migration to a new socket (ConnectionRuntime.openPath: addPath,
     * then the socket's capabilities): the new path's search waits for application data unless the connection already sent some
     * after confirmation. A download-only client that migrates sends no probe from the new socket; one that sent data probes there at
     * once.
     */
    @Test fun aMigrationToANewSocketKeepsTheWaitForData() {
        for (sent in listOf(false, true)) {
            val (p, c) = pair(clientQuic = noIdle, serverQuic = noIdle)
            p.use { _ ->
                val s = p.server.connections().single()
                if (sent) clientSends(p, c, s) else download(p, s, 50_000)
                val other = InetSocketAddress("10.0.0.7", 40000)
                val pid = c.addPath(p.serverAddr, p.now)
                c.setPathCapabilities(pid, df)
                p.clientSocketSources[pid] = other
                p.clientListens += other
                c.probePath(pid, p.now)
                assertTrue(p.runUntil(5.seconds) { c.pathState(pid) == PathState.Validated }, "second path validated")
                c.switchPath(pid, p.now)
                val before = p.clientDatagramSizes.size
                p.runUntil(5.seconds) { false }
                val probes = p.clientDatagramSizes.drop(before).filter { it > 1200 }
                if (sent) {
                    assertTrue(probes.isNotEmpty(), "a client that sent data probes from the new socket at once")
                } else {
                    assertTrue(probes.isEmpty(), "a download-only client probed from the new socket: $probes")
                    assertTrue(c.path.pmtud!!.awaitingData, "the new socket's search waits for data")
                }
            }
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
        p.use { _ ->
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
        }
    }

    @Test fun searchStopsBelowLinkMtu() {
        val (p, c) = pair(linkMtu = 1400)
        p.use { _ ->
            transfer(p, c)
            // two sizes above the link, three probes each about a second apart: done within seconds (a 16 s PROBE_TIMER per probe
            // took about 100 s here)
            assertTrue(p.runUntil(10.seconds) { c.pmtudSearchDoneForTest }, "search done: mtu ${c.stats.pathMtu}")
            assertTrue(c.stats.pathMtu in 1380..1400, "mtu ${c.stats.pathMtu}")
        }
    }

    @Test fun atMostThreeLostProbesPerSize() {
        val (p, c) = pair(linkMtu = 1200)
        p.use { _ ->
            transfer(p, c)
            assertTrue(p.runUntil(60.seconds) { c.pmtudSearchDoneForTest }, "search gives up: mtu ${c.stats.pathMtu}")
            val perSize = probesTo(p).groupingBy { it }.eachCount()
            assertTrue(perSize.isNotEmpty() && perSize.values.all { it <= 3 }, "probes per size: $perSize")
            assertEquals(1200, c.stats.pathMtu)
        }
    }

    @Test fun negative_aLostProbeFailsNoEarlierThanOneSecondAfterItWasSent() {
        // RFC 8899 section 5.1.1: the PROBE_TIMER "MUST NOT be smaller than 1 second". On a 1400-byte link the probes above it are lost
        // and loss detection declares each within a few 10 ms RTTs; the next probe still waits until a second after the lost one was
        // sent (before 0.3.0 it went at once, about 30 ms later), and not the 15 s of the section's SHOULD (see the RFC 8899 row)
        val (p, c) = pair(linkMtu = 1400)
        p.use { _ ->
            val lost = ArrayList<Pair<io.kuicksilver.quic.TimeMark, Int>>()
            p.filterToServer = { _, b ->
                if (b.size > 1400) lost += p.now to b.size
                true
            }
            transfer(p, c)
            assertTrue(p.runUntil(30.seconds) { lost.size >= 3 }, "lost probes: $lost")
            for (i in 1 until lost.size) {
                val gap = lost[i].first - lost[i - 1].first
                assertTrue(gap >= 1.seconds && gap < 5.seconds, "probe ${i + 1} (${lost[i].second} B) after $gap: $lost")
            }
        }
    }

    @Test fun negative_aLateAckOfAProbeSentBeforeABlackHoleVerdictRaisesNothing() {
        // a probe declared lost, then a black-hole verdict (back to 1200 and a 60 s pause): an acknowledgment of that probe arriving
        // later is about the path before the verdict, as `Pmtud.onPacketAcked` judges a late full-size packet only after the packets
        // the verdict rested on; it must not raise the MTU during the pause
        val m = Pmtud(upperBound = 1452)
        val t = io.kuicksilver.quic.TimeMark(1_000_000_000L)
        val size = m.nextProbeSize(t)
        assertTrue(size > 1200)
        m.onProbeSent(10, size)
        m.onProbeDeclaredLost(10, t + 50.milliseconds)
        m.onBlackHole(t + 100.milliseconds)
        assertEquals(0, m.takeLostProbeIn(10, 10), "the probe sent before the verdict is no longer matched")
        assertTrue(!m.hasLostProbes)
        assertEquals(1200, m.current)
    }

    @Test fun probeLossNotCongestion() {
        // RFC 9000 section 14.4 and RFC 8899 section 3 item 7: a lost probe is not a congestion signal. The probes go out during a
        // transfer on a link that drops everything above 1200 bytes and nothing else, so every loss is a probe's: the controller
        // never left slow start. 0.3.0 cross-review: this test compared lostPackets with itself and ran with no traffic at all
        val (p, c) = pair(linkMtu = 1200)
        p.use { _ ->
            transfer(p, c)
            assertTrue(p.runUntil(60.seconds) { c.pmtudSearchDoneForTest })
            assertTrue(probesTo(p).size >= 3, "probes were lost: ${probesTo(p)}")
            val ssthresh =
                when (val cc = c.path.cc) {
                    is io.kuicksilver.quic.Cubic -> cc.ssthresh
                    is io.kuicksilver.quic.NewReno -> cc.ssthresh
                    else -> error("unexpected controller $cc")
                }
            assertEquals(Long.MAX_VALUE, ssthresh, "no congestion event for the lost probes")
            assertTrue(c.stats.cwnd > 12_000L, "the window grew with the transfer: ${c.stats.cwnd}")
        }
    }

    @Test fun blackHoleFallsBackTo1200AndPauses60s() {
        val (p, c) = pair(clientQuic = noIdle, serverQuic = noIdle)
        p.use { _ ->
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
        }
    }

    @Test fun researchAfter600s() {
        val (p, c) = pair(linkMtu = 1300, clientQuic = noIdle, serverQuic = noIdle)
        p.use { _ ->
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
        }
    }

    @Test fun noProbesWithoutDf() {
        val (p, c) = pair(caps = IoCapabilities.Portable)
        p.use { _ ->
            transfer(p, c)
            p.runUntil(5.seconds) { false }
            assertTrue(probesTo(p).isEmpty())
            assertEquals(1200, c.stats.pathMtu)
        }
    }

    @Test fun peerMaxUdpPayloadCapsSearch() {
        val (p, c) = pair(serverQuic = quicConfig { pathMtu { maxReceive = 1300 } })
        p.use { _ ->
            transfer(p, c)
            assertTrue(p.runUntil(30.seconds) { c.pmtudSearchDoneForTest })
            assertTrue(c.stats.pathMtu in 1280..1300, "mtu ${c.stats.pathMtu}")
            assertTrue(probesTo(p).all { it <= 1300 })
        }
    }

    @Test fun mtuUpdatedEventAndStats() {
        val (p, c) = pair()
        p.use { _ ->
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
        }
    }

    @Test fun ccNotifiedOnMtuChange() {
        val (p, c) = pair()
        p.use { _ ->
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            assertEquals(1452, c.ccMtuUpdatesForTest.last())
        }
    }

    @Test fun pmtudOffKeeps1200() {
        val (p, c) = pair(clientQuic = quicConfig { pathMtu { discovery = false } })
        p.use { _ ->
            transfer(p, c)
            p.runUntil(5.seconds) { false }
            assertTrue(probesTo(p).isEmpty())
            assertEquals(1200, c.stats.pathMtu)
        }
    }

    /** A black-hole pause left on a path that is no longer active must not keep the connection's deadline in the past (a timer loop that never sleeps). */
    @Test fun pauseOnFormerPathDoesNotStallTimers() {
        val (p, c) = pair(clientQuic = noIdle, serverQuic = noIdle)
        p.use { _ ->
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
        }
    }

    /** A burst of lost full-size data packets on an otherwise healthy link is congestion, not a black hole: the ACK that declares them lost also acknowledges full-size packets sent after them. */
    @Test fun congestionBurstDoesNotFallBack() {
        val (p, c) = pair()
        p.use { _ ->
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
        p.use { _ ->
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
        }
    }

    /**
     * Repeated PTOs mean a black hole only when packets above the base size are among the unanswered ones: a sender of
     * small packets alone (the receiving side of a transfer: ACKs, flow-control credit) whose peer stalls has lost nothing
     * to the MTU. The server of KslDatagramIoTest's upload ended at 1200 this way on a loaded host.
     */
    @Test fun unansweredSmallPacketsAreNotABlackHole() {
        val (p, c) = pair(clientQuic = noIdle, serverQuic = noIdle)
        p.use { _ ->
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
        }
    }

    /**
     * Threat-model 3.16: ICMP Packet Too Big is not an input of the core (quic-go CVE-2024-53259); the path MTU moves only on acknowledged probes and
     * on the loss-based black-hole detector. Whatever an off-path sender injects — a PTB-shaped datagram quoting one of our packets, a truncated copy of
     * a real packet, a forged short header carrying our CID, garbage — leaves the MTU where the probes put it.
     */
    @Test fun negative_icmpPtbIgnored() {
        val (p, c) = pair()
        p.use { _ ->
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
        // a search waits for the connection's first application data after confirmation (Pmtud.waitsForData): some goes first
        val id = c.openStream(true)
        c.writeStream(id, ByteArray(100), 0, 100, true)
        assertTrue(p.runUntil(5.seconds) { c.stats.bytesInFlight == 0L }, "the data is acknowledged")
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
        p.use { _ ->
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
        }
    }

    @Test fun negative_ptbBelowQuicMinimumIgnored() {
        // RFC 9000 section 14.2.1: "MUST ignore an ICMP message that claims the PMTU has decreased below QUIC's smallest allowed
        // maximum datagram size": an IPv4 MTU of 1227 leaves 1199 bytes of UDP payload
        val (p, c) = pair()
        p.use { _ ->
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            ptb(p, c, 1227)
            assertEquals(0L, p.client.stats.ptbAccepted)
            assertEquals(1L, p.client.stats.ptbIgnored)
            assertEquals(0, c.path.pmtud!!.confirmingForTest)
            transfer(p, c, 50_000)
            assertEquals(1452, c.stats.pathMtu)
        }
    }

    @Test fun negative_ptbWithForeignCidIgnored() {
        // the quote must be one of our datagrams on that path: an off-path attacker who does not know the connection ID cannot aim one
        val (p, c) = pair()
        p.use { _ ->
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            ptb(p, c, 1328, quote = quoteOf(c, ByteArray(c.remoteCid.length) { 0x5a }))
            ptb(p, c, 1328, quote = byteArrayOf(0x43, 1, 2)) // too short to hold the ID
            ptb(p, c, 1328, quote = byteArrayOf(0xc3.toByte()) + ByteArray(30)) // a long header that is not ours
            assertEquals(0L, p.client.stats.ptbAccepted)
            assertEquals(3L, p.client.stats.ptbIgnored)
            assertEquals(0, c.path.pmtud!!.confirmingForTest)
        }
    }

    private fun mtuChanges(
        p: EndpointPair,
        c: ConnectionCore,
        before: Int,
    ): List<Int> =
        p.events[c]!!
            .filterIsInstance<ConnectionEvent.MtuUpdated>()
            .drop(before)
            .map { it.mtu }

    private fun mtuUpdates(
        p: EndpointPair,
        c: ConnectionCore,
    ): Int = p.events[c]!!.filterIsInstance<ConnectionEvent.MtuUpdated>().size

    @Test fun negative_forgedPtbDropIsProvisionalAndSuspendsPtbs() {
        // RFC 8899 section 4.6.2, "BASE_PLPMTU <= PL_PTB_SIZE < PLPMTU": "The PLPMTU SHOULD be set to BASE_PLPMTU"; RFC 9000 section
        // 14.2.1: "Any reduction in QUIC's maximum datagram size in response to ICMP messages MAY be provisional". The PTB drops the
        // size to 1200 at once; the link still carries 1452 (the PTB was forged), so the probe of 1452 that follows is acknowledged and
        // restores it, and PTBs are not processed for the next 600 s (RFC 8899 section 8: "suspend processing of PTB messages")
        val (p, c) = pair(clientQuic = noIdle, serverQuic = noIdle)
        p.use { _ ->
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            val before = mtuUpdates(p, c)
            val sizesBefore = p.clientDatagramSizes.size
            ptb(p, c, 1328)
            assertEquals(1L, p.client.stats.ptbAccepted)
            assertEquals(1200, c.stats.pathMtu, "dropped to the base at once")
            assertTrue(p.runUntil(5.seconds) { c.stats.pathMtu == 1452 }, "restored by the acknowledged probe: ${mtuChanges(p, c, before)}")
            assertTrue(p.clientDatagramSizes.drop(sizesBefore).contains(1452), "a 1452-byte probe went out")
            assertEquals(listOf(1200, 1452), mtuChanges(p, c, before))
            assertTrue(c.path.pmtud!!.ptbSuspendedForTest, "PTB processing suspended")
            ptb(p, c, 1328)
            assertEquals(1452, c.stats.pathMtu, "a PTB while suspended changes nothing")
            transfer(p, c, 50_000)
            assertEquals(1452, c.stats.pathMtu)
            assertEquals(null, p.closed(c))
        }
    }

    @Test fun negative_forgedPtbsCannotHoldThePathAtTheBase() {
        // an attacker who can forge valid PTBs sends one every 5 s for 1300 s: each disproved drop suspends PTB processing for 600 s,
        // so the path is at 1200 at most three times, each for the round trip of one probe
        val (p, c) = pair(clientQuic = noIdle, serverQuic = noIdle)
        p.use { _ ->
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            val before = mtuUpdates(p, c)
            var atBase = 0
            repeat(260) {
                ptb(p, c, 1328)
                p.runUntil(5.seconds) { false }
                if (c.stats.pathMtu == 1200) atBase++
            }
            val drops = mtuChanges(p, c, before).count { it == 1200 }
            assertTrue(drops in 1..3, "provisional drops: $drops (${mtuChanges(p, c, before)})")
            assertEquals(0, atBase, "the probe restored 1452 within 5 s every time")
            assertEquals(1452, c.stats.pathMtu)
            assertEquals(null, p.closed(c))
        }
    }

    @Test fun ptbDropsToBaseThenSearchesFromItsSize() {
        // the link narrows to 1320 and a PTB says 1328 (payload 1300): the size drops to 1200 at once (RFC 8899 section 4.6.2); the
        // probe of 1452 is lost, the drop stands, and the search starts at the reported 1300 (a multiple of the 20-byte step above the
        // base: "The PL_PTB_SIZE reported in the PTB message can be used to initialize a search algorithm"), with no black-hole pause
        val (p, c) = pair(clientQuic = noIdle, serverQuic = noIdle)
        p.use { _ ->
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            assertTrue(p.runUntil(10.seconds) { !c.streams.hasStreamData() && c.stats.bytesInFlight == 0L }, "the transfer drained")
            p.linkMtuToServer = 1320
            p.linkMtuToClient = 1320
            val before = mtuUpdates(p, c)
            val sizesBefore = p.clientDatagramSizes.size
            ptb(p, c, 1328)
            assertEquals(1200, c.stats.pathMtu, "to the base at once")
            // a trickle of small packets, as an application keeps sending: their ACKs show the probe of 1452 lost (RFC 9002 section 6.1)
            val id = c.openStream(true)
            val ok =
                p.runUntil(10.seconds) {
                    c.writeStream(id, ByteArray(100), 0, 100, false)
                    1300 in mtuChanges(p, c, before)
                }
            assertTrue(ok, "the search reached the PTB size: ${mtuChanges(p, c, before)}")
            assertEquals(listOf(1200, 1300), mtuChanges(p, c, before).take(2))
            val probes = p.clientDatagramSizes.drop(sizesBefore).filter { it > 1200 }
            assertEquals(listOf(1452, 1300), probes.take(2), "the old size once, then the PTB size first: $probes")
            assertTrue(!c.path.pmtud!!.pausedForTest, "no black-hole pause")
            transfer(p, c, 50_000)
            assertTrue(c.stats.pathMtu in 1300..1320, "the search goes on from there: ${c.stats.pathMtu}")
            assertEquals(null, p.closed(c))
        }
    }

    @Test fun negative_aLateAckOfTheOldSizeAfterTheDropStoodRestoresItAndSuspendsPtbs() {
        // the probe of the old size was declared lost (the drop stands, the search starts at the PTB's size), then acknowledged after
        // all: the PTB was wrong; the size comes back and PTB processing is suspended (RFC 8899 section 8)
        val m = Pmtud(upperBound = 1452, start = 1452)
        val t = io.kuicksilver.quic.TimeMark(1_000_000_000L)
        assertTrue(m.onPtb(1300, t))
        assertEquals(1200, m.current)
        assertEquals(1452, m.nextProbeSize(t), "the old size first")
        m.onProbeSent(10, 1452)
        m.onProbeDeclaredLost(10, t + 50.milliseconds)
        m.onTimeout(t + 1.seconds)
        assertEquals(0, m.confirmingForTest, "the drop stands")
        assertEquals(1300, m.nextProbeSize(t + 1.seconds), "the search starts at the PTB size")
        m.onProbeSent(11, 1300)
        assertTrue(m.ackLostProbesIn(10, 10, t + 1100.milliseconds))
        assertEquals(1452, m.current)
        assertEquals(0, m.probeInFlightForTest, "the smaller probe in flight is settled")
        assertTrue(m.ptbSuspendedForTest)
        assertTrue(!m.onPtb(1300, t + 1200.milliseconds), "suspended")
        assertEquals(1452, m.current)
        assertTrue(m.onPtb(1300, t + 1200.milliseconds + 600.seconds), "processed again after 600 s")
        assertEquals(1200, m.current)
    }

    @Test fun negative_lossesOfPacketsLargerThanTheSizeInUseAreNoBlackHole() {
        // full-size packets in flight when a PTB dropped the size are lost afterwards: they were sent at the old size and say nothing
        // about the base; no black-hole verdict, no 60 s pause, the probe of the old size still goes
        val m = Pmtud(upperBound = 1452, start = 1452)
        val t = io.kuicksilver.quic.TimeMark(1_000_000_000L)
        assertTrue(m.onPtb(1300, t))
        for (pn in 20L..25L) m.onPacketLost(1452, pn)
        assertTrue(!m.takeBlackHole(t + 10.milliseconds))
        assertTrue(!m.pausedForTest)
        assertEquals(1452, m.nextProbeSize(t + 10.milliseconds))
    }

    @Test fun negative_ptbBelowTheMtuWithZeroLengthIdsIsIgnored() {
        // with a zero-length peer connection ID the quote matches no ID bytes: any short-header-looking datagram passes, so the message
        // rests on the address and port alone (RFC 9000 section 14.2.1: validation includes "when possible, connection IDs"). It may
        // not lower the size in use (nor cap the search, see the next test)
        val (p, c) = pair()
        p.use { _ ->
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            c.remoteCid = io.kuicksilver.quic.wire.ConnectionId.EMPTY // as with a server whose Source Connection ID was empty
            ptb(p, c, 1328, quote = byteArrayOf(0x43, 0x11))
            ptb(p, c, 1328, quote = quoteOf(c, ByteArray(0)))
            assertEquals(0L, p.client.stats.ptbAccepted)
            assertEquals(2L, p.client.stats.ptbIgnored)
            assertEquals(1452, c.stats.pathMtu, "not lowered")
            assertEquals(0, c.path.pmtud!!.confirmingForTest)
        }
    }

    @Test fun negative_ptbAboveTheMtuWithZeroLengthIdsDoesNotCapTheSearch() {
        // zero-length IDs again, a PTB at or above the size in use: on the address and port alone it may not settle the probe in
        // flight nor cap the search (that would hold the size down until the 600 s re-search); ignored and counted
        val (p, c) = pair(linkMtu = 1500, caps = IoCapabilities.Portable)
        p.use { _ ->
            val probe = probeAbove(p, c, 1250)
            c.remoteCid = io.kuicksilver.quic.wire.ConnectionId.EMPTY
            ptb(p, c, 1278, quote = byteArrayOf(0x43, 0x11)) // payload 1250: above the size in use, below the probe
            assertEquals(0L, p.client.stats.ptbAccepted)
            assertEquals(1L, p.client.stats.ptbIgnored)
            assertEquals(probe, c.path.pmtud!!.probeInFlightForTest, "the probe in flight is not settled by it")
        }
    }

    @Test fun negative_aProbeOfAReplacedSearchRaisesNothing() {
        // the search is replaced while a probe is in flight (new capabilities; an IP change does the same through resetForNewIp): the
        // new search did not send that probe, so its acknowledgment, which arrives afterwards, must not raise the new search's size
        val (p, c) = pair(linkMtu = 1500, caps = IoCapabilities.Portable)
        p.use { _ ->
            val probe = probeAbove(p, c, 1200)
            assertEquals(1200, c.stats.pathMtu, "the probe is not acknowledged yet")
            c.setPathCapabilities(PathId.Initial, df)
            p.filterToServer = { _, b -> b.size <= 1200 } // the new search's own probes never arrive: any raise is the old probe's
            val acked = p.runUntil(2.seconds) { c.stats.pathMtu > 1200 }
            assertTrue(!acked, "the old $probe-byte probe raised the new search to ${c.stats.pathMtu}")
            assertEquals(1200, c.path.pmtud!!.current)
        }
    }

    @Test fun negative_losingDfDropsTheMtuTo1200() {
        // RFC 9000 section 14: "UDP datagrams MUST NOT be fragmented at the IP layer". A path at 1452 whose socket no longer sets DF
        // (new capabilities) has no DPLPMTUD and nothing keeps a larger datagram from being fragmented: back to 1200, and nothing
        // larger goes out afterwards
        val (p, c) = pair()
        p.use { _ ->
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            c.setPathCapabilities(PathId.Initial, IoCapabilities.Portable) // no DF
            assertEquals(1200, c.stats.pathMtu)
            assertEquals(null, c.path.pmtud)
            val sizesBefore = p.clientDatagramSizes.size
            transfer(p, c, 100_000)
            assertTrue(p.clientDatagramSizes.drop(sizesBefore).all { it <= 1200 }, "nothing above 1200 without DF")
            assertEquals(null, p.closed(c))
        }
    }

    @Test fun negative_ptbWithEmptyQuoteIgnored() {
        // a message that quotes nothing of ours cannot be checked: ignored
        val (p, c) = pair()
        p.use { _ ->
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            ptb(p, c, 1328, quote = ByteArray(0))
            ptb(p, c, 1328, quote = byteArrayOf(0x43)) // the first byte alone
            assertEquals(0L, p.client.stats.ptbAccepted)
            assertEquals(2L, p.client.stats.ptbIgnored)
            assertEquals(0, c.path.pmtud!!.confirmingForTest)
        }
    }

    @Test fun negative_aProbeSentBeforeThePtbNeitherOverturnsItNorRaisesTheSize() {
        // the search reached 1400 with a 1420 probe in flight; the path shrinks and a genuine PTB (payload 1300) drops the size to
        // 1200. The 1420 probe, sent before the PTB, is acknowledged afterwards, in time or late: it tells about the path before the
        // PTB, so it neither restores the old size nor suspends PTB processing (RFC 8899 section 8 trusts "subsequent probes")
        for (late in listOf(false, true)) {
            val m = Pmtud(upperBound = 1452, start = 1400)
            val t = io.kuicksilver.quic.TimeMark(1_000_000_000L)
            val size = m.nextProbeSize(t)
            assertTrue(size > 1400, "a probe above 1400: $size")
            m.onProbeSent(7, size)
            if (late) m.onProbeDeclaredLost(7, t + 5.milliseconds)
            assertTrue(m.onPtb(1300, t + 10.milliseconds))
            assertEquals(1200, m.current)
            if (late) {
                assertTrue(!m.ackLostProbesIn(7, 7, t + 20.milliseconds), "late=$late: a probe lost before the PTB is no longer matched")
            } else {
                m.onProbeAcked(size, 7, t + 20.milliseconds)
            }
            assertEquals(1200, m.current, "late=$late: not restored")
            assertTrue(!m.ptbSuspendedForTest, "late=$late: not suspended")
            assertEquals(1400, m.nextProbeSize(t + 20.milliseconds), "late=$late: the probe of the old size still decides")
            m.onProbeSent(8, 1400)
            m.onProbeAcked(1400, 8, t + 40.milliseconds)
            assertEquals(1400, m.current, "late=$late: a probe sent after the PTB overturns it")
            assertTrue(m.ptbSuspendedForTest)
        }
    }

    /**
     * Property over random interleavings of forged and genuine PTBs (any size), probes acknowledged when they fit the link of their
     * sending (random MTU, which may shrink mid-way with a genuine PTB) and lost otherwise, acknowledgments late or in time, and timers:
     * ICMP never raises the size above what an acknowledged probe showed, an accepted PTB below the size in use always lands at the
     * base (RFC 8899 section 4.6.2), the timers never stay in the past, after a genuine PTB for a shrunk link no probe sent before it
     * lifts the size above the new link, and once PTBs stop the search reaches the link again.
     */
    @Test fun negative_ptbSequencesKeepTheSearchSafeAndLive() {
        for (seed in 0 until 200) {
            val rnd = kotlin.random.Random(seed)
            var link = 1200 + rnd.nextInt(0, 300)
            val m = Pmtud(upperBound = 1452)
            var now = io.kuicksilver.quic.TimeMark(1_000_000_000L)
            var pn = 0L
            var inFlight: Triple<Long, Int, Int>? = null // packet number, size, link MTU when it was sent
            val lateLost = ArrayList<Triple<Long, Int, Int>>()
            var acked = 1200
            var bound = Int.MAX_VALUE // after a genuine PTB for a shrunk link: the new link

            fun step(ptbs: Boolean) {
                now += rnd.nextInt(10, 700).milliseconds
                val at = "seed $seed link $link"
                if (ptbs && rnd.nextInt(5) == 0) {
                    val before = m.current
                    val dropped = m.onPtb(rnd.nextInt(1100, 1500), now)
                    if (dropped) assertEquals(1200, m.current, "$at: a PTB drop lands at the base")
                    if (!dropped) assertEquals(before, m.current, "$at: no change unless reported")
                }
                inFlight?.let { (n, size, sentLink) ->
                    inFlight = null
                    if (size <= sentLink && rnd.nextInt(10) < 8) {
                        m.onProbeAcked(size, n, now)
                        acked = maxOf(acked, size)
                    } else {
                        m.onProbeDeclaredLost(n, now)
                        if (size <= sentLink) lateLost += Triple(n, size, sentLink) // acknowledged after all, later
                    }
                }
                if (lateLost.isNotEmpty() && rnd.nextInt(4) == 0) {
                    val (n, size, _) = lateLost.removeAt(0)
                    if (m.ackLostProbesIn(n, n, now)) acked = maxOf(acked, size)
                }
                m.onTimeout(now)
                assertTrue(m.timeout() > now, "$at: a timer left in the past")
                val size = m.nextProbeSize(now)
                if (size > 0) {
                    m.onProbeSent(++pn, size)
                    inFlight = Triple(pn, size, link)
                }
                assertTrue(m.current in 1200..acked, "$at: ${m.current} above the largest acknowledged probe $acked")
                assertTrue(m.current <= bound, "$at: ${m.current} above the shrunk link $bound after its PTB")
            }
            repeat(300) { step(ptbs = true) }
            if (rnd.nextBoolean()) {
                // during a later climb a probe the link carries is in flight above the size in use; the link shrinks below the size in
                // use and a genuine PTB reports it: that probe's acknowledgment (sent before the PTB) must not lift the size above the
                // new link
                var guard = 0
                while (inFlight.let { it == null || it.second <= m.current || it.second > link } && guard++ < 10_000) step(ptbs = false)
                if (guard < 10_000 && m.current > 1200) {
                    link = 1200 + rnd.nextInt(0, m.current - 1200)
                    if (m.onPtb(link, now)) bound = link
                }
            }
            // the PTBs stop: within the suspension, the re-search interval and a search, the path is back at the link's size
            repeat(4000) { step(ptbs = false) }
            assertTrue(m.current > minOf(link, 1452) - 20, "seed $seed link $link: the search did not come back: ${m.current}")
        }
    }

    @Test fun ptbDuringABulkTransferDropsToBaseWithoutBlackHolePause() {
        // the link narrows under a bulk transfer and a PTB (payload 1300) arrives: the size drops to 1200 at once, the full-size
        // packets in flight that the link now drops are no black hole (they were sent before the drop), so no pause, and the search
        // climbs back to the link's size
        val (p, c) = pair(clientQuic = noIdle, serverQuic = noIdle)
        p.use { _ ->
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            assertTrue(p.runUntil(10.seconds) { !c.streams.hasStreamData() && c.stats.bytesInFlight == 0L }, "the transfer drained")
            val before = mtuUpdates(p, c)
            val id = c.openStream(true)
            c.writeStream(id, ByteArray(60_000), 0, 60_000, false) // full-size packets in flight
            p.step()
            p.linkMtuToServer = 1320
            p.linkMtuToClient = 1320
            ptb(p, c, 1328)
            assertEquals(1200, c.stats.pathMtu)
            transfer(p, c, 100_000)
            assertEquals(1200, mtuChanges(p, c, before).firstOrNull(), "${mtuChanges(p, c, before)}")
            assertTrue(!c.path.pmtud!!.pausedForTest, "no pause")
            assertTrue(p.runUntil(10.seconds) { c.stats.pathMtu in 1300..1320 }, "the search reached the link: ${mtuChanges(p, c, before)}")
            assertEquals(null, p.closed(c))
        }
    }

    @Test fun negative_ptbFloodIsRateLimited() {
        // 10 000 valid-looking PTB messages in one second: at most 64 are looked at, the rest only counted
        val (p, c) = pair()
        p.use { _ ->
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
        }
    }

    @Test fun negative_ptbForNonActivePathIgnored() {
        // a PTB about a datagram to another address, or one that arrived on another socket, says nothing about the active path
        val (p, c) = pair()
        p.use { _ ->
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            ptb(p, c, 1328, to = InetSocketAddress("10.0.0.99", 443))
            ptb(p, c, 1328, socket = PathId(7))
            assertEquals(0L, p.client.stats.ptbAccepted)
            assertEquals(2L, p.client.stats.ptbIgnored)
            assertEquals(0, c.path.pmtud!!.confirmingForTest)
        }
    }

    @Test fun negative_ptbIgnoredWhenHintsAreOff() {
        val (p, c) = pair(clientQuic = quicConfig { pathMtu { icmpHints = false } })
        p.use { _ ->
            transfer(p, c)
            assertTrue(p.runUntil(20.seconds) { c.stats.pathMtu == 1452 })
            ptb(p, c, 1328)
            assertEquals(0L, p.client.stats.ptbAccepted)
            assertEquals(1L, p.client.stats.ptbIgnored)
        }
    }

    @Test fun emsgsizeOnProbeCountsAsLost() {
        // the kernel refused the probe as larger than the MTU it knows (EMSGSIZE): that size is settled at once, like a probe lost
        // three times, and the next probe is smaller
        val (p, c) = pair(linkMtu = 1350, caps = IoCapabilities.Portable)
        p.use { _ ->
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
        }
    }
}
