// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
internal object SimFixtures {
    val testCa = Certificate(TestCerts.testCa)

    fun client(): TlsConfig =
        tlsConfig(TlsRole.Client) {
            alpn = listOf("hq-interop")
            serverName = "server.test"
            trust =
                TrustConfig.AnchoredCa(listOf(testCa))
        }

    fun server(
        chain: List<ByteArray> = listOf(TestCerts.server),
        key: ByteArray = TestCerts.serverKey,
    ): TlsConfig =
        tlsConfig(TlsRole.Server) {
            alpn =
                listOf("hq-interop")
            ; identity = TlsIdentity.fromDer(chain, key.copyOf())
        }
}

@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class SimulatorTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        SimScenario.defaultTls =
            { SimScenario.nullTls(TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())) }
    }

    private fun ok(
        r: SimResult,
        what: String,
    ) {
        assertTrue(r.finished, "$what: not finished after ${r.elapsed}: ${r.violations}")
        assertTrue(r.violations.isEmpty(), "$what: ${r.violations}")
    }

    /** The keys stand for the native ones a real provider makes: the simulator's close must free all of them. */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    private class CountingCrypto : io.kuicksilver.tls.QuicCrypto by io.kuicksilver.quic.NullCryptoProvider {
        var live = 0

        override fun newResetKey(): io.kuicksilver.tls.ResetKey {
            val k =
                io.kuicksilver.quic.NullCryptoProvider
                    .newResetKey()
            live++
            return object : io.kuicksilver.tls.ResetKey by k {
                override fun close() {
                    live--
                    k.close()
                }
            }
        }

        override fun newTokenKey(): io.kuicksilver.tls.TokenKey {
            val k =
                io.kuicksilver.quic.NullCryptoProvider
                    .newTokenKey()
            live++
            return object : io.kuicksilver.tls.TokenKey by k {
                override fun close() {
                    live--
                    k.close()
                }
            }
        }
    }

    @Test fun closeFreesBothEndpoints() {
        val crypto = CountingCrypto()
        Simulator(seed = 5, LinkParams(), crypto = crypto).use { sim ->
            val (ct, st) = SimScenario.defaultTls!!()
            val conn = sim.connect(tlsClient = ct, tlsServer = st)
            assertTrue(sim.runUntil(5.seconds) { conn.handshakeDone }.finished)
            assertTrue(crypto.live > 0)
            sim.close()
            assertEquals(0, crypto.live, "the reset and address-token keys of both endpoint cores")
        } // use's close is the second one: it does nothing
        assertEquals(0, crypto.live)
    }

    @Test fun aSecondConnectIsRefused() {
        Simulator(seed = 6, LinkParams()).use { sim ->
            val (ct, st) = SimScenario.defaultTls!!()
            sim.connect(tlsClient = ct, tlsServer = st)
            val (ct2, st2) = SimScenario.defaultTls!!()
            assertFailsWith<IllegalStateException> { sim.connect(tlsClient = ct2, tlsServer = st2) }
        }
    }

    @Test fun transfer10MiBNoLoss() {
        Simulator(seed = 1, LinkParams()).use { sim -> ok(SimScenario.transfer(sim, 10 shl 20), "10 MiB") }
    }

    @Test fun transferWithFivePercentLoss() {
        for (seed in 1L..20L) {
            Simulator(seed, LinkParams(lossRate = 0.05)).use { sim -> ok(SimScenario.transfer(sim, 1 shl 20), "seed $seed") }
        }
    }

    @Test fun natRebindMidTransferKeepsCwnd() {
        // a NAT rebind (same IP, new port) at 3 MiB of 10 keeps the server's congestion state and costs no stall against the same
        // transfer without it (10 MiB rather than 50: two 50 MiB transfers took about 11 minutes on Kotlin/Native); the plain run is
        // window-limited, so the comparison is tight (uploadIsWindowLimitedNotQuantumLimited)
        val plain = Simulator(seed = 21, LinkParams(delay = 20.milliseconds)).use { SimScenario.transfer(it, 10 shl 20) }
        ok(plain, "no rebind")
        Simulator(seed = 21, LinkParams(delay = 20.milliseconds)).use { sim ->
            val (ct, st) = SimScenario.defaultTls!!()
            val conn = sim.connect(tlsClient = ct, tlsServer = st)
            var rttBefore = Duration.ZERO
            var cwndBefore = 0L
            val r =
                SimScenario.transfer(sim, 10 shl 20, connection = conn, atBytes = 3L shl 20, midway = {
                    rttBefore =
                        conn.server!!.stats.smoothedRtt
                    ; cwndBefore = conn.server!!.stats.cwnd
                    sim.rebindClient(port = 40001)
                })
            ok(r, "rebind")
            val changes = conn.serverEvents.filterIsInstance<io.kuicksilver.quic.ConnectionEvent.PathChanged>()
            assertEquals(1, changes.size)
            assertEquals(io.kuicksilver.quic.PathChangeReason.NatRebinding, changes[0].reason)
            val s = conn.server!!.stats
            assertTrue(
                s.smoothedRtt <= rttBefore * 2 && s.smoothedRtt != 333.milliseconds,
                "RTT kept: before $rttBefore after ${s.smoothedRtt}",
            )
            assertTrue(
                s.cwnd >= 2400 && cwndBefore > 0,
                "the receiver's window survives (the datagrams in flight to the old port are lost, a real congestion signal): before $cwndBefore after ${s.cwnd}",
            )
            assertTrue(r.elapsed <= plain.elapsed * 1.25, "no stall: ${r.elapsed} vs ${plain.elapsed} without the rebind")
            assertEquals(40001, sim.lastClientSourceSeenByServer!!.port)
        }
    }

    @Test fun preferredAddressMidTransferKeepsTransfer() {
        // the server offers a preferred address: the client validates it after confirmation and moves while 10 MiB flow, with no
        // loss of data and no stall against the same transfer without the offer (RFC 9000 section 9.6)
        val plain = Simulator(seed = 23, LinkParams(delay = 20.milliseconds)).use { SimScenario.transfer(it, 10 shl 20) }
        ok(plain, "no preferred address")
        Simulator(seed = 23, LinkParams(delay = 20.milliseconds)).use { sim ->
            val (ct, st) = SimScenario.defaultTls!!()
            val conn =
                sim.connect(
                    tlsClient = ct,
                    tlsServer = st,
                    preferredAddress =
                        io.kuicksilver.quic.PreferredAddress(
                            io.ktor.network.sockets
                                .InetSocketAddress("10.0.0.3", 4433),
                            null,
                        ),
                )
            val r = SimScenario.transfer(sim, 10 shl 20, connection = conn)
            ok(r, "preferred address")
            val moves = conn.clientEvents.filterIsInstance<io.kuicksilver.quic.ConnectionEvent.PathChanged>()
            assertEquals(listOf(io.kuicksilver.quic.PathChangeReason.PreferredAddress), moves.map { it.reason }, "the client moved once")
            assertEquals(
                io.kuicksilver.quic.PathChangeReason.PreferredAddress,
                conn.serverEvents
                    .filterIsInstance<io.kuicksilver.quic.ConnectionEvent.PathChanged>()
                    .singleOrNull()
                    ?.reason,
                "and so did the server",
            )
            assertTrue(sim.preferredDelivered > 1000, "the transfer went through the preferred address: ${sim.preferredDelivered}")
            assertTrue(r.elapsed <= plain.elapsed * 1.25, "no stall: ${r.elapsed} vs ${plain.elapsed} without the move")
        }
    }

    @Test fun periodicAddressRebindDownloadKeepsThroughput() {
        // the interop runner's rebind-addr case: a 10 MiB download while the client's IP changes every 5 s; each change is a peer migration with a fresh congestion state
        val link = LinkParams(delay = 15.milliseconds, bandwidthBitsPerSecond = 10_000_000)
        val plain = Simulator(seed = 31, link).use { SimScenario.transfer(it, 10 shl 20, fromServer = true) }
        ok(plain, "no rebind")
        Simulator(seed = 31, link).use { sim ->
            val (ct, st) = SimScenario.defaultTls!!()
            val conn = sim.connect(tlsClient = ct, tlsServer = st)
            var rebinds = 0
            var nextRebind = sim.now + 500.milliseconds // the runner rebinds first during slow start
            val r =
                SimScenario.transfer(sim, 10 shl 20, connection = conn, fromServer = true, onStep = {
                    if (sim.now >=
                        nextRebind
                    ) {
                        rebinds++
                        nextRebind = sim.now + 5.seconds
                        sim.rebindClient(
                            host = "10.0.0.${10 + rebinds}",
                            port =
                                40000 + rebinds,
                        )
                    }
                })
            ok(r, "rebind run")
            val changes = conn.serverEvents.filterIsInstance<io.kuicksilver.quic.ConnectionEvent.PathChanged>()
            assertTrue(
                rebinds >= 1 && changes.size >= rebinds,
                "every rebind became a migration: rebinds $rebinds changes ${changes.map { it.reason }}",
            )
            val pathLog =
                conn.serverEvents.mapNotNull { e ->
                    when (e) {
                        is io.kuicksilver.quic.ConnectionEvent.PathChanged -> "changed ${e.old.value}->${e.new.value} ${e.reason}"
                        is io.kuicksilver.quic.ConnectionEvent.PathValidated -> "validated ${e.path.value}"
                        is io.kuicksilver.quic.ConnectionEvent.PathFailed -> "failed ${e.path.value}"
                        else -> null
                    }
                }
            assertTrue(
                r.elapsed <= plain.elapsed * 2,
                "download with address changes every 5 s: ${r.elapsed} vs ${plain.elapsed} without (misrouted ${sim.misrouted}); " +
                    "path log: $pathLog; server stats ${conn.server!!.stats.let {
                        "cwnd=${it.cwnd} srtt=${it.smoothedRtt} lost=${it.lostPackets} pto=${it.ptoCount}"
                    }}",
            )
        }
    }

    @Test fun realtimeScenarioStreamsAndDatagrams() {
        // the real-time shape of samples/realtime-telemetry: a control stream, latest-wins sensor datagrams and a media stream over a 5% lossy link — the streams arrive whole, each sensor key ends with its final value
        Simulator(seed = 17, LinkParams(delay = 20.milliseconds, lossRate = 0.05)).use { sim ->
            val (ct, st) = SimScenario.defaultTls!!()
            val conn = sim.connect(tlsClient = ct, tlsServer = st)
            val latest = HashMap<Int, Int>()
            val dirty = HashSet<Int>()
            val received = HashMap<Int, Int>()
            var tick = 0
            var sent = 0
            val sender =
                // the API's LatestWins policy at the core level: one slot per key, always the newest value
                object : io.kuicksilver.quic.DatagramSender {
                    override fun onTransmit(packet: io.kuicksilver.quic.DatagramPacketWriter) {
                        val it = dirty.iterator()
                        while (it.hasNext()) {
                            val k = it.next()
                            val v = latest[k]!!
                            val d =
                                byteArrayOf(
                                    k.toByte(),
                                    (
                                        v shr
                                            8
                                    ).toByte(),
                                    v.toByte(),
                                )
                            ; if (packet.remaining <
                                d.size
                            ) {
                                return
                            }
                            if (!packet.write(d, 0, d.size)) return
                            it.remove()
                            sent++
                        }
                    }
                }
            val buf = ByteArray(16)

            fun pump() {
                conn.server?.let { s ->
                    while (true) {
                        val n = s.readDatagram(buf, 0)
                        if (n <
                            0
                        ) {
                            break
                        }
                        received[buf[0].toInt()] = ((buf[1].toInt() and 0xff) shl 8) or (buf[2].toInt() and 0xff)
                    }
                }
            }
            val r =
                SimScenario.transfer(sim, 2 shl 20, streams = 2, connection = conn, onStep = {
                    if (conn.handshakeDone && conn.client.datagramSender == null) conn.client.datagramSender = sender
                    if (++tick % 3 == 0) {
                        for (k in 0 until 4) {
                            latest[k] = tick * 7 + k
                            dirty += k
                        } // sensors update faster than the link can carry them
                    }
                    pump()
                })
            ok(r, "media and control streams")
            assertTrue(sent > 100, "datagrams flowed: $sent")
            for (k in 0 until 4) dirty += k // the final readings keep being offered until acknowledged by arrival (a real sensor repeats)
            assertTrue(
                sim
                    .runUntil(10.seconds) {
                        pump()
                        (0 until 4).all { received[it] == latest[it] }
                    }.finished,
                "every key ends with its final value: got $received want $latest",
            )
            assertTrue(conn.client.stats.datagramsDropped == 0L && conn.server!!.stats.datagramsDropped >= 0L)
        }
    }

    @Test fun cubicTransferWithLossFinishes() {
        for (seed in 1L..5L) {
            Simulator(seed, LinkParams(delay = 20.milliseconds, lossRate = 0.05)).use { sim ->
                val (ct, st) = SimScenario.defaultTls!!()
                val conn = sim.connect(tlsClient = ct, tlsServer = st)
                ok(SimScenario.transfer(sim, 10 shl 20, connection = conn), "CUBIC seed $seed")
            }
        }
    }

    // the burst hits the data direction only: an index-based burst on the ACK direction too would swallow the next 20 ACKs however slowly PTO probes draw them
    @Test fun burstLossRecovers() {
        Simulator(7, LinkParams(burstLoss = BurstLoss(startIndex = 30, length = 20)), LinkParams()).use { sim ->
            ok(SimScenario.transfer(sim, 1 shl 20), "burst")
        }
    }

    @Test fun reorderAndDuplicate() {
        Simulator(3, LinkParams(reorderRate = 0.10, duplicateRate = 0.05)).use { sim ->
            ok(SimScenario.transfer(sim, 1 shl 20), "reorder")
        }
    }

    // real AEAD: the null provider cannot detect a flipped byte, so this scenario runs over ksl
    @Test fun corruptionDropsPacketsNotConnection() {
        Simulator(5, LinkParams(corruptRate = 0.01), crypto = KslQuicCrypto).use { sim ->
            val conn = sim.connect(tlsClient = SimFixtures.client(), tlsServer = SimFixtures.server())
            ok(SimScenario.transfer(sim, 1 shl 20, connection = conn), "corrupt")
        }
    }

    // two losses per direction: with the 333 ms initial RTT the PTO backoff (1 s, 2 s) keeps the handshake under the 10 s timeout; three would not (RFC 9002 section 6.2)
    @Test fun handshakeLossBothDirections() {
        Simulator(2, LinkParams(lossMask = setOf(0, 1))).use { sim ->
            ok(SimScenario.transfer(sim, 64 shl 10), "handshake loss")
        }
    }

    @Test fun tailLossRecoveredByPto() {
        Simulator(4, LinkParams()).use { sim ->
            val (ct, st) = SimScenario.defaultTls!!()
            val conn = sim.connect(tlsClient = ct, tlsServer = st)
            val r = SimScenario.transfer(sim, 200_000, connection = conn, dropLastClientDatagram = true)
            ok(r, "tail loss")
            assertTrue(conn.maxPtoCount >= 1, "PTO fired: ${conn.maxPtoCount}")
        }
    }

    @Test fun handshakeWithLargeChainUnderAmplificationLimit() {
        Simulator(9, LinkParams(lossMask = setOf(1)), crypto = KslQuicCrypto).use { sim ->
            // the client's second flight is lost
            val conn =
                sim.connect(
                    tlsClient = SimFixtures.client(),
                    tlsServer = SimFixtures.server(listOf(TestCerts.serverBigChain, TestCerts.intermediate), TestCerts.serverBigChainKey),
                )
            val r = sim.runUntil(10.seconds) { conn.handshakeDone }
            ok(r, "big chain")
            assertTrue(r.elapsed < 10.seconds)
        }
    }

    @Test fun seedReproducesRun() {
        val a = Simulator(42, LinkParams(lossRate = 0.03, reorderRate = 0.02)).use { SimScenario.transfer(it, 256 shl 10) }
        val b = Simulator(42, LinkParams(lossRate = 0.03, reorderRate = 0.02)).use { SimScenario.transfer(it, 256 shl 10) }
        ok(a, "a")
        assertEquals(a.traceHash, b.traceHash)
    }

    @Test fun bandwidthLimitRespected() {
        val r = Simulator(1, LinkParams(bandwidthBitsPerSecond = 1_000_000)).use { SimScenario.transfer(it, 1 shl 20) }
        ok(r, "1 Mbit/s")
        assertTrue(r.elapsed >= 8.seconds, "${r.elapsed}")
    }

    /**
     * An upload is window-limited, not limited to one send quantum per batch of ACKs. A poll ends after one quantum (ten datagrams,
     * RFC 9002 section 7.7) and the connection used to wait for the peer's next packet to send the rest. Where a flight's ACKs
     * arrive together (here a link without a rate limit, on a real host a receive batch processed in one flush) that meant one
     * quantum per round of ACKs: about 20 datagrams in flight whatever the window, 10 MiB over a 20 ms link in 18.2 s, and
     * CUBIC, seeing an application-limited sender, never grew. Now the window fills: 0.53 s.
     */
    @Test fun uploadIsWindowLimitedNotQuantumLimited() {
        val r = Simulator(seed = 21, LinkParams(delay = 20.milliseconds)).use { SimScenario.transfer(it, 10 shl 20) }
        ok(r, "10 MiB over 20 ms")
        assertTrue(r.elapsed <= 2.seconds, "10 MiB took ${r.elapsed}")
    }
}
