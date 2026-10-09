// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.tls.TlsIdentity
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** MTU black holes, NAT rebind, ECN marking and a second client path in the simulator. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class SimLinkTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        SimScenario.defaultTls =
            { SimScenario.nullTls(TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())) }
    }

    private val t0 = TimeMark(1_000_000_000L)

    private fun link(params: LinkParams) = SimLink(params, Random(1), "test")

    private fun deliveredSizes(
        l: SimLink,
        at: TimeMark,
    ) = l.due(at).map { it.bytes.size }

    @Test fun mtuDropsLargerDatagrams() {
        val l = link(LinkParams(mtu = 1300))
        l.send(ByteArray(1300), Ecn.NotEct, t0)
        l.send(ByteArray(1301), Ecn.NotEct, t0)
        assertEquals(listOf(1300), deliveredSizes(l, t0 + 1.seconds))
        assertEquals(1L, l.dropped)
    }

    @Test fun setMtuMidRunAffectsOnlyLaterDatagrams() {
        val l = link(LinkParams())
        l.send(ByteArray(1400), Ecn.NotEct, t0)
        l.mtu = 1300
        l.send(ByteArray(1400), Ecn.NotEct, t0 + 1.milliseconds)
        assertEquals(
            listOf(1400),
            deliveredSizes(l, t0 + 1.seconds),
            "the datagram already on the wire still arrives; the later one hits the black hole",
        )
    }

    @Test fun bleachClearsEcn() {
        val l = link(LinkParams(ecn = EcnMarking.Bleach))
        l.send(ByteArray(100), Ecn.Ect0, t0)
        l.send(ByteArray(100), Ecn.Ce, t0)
        assertEquals(listOf(Ecn.NotEct, Ecn.NotEct), l.due(t0 + 1.seconds).map { it.ecn })
    }

    @Test fun ceRateMarksEctOnly() {
        val l = link(LinkParams(ecn = EcnMarking.CeRate(1.0)))
        l.send(ByteArray(100), Ecn.Ect0, t0)
        l.send(ByteArray(100), Ecn.NotEct, t0)
        l.send(ByteArray(100), Ecn.Ect1, t0)
        assertEquals(listOf(Ecn.Ce, Ecn.NotEct, Ecn.Ce), l.due(t0 + 1.seconds).map { it.ecn })
        val pass = link(LinkParams())
        pass.send(ByteArray(100), Ecn.Ect0, t0)
        assertEquals(listOf(Ecn.Ect0), pass.due(t0 + 1.seconds).map { it.ecn })
    }

    @Test fun rebindChangesSourceAddressSeenByServer() {
        val sim = Simulator(seed = 11, LinkParams())
        val (ct, st) = SimScenario.defaultTls!!()
        val conn = sim.connect(tlsClient = ct, tlsServer = st)
        assertTrue(sim.runUntil(5.seconds) { conn.handshakeDone }.finished)
        assertEquals(40000, sim.lastClientSourceSeenByServer!!.port)
        sim.rebindClient(port = 40001)
        assertEquals(40001, sim.clientAddress.port)
        val r = SimScenario.transfer(sim, 64 shl 10, connection = conn) // traffic after the rebind
        assertTrue(r.finished, "${r.violations}")
        assertEquals(40001, sim.lastClientSourceSeenByServer!!.port, "the server now sees the new source port")
    }

    @Test fun secondPathIndependentLoss() {
        val sim = Simulator(seed = 12, LinkParams())
        val idx = sim.addClientPath(InetSocketAddress("10.0.1.1", 41000), LinkParams(lossRate = 1.0))
        assertEquals(1, idx)
        val r = SimScenario.transfer(sim, 256 shl 10)
        assertTrue(r.finished && r.violations.isEmpty(), "a dead second path does not touch the first: ${r.violations}")
        assertEquals(0L, sim.pathDelivered(idx), "nothing travels on the unused path yet")
    }

    @Test fun seedStillReproducesRun() {
        fun run() =
            SimScenario.transfer(
                Simulator(42, LinkParams(lossRate = 0.03, reorderRate = 0.02, ecn = EcnMarking.CeRate(0.1))),
                256 shl 10,
            )
        val a = run()
        val b = run()
        assertTrue(a.finished && b.finished)
        assertEquals(a.traceHash, b.traceHash)
    }
}
