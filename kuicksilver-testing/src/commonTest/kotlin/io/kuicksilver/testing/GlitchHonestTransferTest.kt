// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.TlsIdentity
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Glitch protection (docs/guide/quic.md, Glitch protection): an honest transfer over a lossy link spends no glitch tokens on either side. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class GlitchHonestTransferTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        SimScenario.defaultTls =
            { SimScenario.nullTls(TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())) }
    }

    @Test fun honestTransferSpendsNothing() {
        val sim = Simulator(seed = 11, LinkParams(lossRate = 0.05))
        val (c, s) = SimScenario.defaultTls!!.invoke()
        val conn = sim.connect(tlsClient = c, tlsServer = s)
        val r = SimScenario.transfer(sim, 10 shl 20, connection = conn)
        assertTrue(r.finished && r.violations.isEmpty(), "10 MiB with 5% loss: finished=${r.finished} ${r.violations}")

        fun breakdown(c: io.kuicksilver.quic.ConnectionCore) =
            c.glitchByFrameType
                .withIndex()
                .filter {
                    it.value > 0
                }.joinToString { "0x${it.index.toString(16)}=${it.value}" }
        assertEquals(0L, conn.client.stats.glitchTokensSpent, "client spent: ${breakdown(conn.client)}")
        assertEquals(0L, conn.server!!.stats.glitchTokensSpent, "server spent: ${breakdown(conn.server!!)}")
    }
}
