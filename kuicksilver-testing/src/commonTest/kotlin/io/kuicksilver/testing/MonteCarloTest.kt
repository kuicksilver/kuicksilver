// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class MonteCarloTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        SimScenario.defaultTls =
            {
                SimScenario.nullTls(
                    io.kuicksilver.tls.TlsIdentity
                        .fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf()),
                )
            }
    }

    @Test fun randomLinksNeverViolateInvariants() {
        val runs = simRuns(default = 50)
        println("MonteCarlo runs=$runs")
        for (seed in 1L..runs) {
            val r = Random(seed)
            val params =
                LinkParams(
                    delay = (1 + r.nextInt(200)).milliseconds,
                    lossRate = r.nextDouble() * 0.10,
                    reorderRate =
                        r.nextDouble() * 0.10,
                    mtu = 1200 + r.nextInt(301),
                ) // DPLPMTUD searches against a random link MTU
            val df =
                io.kuicksilver.quic.IoCapabilities(
                    ecnSend = false,
                    ecnReceive = false,
                    gsoMaxSegments = 1,
                    gro = false,
                    df = true,
                    batch = 1,
                )
            val res = SimScenario.transfer(Simulator(seed, params, pathCapabilities = df), 128 shl 10)
            if (!res.finished || res.violations.isNotEmpty()) recordFailure("MonteCarloTest", seed, params)
            assertTrue(
                res.finished && res.violations.isEmpty(),
                "seed $seed params $params: finished=${res.finished} violations=${res.violations}",
            )
        }
    }
}
