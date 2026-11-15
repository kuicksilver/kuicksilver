// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.CongestionController
import io.kuicksilver.quic.Cubic
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.fuzz.ConnProgram.DF
import io.kuicksilver.quic.fuzz.ConnProgram.ECN
import io.kuicksilver.quic.fuzz.ConnProgram.E_ECN_PATH
import io.kuicksilver.quic.fuzz.ConnProgram.LIVE
import io.kuicksilver.quic.fuzz.ConnProgram.num
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Negative controls of the connection fuzzer's path and ECN invariants ([ConnectionInvariants], [MtuCheckedCc]): each corrupts
 * one thing a check covers, the way a bug would leave it, in an otherwise clean run, and the check must catch it. Without these a
 * check that silently stopped looking would let the fuzzer pass everything. The engine-side counterparts (a planted bug in
 * DPLPMTUD or ECN validation that the fuzzer must find) were run by hand; see the change that added these.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class ConnectionInvariantControlsTest {
    private fun caught(
        program: ByteArray,
        expected: String,
        tamper: (EndpointNet) -> Unit,
    ) {
        ConnectionFuzz(program, NullCryptoProvider).run() // the same run without the corruption passes
        val e = assertFailsWith<IllegalStateException> { ConnectionFuzz(program, NullCryptoProvider, tamper).run() }
        assertContains(e.message ?: "", expected)
    }

    private val transfer =
        ConnProgram
            .Builder(0)
            .app(0, 0, num(5000), byteArrayOf(1))
            .steps(10)
            .build()

    @Test fun negative_anMtuAboveWhatThePathDeliveredIsCaught() {
        // no DF: nothing above 1200 bytes ever crosses, so a raised MTU is one the network never confirmed
        caught(transfer, "above the largest datagram the network delivered") { net -> net.client.paths.active.mtu = 1400 }
    }

    @Test fun negative_aPathWithoutDplpmtudOnADfSocketIsCaught() {
        caught(
            ConnProgram
                .Builder(DF)
                .app(0, 0, num(5000), byteArrayOf(1))
                .steps(10)
                .build(),
            "runs no DPLPMTUD",
        ) { net ->
            net.client.paths.active.pmtud = null
        }
    }

    @Test fun negative_aPathWithoutEcnOnAMarkingSocketIsCaught() {
        caught(
            ConnProgram
                .Builder(ECN)
                .app(0, 0, num(5000), byteArrayOf(1))
                .steps(10)
                .build(),
            "does not use ECN",
        ) { net ->
            net.client.paths.active.ecn =
                io.kuicksilver.quic.core
                    .EcnValidator()
        }
    }

    @Test fun negative_ecnValidatedOverABleachingPathIsCaught() {
        val bleached =
            ConnProgram
                .Builder(ECN or LIVE)
                .path(0, E_ECN_PATH, byteArrayOf(1))
                .steps(20)
                .app(0, 0, num(3000), byteArrayOf(1))
                .steps(10)
                .build()
        // a validator that took counts that never grew for marked packets as valid
        caught(bleached, "validated ECN though no marked datagram") { net ->
            val p = net.client.paths.active
            if (p.ecn.state !=
                io.kuicksilver.quic.EcnState.Capable
            ) {
                p.ecn.onAck(countsPresent = true, countsValid = true, newlyAckedMarked = 1)
            }
        }
    }

    /** A controller whose window grows with the datagram size: RFC 8899 section 3 forbids it. */
    @Test fun negative_aWindowRaisedByAnMtuUpdateIsCaught() {
        val violations = ArrayList<String>()
        val growing =
            object : CongestionController by Cubic() {
                private var w = 12_000L
                override val cwnd: Long get() = w

                override fun onMtuUpdate(maxDatagramSize: Int) {
                    w = 10L * maxDatagramSize
                }
            }
        val cc = MtuCheckedCc(growing, violations)
        cc.onMtuUpdate(1200)
        assertEquals(emptyList(), violations)
        cc.onMtuUpdate(1452)
        assertContains(violations.single(), "raised the congestion window")
    }
}
