// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.tls.TlsRole
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/** Checks after every simulator step: the per-connection resource ceilings (threat-model 3.2), the amplification limit and liveness. */
@OptIn(ExperimentalKuicksilverApi::class)
internal class SimInvariants {
    val violations = ArrayList<String>()
    private var lastProgress: TimeMark? = null
    private var lastProgressValue = -1L

    fun check(
        core: ConnectionCore,
        now: TimeMark,
        progressValue: Long,
        linkAlive: Boolean,
        handshakeDone: Boolean,
    ) {
        if (simForceViolation()) violations += "forced violation (kuicksilver.sim.forceViolation)"
        val s = core.stats
        val who = core.role.name
        if (s.undecryptableBuffered > 32) violations += "$who: ${s.undecryptableBuffered} undecryptable packets buffered"
        if (s.ackRanges > 64) violations += "$who: ${s.ackRanges} ACK ranges"
        if (s.reassemblyRanges > 4096) violations += "$who: ${s.reassemblyRanges} reassembly ranges"
        if (!core.addressValidated &&
            s.pathBytesSent > 3 * s.pathBytesReceived
        ) {
            violations +=
                // RFC 9000 sections 8.1, 9.3.1
                "sent ${s.pathBytesSent} on path ${s.currentPath.value} after receiving ${s.pathBytesReceived} before its validation"
        }
        if (progressValue != lastProgressValue) {
            lastProgressValue = progressValue
            lastProgress = now
        }
        val lp =
            lastProgress ?: run {
                lastProgress = now
                now
            }
        val pto = s.smoothedRtt + maxOf(s.rttVar * 4, 1.milliseconds) + 25.milliseconds
        // liveness: application progress at least every 10 x PTO (scaled by the PTO backoff in force), once the handshake is done
        // floor 10 s: PTO backoff accumulated during a lossy handshake legitimately delays the first application bytes by several seconds
        if (linkAlive && handshakeDone &&
            now - lp > maxOf(pto * 10 * (1 shl minOf(s.ptoCount, 6)), 10_000.milliseconds)
        ) {
            violations +=
                "$who: no progress for ${now - lp} (10 x PTO = ${pto * 10})"
            lastProgress = now
        }
    }
}
