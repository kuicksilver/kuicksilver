// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing

import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/** A run of consecutive datagrams (by index in one direction) that the link drops. */
public class BurstLoss(
    public val startIndex: Int,
    public val length: Int,
)

/** What the link does to ECN code points: passes them, bleaches them to Not-ECT, or marks ECT datagrams CE with a probability. */
public sealed interface EcnMarking {
    public object Pass : EcnMarking

    public object Bleach : EcnMarking

    public class CeRate(
        public val rate: Double,
    ) : EcnMarking
}

/** Impairments of one direction of the simulated link. */
public class LinkParams(
    public val delay: Duration = 10.milliseconds,
    public val jitter: Duration = Duration.ZERO,
    public val bandwidthBitsPerSecond: Long? = null,
    public val lossRate: Double = 0.0,
    /** Indices (per direction, from 0) of datagrams that are always dropped. */
    public val lossMask: Set<Int> = emptySet(),
    public val burstLoss: BurstLoss? = null,
    public val reorderRate: Double = 0.0,
    public val duplicateRate: Double = 0.0,
    public val corruptRate: Double = 0.0,
    /** Datagrams longer than this are dropped silently (an MTU black hole); null — no limit. */
    public val mtu: Int? = null,
    public val ecn: EcnMarking = EcnMarking.Pass,
    /**
     * Bottleneck buffer in bytes when [bandwidthBitsPerSecond] is set: a datagram that finds this many bytes waiting for the
     * link is dropped (tail drop); null — an unbounded buffer.
     */
    public val queueLimitBytes: Long? = null,
) {
    override fun toString(): String =
        "LinkParams(delay=$delay, jitter=$jitter, bw=$bandwidthBitsPerSecond, loss=$lossRate, mask=$lossMask, burst=${burstLoss?.let {
            "${it.startIndex}+${it.length}"
        }}, reorder=$reorderRate, dup=$duplicateRate, corrupt=$corruptRate, mtu=$mtu, ecn=$ecn, queue=$queueLimitBytes)"
}
