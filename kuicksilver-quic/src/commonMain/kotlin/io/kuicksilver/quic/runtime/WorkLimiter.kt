// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.kuicksilver.quic.TimeMark
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/**
 * Bounds how long a receiver runs without giving the loop's dispatcher back: after [maxRounds] receive rounds or [budget] of
 * wall time since [start], [shouldYield] answers true and the receiver yields, so the timer coroutine and queued application
 * commands run even when the socket never runs dry (a flood, a busy peer). The count bound follows quic-go
 * (`connection.go`, `maxPacketsToProcess`) and msquic (`QUIC_MAX_RECEIVE_BATCH_COUNT`); the time bound covers slow rounds.
 */
internal class WorkLimiter(
    private val maxRounds: Int = 16,
    private val budget: Duration = 2.milliseconds,
) {
    private var rounds = 0
    private var since = TimeMark(0)

    /** Opens a new run of rounds at [now]. */
    fun start(now: TimeMark) {
        rounds = 0
        since = now
    }

    /** Counts one round; true once the run has used its rounds or its time. */
    fun shouldYield(now: TimeMark): Boolean = ++rounds >= maxRounds || now - since >= budget
}
