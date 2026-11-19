// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.TimeMark
import kotlin.time.Duration.Companion.milliseconds

/**
 * Closes this core and runs its timers, under a virtual clock from [now], until it is closed: its TLS session and keys are
 * native memory freed only then. What it sends is dropped. Nothing when it is closed already.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal fun ConnectionCore.closeToTheEnd(now: TimeMark) {
    if (state == ConnectionState.Closed) return
    var t = now
    close(0, "", t)
    PacketBatch(16).use { out ->
        val deadline = t + 60_000.milliseconds
        while (state != ConnectionState.Closed && t < deadline) {
            out.clear()
            poll(out, t)
            while (nextEvent() != null) Unit
            t = maxOf(t + 1.milliseconds, nextTimeoutOrNever())
            if (nextTimeoutOrNever() <= t) onTimeout(t)
        }
    }
    check(state == ConnectionState.Closed) { "the connection did not close" }
}
