// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.util.date.getTimeMillis
import io.kuicksilver.ktor.client.h1.monotonicMillis

/**
 * Elapsed time for an expiry (a DNS TTL, a backoff) that neither a wall clock stepped back nor a device that slept can
 * stretch. Each [Mark] holds a reading of both clocks, and [elapsedMillis] is the larger of the two elapsed times:
 *
 * - the monotonic clock (`System.nanoTime`, `CLOCK_MONOTONIC`, `mach_absolute_time`, `steady_clock`) is not stepped, but
 *   on most platforms it stops while the device sleeps, so alone it would keep an entry past its expiry after a suspend;
 * - the wall clock goes on through sleep, but NTP or a user can step it back, so alone it would keep an entry past its
 *   expiry by the size of the step.
 *
 * The larger of the two expires an entry once either clock has seen its lifetime pass. A clock stepped forward expires
 * entries early, the safe side for a cache. A boot-time clock that counts sleep (Android `elapsedRealtime`, Linux
 * `CLOCK_BOOTTIME`, Apple `mach_continuous_time`) would do alone, but the JVM has no portable one; this pair works the
 * same on every target. What it cannot bound is a wall clock stepped back while the device sleeps: then neither clock
 * sees the time pass.
 */
internal class ExpiryClock(
    private val monotonic: () -> Long = monotonicMillis(),
    private val wall: () -> Long = ::getTimeMillis,
) {
    /** Tests: one clock read as both. */
    constructor(millis: () -> Long) : this(millis, millis)

    /** A point in time, on both clocks. */
    class Mark internal constructor(
        internal val monotonic: Long,
        internal val wall: Long,
    )

    /** Now. */
    fun mark(): Mark = Mark(monotonic(), wall())

    /** Milliseconds since [mark]: the larger of the monotonic and the wall clock's elapsed times. */
    fun elapsedMillis(mark: Mark): Long = maxOf(monotonic() - mark.monotonic, wall() - mark.wall)

    /** The monotonic reading (tests). */
    internal fun monotonicForTest(): Long = monotonic()
}
