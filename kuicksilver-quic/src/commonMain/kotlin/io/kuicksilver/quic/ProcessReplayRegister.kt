// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.quic.endpoint.ZeroRttReplayRegister
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.TimeSource

/**
 * The process's one 0-RTT replay register (ADR-0015), shared by every server endpoint, loop and configuration and kept
 * across endpoint restarts. Its scope is the ticket key: any endpoint of this process that holds a key can decrypt every
 * ticket issued under it (the generated keys are process-wide, `SessionTicketConfig.keys` may repeat across configurations
 * and a rotated key set keeps the previous key), and the register's key, `key_name ‖ iv`, starts with the ticket's key name,
 * so one register per process is exactly one register per ticket key. Its clock is the process's monotonic clock, not a
 * loop's: loops start at different times.
 */
@OptIn(ExperimentalAtomicApi::class)
internal object ProcessReplayRegister {
    private val ref = AtomicReference<ZeroRttReplayRegister?>(null)
    private val origin = TimeSource.Monotonic.markNow()

    /** The register, keyed with [random] of the first endpoint that asks (a CSPRNG in production). */
    fun get(random: Random): ZeroRttReplayRegister {
        ref.load()?.let { return it }
        val made = ZeroRttReplayRegister(random)
        return if (ref.compareAndSet(null, made)) made else ref.load()!!
    }

    /** Monotonic time of the process (not of one loop). */
    fun now(): TimeMark = TimeMark(1_000_000_000L + origin.elapsedNow().inWholeNanoseconds)

    /** The wall clock in milliseconds since the epoch: what OpenSSL's ticket-age check uses. */
    fun wallMillis(): Long = Clock.System.now().toEpochMilliseconds()
}
