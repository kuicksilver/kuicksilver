// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.ktor.client.h1.H1Pool
import io.kuicksilver.ktor.client.h1.toMillisOrMax
import io.kuicksilver.ktor.client.h3.H3Pool
import kotlinx.coroutines.delay

/** The longest the reaper sleeps: connections the peer closed and entries of ended HTTP/3 connections go within this. */
internal const val REAPER_MAX_SLEEP_MILLIS: Long = 60_000

/** The shortest: a burst of expiries is handled in a few passes, not a busy loop. */
internal const val REAPER_MIN_SLEEP_MILLIS: Long = 10

/**
 * The engine's background reaper: closes idle connections past `idleTimeout` or their lifetime in both pools and drops
 * the bookkeeping of origins without connections; it sleeps until the next expiry, at most `idleTimeout` (a connection
 * that goes idle while it sleeps waits at most twice its timeout) and at most a minute. Runs until cancelled.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal suspend fun reapIdleConnections(
    h1: H1Pool,
    h3: H3Pool,
    config: KuicksilverEngineConfig,
) {
    val idle = config.idleTimeout.toMillisOrMax()
    while (true) {
        val next = listOfNotNull(h1.evictExpired(), h3.evictExpired()).minOrNull() ?: idle
        delay(next.coerceIn(REAPER_MIN_SLEEP_MILLIS, minOf(idle, REAPER_MAX_SLEEP_MILLIS).coerceAtLeast(REAPER_MIN_SLEEP_MILLIS)))
    }
}
