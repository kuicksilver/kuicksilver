// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.time.Duration

/**
 * Takes every HTTP/3 connection of this client out of use (docs/guide/ktor.md, "Turning HTTP/3 off remotely"): each
 * established pooled connection gets a GOAWAY and no further request; the next request opens a new connection (when
 * HTTP/3 is allowed, see `Http3ClientConfig.http3Allowed`) or goes over HTTP/1.1. Calls already running on them finish, and
 * each closes with H3_NO_ERROR once its last call is done (an idle one at once). A connection still being set up serves the
 * requests already waiting for it, then closes. Every open WebTransport session gets WT_DRAIN_SESSION and its connection a
 * GOAWAY: the server is asked to wind the session down; the session itself stays open until either side closes it.
 * Returns once the GOAWAYs are written (each waits at most 5 seconds). Does nothing when the client's engine is not
 * Kuicksilver.
 */
@ExperimentalKuicksilverApi
public suspend fun HttpClient.closeHttp3Connections() {
    (engine as? KuicksilverEngine)?.closeHttp3Connections()
}

/** At most one `true` from [tryAcquire] per [interval] of [clock] (milliseconds): a warning that must not flood the log. */
@OptIn(ExperimentalAtomicApi::class)
internal class RateLimitedWarning(
    interval: Duration,
    @kotlin.concurrent.Volatile var clock: () -> Long, // a var for tests
) {
    private val intervalMillis = interval.inWholeMilliseconds
    private val last = AtomicLong(NEVER)

    /** Whether to warn now; true at most once per interval, also under concurrent callers. */
    fun tryAcquire(): Boolean {
        val now = clock()
        while (true) {
            val prev = last.load()
            if (prev != NEVER && now - prev < intervalMillis) return false
            if (last.compareAndSet(prev, now)) return true
        }
    }

    private companion object {
        const val NEVER = Long.MIN_VALUE
    }
}
