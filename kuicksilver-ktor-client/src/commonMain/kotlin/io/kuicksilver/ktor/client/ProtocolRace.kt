// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.onTimeout
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withContext
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

internal enum class Protocol { H3, H1 }

internal class RaceResult<T>(
    val value: T,
    val winner: Protocol,
    val h3Failure: Throwable?,
)

/**
 * Racing HTTP/3 against HTTP/1.1 connection setup (RFC 8305 section 5, as in Chromium): HTTP/3 starts at once;
 * HTTP/1.1 starts when HTTP/3 fails, or after the head start — [hardDelay] when set, else 1.5 x the host's smoothed RTT,
 * or 250 ms without history, clamped to 100 ms..2 s — and after [MIN_HEAD_START] on a network where QUIC was never seen
 * working (RFC 8305 section 5: "a subsequent connection MUST NOT be started within 10 milliseconds of the previous
 * attempt"; the attempts are not simultaneous either, which the section says they SHOULD NOT be). [hardDelay] must keep
 * the same bounds as `connectionAttemptDelay`: 10 ms..2 s, or [Duration.INFINITE] for HTTP/1.1 only after HTTP/3 failed,
 * on every network (the 10 ms head start of an unconfirmed network does not apply to it).
 * An HTTP/3 setup succeeds when its connection is usable: with 0-RTT that is before the handshake only on a network where
 * QUIC was confirmed (the caller's `h3` decides). The first success wins. A losing h1 setup is cancelled, and one that
 * completed just as h3 won is handed to `onLoser` so the caller can close it (a connection must not be leaked, RFC 8305
 * section 5), also when the caller is cancelled. A losing h3 setup is not cancelled: the race stops waiting for it, but
 * the QUIC connection goes on in the engine's background scope, so later requests to the origin can use it (RFC 7838
 * section 2.4: the client SHOULD use the alternative service as soon as it is available), the deviation from RFC 8305
 * section 5's "SHOULD be canceled" the compliance row documents.
 */
internal class ProtocolRace(
    private val hardDelay: Duration?,
) {
    init {
        require(hardDelay == null || hardDelay.isInfinite() || hardDelay in MIN_HEAD_START..MAX_HEAD_START) {
            "hardDelay must be 10 ms..2 s or Duration.INFINITE (RFC 8305 section 5), was $hardDelay"
        }
    }

    fun headStart(
        srtt: Duration?,
        quicConfirmed: Boolean,
    ): Duration {
        // INFINITE is "HTTP/1.1 only after HTTP/3 failed" on any network: never two attempts at once
        if (hardDelay?.isInfinite() == true) return hardDelay
        if (!quicConfirmed) return MIN_HEAD_START
        return hardDelay ?: (srtt?.times(1.5) ?: 250.milliseconds).coerceIn(100.milliseconds, 2.seconds)
    }

    @Suppress("UNCHECKED_CAST")
    @OptIn(ExperimentalCoroutinesApi::class)
    suspend fun <T> race(
        h3: suspend () -> T,
        h1: suspend () -> T,
        srtt: Duration?,
        quicConfirmed: Boolean,
        onLoser: (T) -> Unit = {},
    ): RaceResult<T> =
        coroutineScope {
            val h3Done = CompletableDeferred<Result<T>>()
            val h1Done = CompletableDeferred<Result<T>>()
            val h3Job =
                launch {
                    h3Done.complete(
                        runCatching { h3() }.also { r ->
                            r.exceptionOrNull()?.let { if (it is CancellationException) throw it }
                        },
                    )
                }
            // head start: HTTP/3 alone, unless it fails first
            val d = headStart(srtt, quicConfirmed)
            val early: Result<T>? =
                if (d.isInfinite()) {
                    h3Done.await()
                } else {
                    select {
                        h3Done.onAwait { it }
                        onTimeout(d) { null }
                    }
                }
            if (early != null && early.isSuccess) return@coroutineScope RaceResult(early.getOrThrow(), Protocol.H3, null)
            val h1Job =
                launch {
                    h1Done.complete(
                        runCatching { h1() }.also { r ->
                            r.exceptionOrNull()?.let { if (it is CancellationException) throw it }
                        },
                    )
                }
            var h1Won = false
            try {
                var h3Result: Result<T>? = early
                var h1Result: Result<T>? = null
                while (true) {
                    if (h3Result?.isSuccess == true) return@coroutineScope RaceResult(h3Result.getOrThrow(), Protocol.H3, null)
                    if (h1Result?.isSuccess == true) {
                        h1Won = true
                        h3Job.cancel()
                        return@coroutineScope RaceResult(h1Result.getOrThrow(), Protocol.H1, h3Result?.exceptionOrNull())
                    }
                    if (h3Result != null && h1Result != null) throw h1Result.exceptionOrNull()!!
                    select<Unit> {
                        if (h3Result == null) h3Done.onAwait { h3Result = it }
                        if (h1Result == null) h1Done.onAwait { h1Result = it }
                    }
                }
                @Suppress("UNREACHABLE_CODE")
                error("unreachable")
            } finally {
                // h3 won, both failed, or the caller was cancelled: an h1 connection that still got made goes to onLoser
                if (!h1Won) {
                    h1Job.cancel()
                    withContext(NonCancellable) { h1Job.join() }
                    if (h1Done.isCompleted) h1Done.getCompleted().getOrNull()?.let(onLoser)
                }
            }
        }
}

/** RFC 8305 section 5: the next connection attempt starts at least 10 ms after the previous one (MUST). */
internal val MIN_HEAD_START = 10.milliseconds

/** RFC 8305 section 5: the connection attempt delay has an upper bound, 2 s recommended (SHOULD). */
private val MAX_HEAD_START = 2.seconds
