// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.client

import io.ktor.http.Url
import io.kuicksilver.ktor.client.h1.monotonicMillis
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetch

/** What one WinHTTP PAC call (`WinHttpGetProxyForUrl`) gave, as [runWinPac] tells its outcomes apart. */
internal sealed interface WinPacCall {
    /** The script ran: its answer. */
    class Answer(
        val answer: WinPacAnswer,
    ) : WinPacCall

    /** `ERROR_WINHTTP_AUTODETECTION_FAILED`: automatic detection (DHCP, then DNS) found no script. */
    object NoWpad : WinPacCall

    /** `ERROR_WINHTTP_LOGIN_FAILURE`: the script's server asked for credentials, which were not sent. */
    object LoginFailure : WinPacCall

    /** Any other failure: the script could not be fetched or run. */
    object Failed : WinPacCall
}

/**
 * How long a WPAD detection that found no script is remembered ([WpadFailures]): 5 minutes. Windows has no event this
 * engine follows for a network change, so the detection runs again after this time, also on the same network.
 */
internal const val WPAD_RETRY_MILLIS: Long = 5 * 60_000

/**
 * Remembers for [WPAD_RETRY_MILLIS] that automatic detection (WPAD) found no script, so the lookups in that time (each
 * route the engine's cache does not hold) skip DHCP and DNS detection instead of running it again.
 */
internal class WpadFailures(
    private val clock: () -> Long = monotonicMillis(),
) {
    private val failedAt = AtomicLong(NEVER)

    /** Detection found no script less than [WPAD_RETRY_MILLIS] ago. */
    fun recentlyFailed(): Boolean {
        val t = failedAt.load()
        return t != NEVER && clock() - t < WPAD_RETRY_MILLIS
    }

    fun failed() = failedAt.store(clock())

    fun found() = failedAt.store(NEVER)

    private companion object {
        const val NEVER = Long.MIN_VALUE
    }
}

/**
 * The URI WinHTTP hands the script for [url] ([pacTarget]): a `wss` URL whole only with [fullWebSocketUrl], only for the
 * settings' PAC URL ([configUrl], not automatic detection, [detect]), and only when that URL is `https` or local `file`
 * ([pacUrlIsPrivate]): a script over plain `http`, or one WPAD found, is as open to the local network as WPAD itself.
 */
internal fun winPacTarget(
    url: Url,
    detect: Boolean,
    configUrl: String?,
    fullWebSocketUrl: Boolean,
): String = pacTarget(url, fullWebSocketUrl && !detect && pacUrlIsPrivate(configUrl))

/**
 * Windows' proxy auto-configuration as WinHTTP and Internet Explorer run it: automatic detection (WPAD) first, then the
 * configuration script's URL. [call] is one `WinHttpGetProxyForUrl` call: with automatic detection when `detect`, else
 * with the script at `configUrl`; with `autoLogon`, the user's credentials go to a script server that asks for them.
 * Each call goes first without them and again with them only when the server asked (`ERROR_WINHTTP_LOGIN_FAILURE`), as
 * Microsoft documents for `fAutoLogonIfChallenged`. A detection that found no script is remembered in [wpad]; while it
 * is, detection is skipped. The answer is [WinPacAnswer.NoWpad] when detection found no script and no URL is set,
 * [WinPacAnswer.Failed] when a script could not be fetched or run.
 */
internal fun runWinPac(
    s: IeProxySettings,
    wpad: WpadFailures,
    call: (detect: Boolean, configUrl: String?, autoLogon: Boolean) -> WinPacCall,
): WinPacAnswer {
    fun once(
        detect: Boolean,
        configUrl: String?,
    ): WinPacCall = call(detect, configUrl, false).let { if (it === WinPacCall.LoginFailure) call(detect, configUrl, true) else it }
    var noWpad = false
    if (s.autoDetect) {
        if (wpad.recentlyFailed()) {
            noWpad = true
        } else {
            when (val r = once(true, null)) {
                is WinPacCall.Answer -> {
                    wpad.found()
                    return r.answer
                }

                WinPacCall.NoWpad -> {
                    wpad.failed()
                    noWpad = true
                }

                // a script detection found that failed: the configured URL, if any, is next
                WinPacCall.LoginFailure, WinPacCall.Failed -> {
                    wpad.found()
                }
            }
        }
    }
    val url = s.autoConfigUrl
    if (url != null) return (once(false, url) as? WinPacCall.Answer)?.answer ?: WinPacAnswer.Failed
    return if (noWpad) WinPacAnswer.NoWpad else WinPacAnswer.Failed
}

/**
 * Runs a blocking PAC evaluation within [timeoutMillis]: WinHTTP's `WinHttpGetProxyForUrl` cannot be cancelled, and
 * its own timeouts bound only the script's download, not detection nor the script's run. Each call runs on a thread of
 * [Dispatchers.IO]; when it has not answered in time the lookup gives [WinPacAnswer.Failed] at once, and the call is
 * left to end on its thread with its answer dropped. At most [MAX_IN_FLIGHT] calls run at once, and none starts while
 * a call that overran still runs (those lookups give [WinPacAnswer.Failed] at once): the counts are taken atomically
 * before a call starts, so a script that hangs holds at most [MAX_IN_FLIGHT] threads, however many lookups race.
 */
internal class BoundedPac(
    private val timeoutMillis: Long,
) {
    /** Calls started and not ended, and of those the ones that overran their bound. */
    private val inFlight = MutableStateFlow(0)
    private val overran = AtomicInt(0)

    /** Calls that have not ended yet (tests). */
    internal val unfinished: StateFlow<Int> get() = inFlight

    @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
    suspend fun run(block: () -> WinPacAnswer): WinPacAnswer {
        while (true) {
            if (overran.load() > 0) return WinPacAnswer.Failed
            val n = inFlight.value
            if (n >= MAX_IN_FLIGHT) return WinPacAnswer.Failed
            if (inFlight.compareAndSet(n, n + 1)) break
        }
        // a call that overran may have been counted between the check and the increment: check again, now counted
        if (overran.load() > 0) {
            inFlight.update { it - 1 }
            return WinPacAnswer.Failed
        }
        val call = GlobalScope.async(Dispatchers.IO) { block() }
        call.invokeOnCompletion { inFlight.update { it - 1 } }
        var answered = false
        try {
            val answer = withTimeoutOrNull(timeoutMillis) { call.await() }
            answered = answer != null
            return answer ?: WinPacAnswer.Failed
        } finally {
            if (!answered && !call.isCompleted) {
                overran.incrementAndFetch()
                call.invokeOnCompletion { overran.decrementAndFetch() }
            }
        }
    }

    internal companion object {
        const val MAX_IN_FLIGHT: Int = 4
    }
}
