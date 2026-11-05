// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

/**
 * Broken HTTP/3 alternatives, per origin and alternative — never "UDP is blocked" globally (as in Chromium): marked
 * only when HTTP/3 failed while HTTP/1.1 worked, for 5 minutes doubling up to 2 days, all forgotten when the network
 * changes. Also remembers the networks where QUIC was seen working (no HTTP/3 head start elsewhere). Both lists keep at
 * most [AltSvcCache.MAX_ORIGINS] keys, dropping the least recently marked (threat-model 3.18). A mark keeps why the
 * alternative broke as a [FallbackReason] (not the failure itself, which would outlive its call), for the diagnostics of
 * the calls it sends to HTTP/1.1.
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
internal class BrokenAltSvc(
    private val clock: () -> Long,
) {
    private class Mark(
        val until: Long,
        val level: Int,
        val reason: FallbackReason,
    )

    private val marks = LinkedHashMap<String, Mark>()
    private val confirmed = LinkedHashSet<String?>()

    /** Broken marks plus networks where QUIC was confirmed (the resource probe). */
    val size: Int get() = marks.size + confirmed.size

    private fun key(
        origin: String,
        alt: String,
    ) = "$origin|$alt"

    fun markBroken(
        origin: String,
        alt: String,
        reason: FallbackReason = FallbackReason.Other,
    ) {
        val level = marks[key(origin, alt)]?.let { it.level + 1 } ?: 0
        val duration = (BASE_MILLIS shl minOf(level, 20)).coerceAtMost(MAX_MILLIS)
        marks.remove(key(origin, alt))
        marks[key(origin, alt)] = Mark(clock() + duration, level, reason)
        marks.evictEldest(AltSvcCache.MAX_ORIGINS)
    }

    fun isBroken(
        origin: String,
        alt: String,
    ): Boolean = (marks[key(origin, alt)]?.until ?: return false) > clock()

    /** Why [alt] of [origin] is broken, or null when it is not (never marked, or the mark expired). */
    fun brokenReason(
        origin: String,
        alt: String,
    ): FallbackReason? = marks[key(origin, alt)]?.takeIf { it.until > clock() }?.reason

    fun markWorking(
        origin: String,
        alt: String,
    ) {
        marks.remove(key(origin, alt))
    }

    fun onNetworkChanged() {
        marks.clear()
        confirmed.clear()
    }

    fun quicConfirmedOn(networkId: String?): Boolean = networkId in confirmed

    fun confirmQuic(networkId: String?) {
        confirmed.remove(networkId)
        confirmed += networkId
        val it = confirmed.iterator()
        while (confirmed.size > AltSvcCache.MAX_ORIGINS && it.hasNext()) {
            it.next()
            it.remove()
        }
    }

    private companion object {
        const val BASE_MILLIS = 5 * 60 * 1000L
        const val MAX_MILLIS = 2 * 86_400 * 1000L
    }
}
