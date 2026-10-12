// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

/**
 * Broken HTTP/3 alternatives, per origin and alternative — never "UDP is blocked" globally (as in Chromium): marked
 * only when HTTP/3 failed while HTTP/1.1 worked, for 5 minutes doubling up to 2 days, all forgotten when the network
 * changes. Also remembers the networks where QUIC was seen working (no HTTP/3 head start elsewhere). Both lists keep at
 * most [AltSvcCache.MAX_ORIGINS] keys, dropping the least recently marked (threat-model 3.18).
 */
internal class BrokenAltSvc(
    private val clock: () -> Long,
) {
    private class Mark(
        val until: Long,
        val level: Int,
    )

    private val marks = LinkedHashMap<String, Mark>()
    private val confirmed = LinkedHashSet<String?>()

    private fun key(
        origin: String,
        alt: String,
    ) = "$origin|$alt"

    fun markBroken(
        origin: String,
        alt: String,
    ) {
        val level = marks[key(origin, alt)]?.let { it.level + 1 } ?: 0
        val duration = (BASE_MILLIS shl minOf(level, 20)).coerceAtMost(MAX_MILLIS)
        marks.remove(key(origin, alt))
        marks[key(origin, alt)] = Mark(clock() + duration, level)
        marks.evictEldest(AltSvcCache.MAX_ORIGINS)
    }

    fun isBroken(
        origin: String,
        alt: String,
    ): Boolean = (marks[key(origin, alt)]?.until ?: return false) > clock()

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
