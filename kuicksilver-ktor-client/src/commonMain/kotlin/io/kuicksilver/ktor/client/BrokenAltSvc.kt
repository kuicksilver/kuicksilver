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
 *
 * A mark ends on whichever of two clocks gets there first: the monotonic [clock] (`monotonicMillis()`; the marks live in
 * memory only), so a backward step of the wall clock cannot extend a backoff, and the [wallClock], which goes on while a
 * device sleeps: on Android and iOS the monotonic clock stops in deep sleep, and a backoff must not stretch over hours of
 * it. A forward step of the wall clock ends marks early, the safe side. (A sleep-aware clock helper is being added on
 * another branch for the HTTPS record cache; the two are to be unified.)
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
internal class BrokenAltSvc(
    internal val clock: () -> Long,
    private val wallClock: () -> Long = clock,
) {
    private class Mark(
        val until: Long,
        val untilWall: Long,
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
        marks[key(origin, alt)] = Mark(clock() + duration, wallClock() + duration, level, reason)
        marks.evictEldest(AltSvcCache.MAX_ORIGINS)
    }

    fun isBroken(
        origin: String,
        alt: String,
    ): Boolean = marks[key(origin, alt)]?.let(::live) ?: false

    /** Neither clock has passed the mark's end. */
    private fun live(m: Mark): Boolean = m.until > clock() && m.untilWall > wallClock()

    /** Why [alt] of [origin] is broken, or null when it is not (never marked, or the mark expired). */
    fun brokenReason(
        origin: String,
        alt: String,
    ): FallbackReason? = marks[key(origin, alt)]?.takeIf(::live)?.reason

    /**
     * A completed handshake through [alt]: its mark goes, except one for a stall ([FallbackReason.QuicStalled]), which
     * stays (expired, it no longer applies) so that its backoff level carries over: a network that cuts UDP flows lets
     * handshakes through and stalls the requests after them, and each such stall must double the backoff (5 minutes, then
     * 10, ...) instead of starting again at 5. A network change forgets it with the rest.
     */
    fun markWorking(
        origin: String,
        alt: String,
    ) {
        if (marks[key(origin, alt)]?.reason == FallbackReason.QuicStalled) return
        marks.remove(key(origin, alt))
    }

    /**
     * A connection through [alt] carried a whole exchange and ended without ever stalling: an expired stall mark ([markWorking] keeps
     * them) goes one backoff level down, and the mark at level 0 goes, so a network that stopped cutting UDP flows walks
     * back to the 5-minute backoff and then to none. A live mark is left alone (nothing goes there while it lives).
     */
    fun decayStall(
        origin: String,
        alt: String,
    ) {
        val k = key(origin, alt)
        val m = marks[k] ?: return
        if (m.reason != FallbackReason.QuicStalled || live(m)) return
        if (m.level == 0) marks.remove(k) else marks[k] = Mark(m.until, m.untilWall, m.level - 1, m.reason)
    }

    /** The backoff level of [alt]'s mark, live or expired, or -1 without one (tests). */
    internal fun levelForTest(
        origin: String,
        alt: String,
    ): Int = marks[key(origin, alt)]?.level ?: -1

    /** Ends [alt]'s mark now and keeps its level, as the passing of its backoff would (tests). */
    internal fun expireForTest(
        origin: String,
        alt: String,
    ) {
        val k = key(origin, alt)
        val m = marks[k] ?: return
        marks[k] = Mark(clock() - 1, wallClock() - 1, m.level, m.reason)
    }

    fun onNetworkChanged() {
        marks.clear()
        confirmed.clear()
    }

    /** Forgets the marks of [origin]'s alternatives, or every mark and confirmed network when null (RFC 7838 section 9.4). */
    fun clear(origin: String?) {
        if (origin == null) {
            marks.clear()
            confirmed.clear()
        } else {
            marks.keys.removeAll { it.startsWith("$origin|") }
        }
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
