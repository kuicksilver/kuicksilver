// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import kotlinx.coroutines.CompletableDeferred

/**
 * The bytes of HEADERS payloads one connection reads ahead of their end, over all its request streams (RFC 9114 section
 * 10.5: "memory commitments ... strictly bounded"). A reader reserves a whole payload's length before it takes any of
 * it from the transport, so a field section that has its reservation never waits for another one's budget, and one
 * without stays in its stream's flow-control window: its bytes are not taken, so they return no credit to the peer. Those
 * bytes still count against the connection's window: when they fill it, a granted section's missing bytes wait for the
 * window, at most until the field-section deadline ends the waiting streams. Reservations are granted in the order they were asked for, so
 * a large section is not overtaken forever by small ones. Confined to the session's dispatcher.
 */
internal class HeaderBudget(
    /** At least the largest single reservation (the HEADERS frame bound), or that one could never be granted. */
    val capacity: Long,
) {
    /** Bytes reserved now (a test hook). */
    var reserved: Long = 0
        private set

    private val waiters = ArrayDeque<Waiter>()

    /** Readers waiting for a reservation (a test hook). */
    val waiting: Int get() = waiters.size

    private class Waiter(
        val bytes: Long,
    ) {
        val granted = CompletableDeferred<Unit>()
    }

    /**
     * Reserves [bytes] (at most [capacity]), waiting in line while the connection holds too much already. A reader that
     * waits also wakes when its stream or its connection ends ([watch]) and leaves the line with that reason.
     */
    suspend fun reserve(
        bytes: Long,
        watch: EndWatch? = null,
    ) {
        require(bytes in 0..capacity) { "reservation of $bytes outside 0..$capacity" }
        if (waiters.isEmpty() && reserved + bytes <= capacity) {
            reserved += bytes
            return
        }
        val w = Waiter(bytes)
        waiters.addLast(w)
        try {
            if (watch == null) w.granted.await() else watch.await(w.granted)
        } catch (e: Throwable) {
            // granted just before the cancellation or the abandonment reached the waiter: the reservation is returned;
            // else the waiter leaves the line, which may let the next one in
            if (!waiters.remove(w)) release(bytes) else grant()
            throw e
        }
    }

    /** Returns [bytes] reserved before. */
    fun release(bytes: Long) {
        reserved -= bytes
        check(reserved >= 0) { "header budget released more than it reserved" }
        grant()
    }

    private fun grant() {
        while (true) {
            val w = waiters.firstOrNull() ?: return
            if (reserved + w.bytes > capacity) return
            waiters.removeFirst()
            reserved += w.bytes
            w.granted.complete(Unit)
        }
    }
}
