// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h2

import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.time.TimeSource

/**
 * The engine's `Alt-Svc` on one HTTP/2 connection (RFC 7838). Section 3: "When using HTTP/2 ([RFC7540]), servers SHOULD
 * instead send an ALTSVC frame (Section 4). A single ALTSVC frame can be sent for a connection; a new frame is not needed for
 * every request. Note that, despite this recommendation, Alt-Svc header fields remain valid in responses delivered over
 * HTTP/2." So both go out: the ALTSVC frame for the clients that read it, the field for those that read only the header
 * (curl, clients of other stacks, Kuicksilver clients before 0.3.0), each response taking one reading of the value for both.
 *
 * The frame goes on a request stream (an empty Origin: it applies to that stream's origin, section 4) once per origin of
 * the connection and value, again when the value changed (`http3Advertising` turned it into `clear`, or back), and again
 * [refreshMillis] after the last one, so a client on a long-lived connection whose entry expired (`ma=86400`) or was
 * cleared learns it again. At most [MAX_ORIGINS] origins are remembered; past them, the memory starts over.
 */
@OptIn(ExperimentalAtomicApi::class)
internal class H2AltSvc(
    private val value: () -> String?,
    private val refreshMillis: Long = REFRESH_MILLIS,
    private val nowMillis: () -> Long = MONOTONIC,
) {
    private class Sent(
        val value: String,
        val atMillis: Long,
    )

    /** The value last sent as a frame per origin (the request's authority, lowercase), and when. */
    private val sent = AtomicReference<Map<String, Sent>>(emptyMap())

    /**
     * Reads the engine's value once for a response to a request for [authority] and returns it (null: none), for the
     * response's `Alt-Svc` field; when that origin has not had this value as a frame within [refreshMillis], it goes out as
     * an ALTSVC frame through [sendFrame] first, which answers false when the stream could no longer carry it.
     */
    fun advertise(
        authority: String?,
        sendFrame: (String) -> Boolean,
    ): String? {
        val v = value() ?: return null
        val origin = authority?.lowercase() ?: ""
        val now = nowMillis()
        val mine = Sent(v, now)
        while (true) {
            val m = sent.load()
            val last = m[origin]
            if (last != null && last.value == v && now - last.atMillis < refreshMillis) return v
            val next = if (origin !in m && m.size >= MAX_ORIGINS) mapOf(origin to mine) else m + (origin to mine)
            if (sent.compareAndSet(m, next)) break
        }
        // a stream that can no longer send (reset meanwhile) did not carry it: the next stream of the origin does
        if (!sendFrame(v)) forget(origin, mine)
        return v
    }

    private fun forget(
        origin: String,
        mine: Sent,
    ) {
        while (true) {
            val m = sent.load()
            if (m[origin] !== mine) return
            if (sent.compareAndSet(m, m - origin)) return
        }
    }

    internal companion object {
        const val MAX_ORIGINS = 16

        /** Half the `ma` (86400 s) the engine advertises: a client re-learns the frame well before its entry expires. */
        const val REFRESH_MILLIS: Long = 43_200_000

        private val start = TimeSource.Monotonic.markNow()
        private val MONOTONIC: () -> Long = { start.elapsedNow().inWholeMilliseconds }
    }
}
