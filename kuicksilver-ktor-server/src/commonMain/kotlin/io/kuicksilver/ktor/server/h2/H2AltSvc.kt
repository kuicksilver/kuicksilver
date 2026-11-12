// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h2

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.http2.runtime.H2ServerStream
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * The engine's `Alt-Svc` on one HTTP/2 connection (RFC 7838). Section 3: "When using HTTP/2 ([RFC7540]), servers SHOULD
 * instead send an ALTSVC frame (Section 4). A single ALTSVC frame can be sent for a connection; a new frame is not needed for
 * every request." So the value goes out as an ALTSVC frame on a request stream (an empty Origin: it applies to that stream's
 * origin, section 4), once per origin of the connection and value: again only when the value changed (`http3Advertising`
 * turned it into `clear`, or back). At most [MAX_ORIGINS] origins are remembered; past them, the memory starts over.
 */
@OptIn(ExperimentalAtomicApi::class, InternalKuicksilverApi::class)
internal class H2AltSvc(
    private val value: () -> String?,
) {
    /** The value last sent per origin (the request's authority, lowercase). */
    private val sent = AtomicReference<Map<String, String>>(emptyMap())

    /** Sends the engine's value on [stream] unless the stream's origin already has it; before the response head. */
    fun advertise(stream: H2ServerStream) {
        val v = value() ?: return
        val origin = stream.authority?.lowercase() ?: ""
        while (true) {
            val m = sent.load()
            if (m[origin] == v) return
            val next = if (origin !in m && m.size >= MAX_ORIGINS) mapOf(origin to v) else m + (origin to v)
            if (sent.compareAndSet(m, next)) break
        }
        // a stream that can no longer send (reset meanwhile) did not carry it: the next stream of the origin does
        if (!stream.altSvc(v)) forget(origin, v)
    }

    private fun forget(
        origin: String,
        v: String,
    ) {
        while (true) {
            val m = sent.load()
            if (m[origin] != v) return
            if (sent.compareAndSet(m, m - origin)) return
        }
    }

    private companion object {
        const val MAX_ORIGINS = 16
    }
}
