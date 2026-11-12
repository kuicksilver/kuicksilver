// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.kuicksilver.ktor.server.h2.H2AltSvc
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The engine's `Alt-Svc` on one HTTP/2 connection: the field on every response (RFC 7838 section 3: "Alt-Svc header fields
 * remain valid in responses delivered over HTTP/2"), the ALTSVC frame once per origin and value, and again after the refresh
 * interval, so a long-lived connection re-teaches a client whose entry expired or was cleared.
 */
class H2AltSvcTest {
    private var now = 0L
    private var value: String? = "h3=\":443\"; ma=86400"
    private val frames = ArrayList<String>()
    private val a = H2AltSvc({ value }, refreshMillis = 1_000, nowMillis = { now })

    private fun respond(
        authority: String = "example.com",
        sent: Boolean = true,
    ) = a.advertise(authority) {
        frames += "$authority $it"
        sent
    }

    @Test fun negative_frameRefreshedAfterTheIntervalAndOnAChange() {
        assertEquals(value, respond())
        assertEquals(value, respond(), "the field on every response")
        assertEquals(1, frames.size, "one frame per origin and value")
        now = 999
        respond()
        assertEquals(1, frames.size)
        now = 1_000
        respond()
        assertEquals(2, frames.size, "re-sent after the refresh interval")
        value = "clear"
        assertEquals("clear", respond())
        assertEquals("example.com clear", frames.last())
        respond(authority = "other.example")
        assertEquals("other.example clear", frames.last(), "per origin")
        value = null
        assertEquals(null, respond())
        assertEquals(4, frames.size)
    }

    /** A stream that could not carry the frame (reset meanwhile) leaves it to the next stream of the origin. */
    @Test fun negative_unsentFrameIsSentOnTheNextStream() {
        respond(sent = false)
        respond()
        assertEquals(2, frames.size)
        respond()
        assertEquals(2, frames.size)
    }
}
