// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame

class ReleaserTest {
    @Test fun theFirstFailureWinsAndEveryStepRuns() {
        val body = IllegalStateException("body")
        val r = Releaser()
        r.note(body) // a teardown body that failed first, as the endpoint's close job notes it
        var ran = 0
        r.release {
            ran++
            throw IllegalArgumentException("release 1")
        }
        r.release { ran++ }
        val e = assertFailsWith<IllegalStateException> { r.finish() }
        assertSame(body, e)
        assertEquals(2, ran)
        assertEquals(listOf("release 1"), e.suppressedExceptions.map { it.message })
    }

    @Test fun nothingFailedNothingThrown() {
        val r = Releaser()
        r.release {}
        r.finish()
    }
}
