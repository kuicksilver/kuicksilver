// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.compose.server

import kotlin.test.Test
import kotlin.test.assertEquals

/** The demo server's `Range` parsing: one byte range, digits only, anything else ignored (RFC 9110 sections 14.1.2 and 14.2). */
class RangeTest {
    private fun part(
        first: Long,
        last: Long,
    ) = RangeRequest.Part(first, last)

    @Test fun firstToEnd() {
        assertEquals(part(400, 999), parseRange("bytes=400-", 1000))
        assertEquals(part(0, 999), parseRange("bytes=0-", 1000))
    }

    @Test fun firstToLastClampedToTheBody() {
        assertEquals(part(10, 19), parseRange("bytes=10-19", 1000))
        assertEquals(part(990, 999), parseRange("bytes=990-5000", 1000))
        assertEquals(part(5, 5), parseRange("bytes=5-5", 1000))
    }

    @Test fun unitIsCaseInsensitive() {
        assertEquals(part(400, 999), parseRange("BYTES=400-", 1000))
        assertEquals(part(400, 999), parseRange("Bytes=400-", 1000))
    }

    @Test fun suffix() {
        assertEquals(part(900, 999), parseRange("bytes=-100", 1000))
        assertEquals(part(0, 999), parseRange("bytes=-5000", 1000), "a suffix longer than the body is the whole body")
    }

    @Test fun negative_zeroSuffixIsUnsatisfiable() {
        assertEquals(RangeRequest.Unsatisfiable, parseRange("bytes=-0", 1000))
    }

    @Test fun negative_firstPastTheEndIsUnsatisfiable() {
        assertEquals(RangeRequest.Unsatisfiable, parseRange("bytes=1000-", 1000))
        assertEquals(RangeRequest.Unsatisfiable, parseRange("bytes=99999999999999999999-", 1000), "an overflowing first byte")
        assertEquals(RangeRequest.Unsatisfiable, parseRange("bytes=0-", 0), "an empty body has no byte to send")
        assertEquals(RangeRequest.Unsatisfiable, parseRange("bytes=-10", 0))
    }

    @Test fun negative_malformedIsIgnored() {
        for (h in listOf(
            "bytes=5", "bytes=+5-", "bytes=5-+9", "bytes=-+5", "bytes=-", "bytes= 5-", "bytes=5-3", "bytes=0-1,5-6",
            "items=0-5", "bytes=a-", "bytes 0-5", "", "bytes=0x10-",
        )) {
            assertEquals(RangeRequest.Whole, parseRange(h, 1000), "'$h' is ignored: the whole body, 200")
        }
        assertEquals(RangeRequest.Whole, parseRange(null, 1000))
    }
}
