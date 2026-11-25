// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.kuicksilver.http3.Http3Headers
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * The length a `content-length` field states for the stream's framing ([contentLength]): `Content-Length = 1*DIGIT` (RFC 9110
 * section 8.6), nothing else. Before, Kotlin's `toLongOrNull` took a sign (`+5` as 5, `-5` as -5) and a Unicode `trim()` took
 * a no-break space for whitespace, so a value a strict recipient refuses framed a body here (the request-smuggling class).
 * The peer's fields are checked before (FieldValidator), so this matters for any value that reaches the helper unchecked.
 */
class ContentLengthTest {
    private fun of(v: String) = contentLength(Http3Headers.of("content-length" to v))

    @Test fun negative_onlyDigitsAreALength() {
        for (v in listOf("+5", "-5", " 5", "5 ", " 5", "5 ", "\t5", "", "0x5", "5.0", "1_0", "٥")) {
            assertNull(of(v), "'$v'")
        }
    }

    @Test fun digitsAreTheLength() {
        assertEquals(5L, of("5"))
        assertEquals(0L, of("0"))
        assertEquals(5L, of("0005"))
        assertEquals(Long.MAX_VALUE, of(Long.MAX_VALUE.toString()))
        assertNull(of("9223372036854775808"), "a length that does not fit is no length the stream can frame")
        assertNull(contentLength(Http3Headers.of()))
    }
}
