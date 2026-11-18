// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing

import kotlin.test.Test
import kotlin.test.assertEquals

/** The simulator's trace hash is FNV-1a 64 with the standard offset basis and prime ([Fnv1a64]). */
class TraceHashTest {
    private fun hex(v: Long) = v.toULong().toString(16).padStart(16, '0')

    @Test fun theReferenceValuesHold() {
        assertEquals("cbf29ce484222325", hex(Fnv1a64.of(ByteArray(0))))
        assertEquals("af63dc4c8601ec8c", hex(Fnv1a64.of("a".encodeToByteArray())))
        assertEquals("e71fa2190541574b", hex(Fnv1a64.of("abc".encodeToByteArray())))
    }

    @Test fun negative_theOldOffsetBasisIsNotTheBasis() {
        // one digit short of 14695981039346656037: "abc" then hashes to e16801510db89efd
        assertEquals("cbf29ce484222325", hex(Fnv1a64.BASIS))
        var h = 1469598103934665603L
        for (b in "abc".encodeToByteArray()) h = Fnv1a64.mix(h, (b.toInt() and 0xff).toLong())
        assertEquals("e16801510db89efd", hex(h))
    }
}
