// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.message

import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.frame.H3ProtocolError
import io.kuicksilver.http3.frame.VarInt
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** Capsule Protocol corners (RFC 9297 sections 3.2-3.4) the parser and field tests did not reach. */
class CapsuleGapTest {
    private fun capsule(
        type: Long,
        payload: ByteArray,
    ) = VarInt.encode(type) + VarInt.encode(payload.size.toLong()) + payload

    /**
     * The read loop hands [CapsuleParser.feedOne] a window `[off, off + len)` of its buffer and advances by the returned
     * count; the count is relative to `off`, also when the capsule delivered is empty (complete at its header) and when no
     * capsule completes in the window.
     */
    @Test fun negative_feedOneCountsFromItsOffset() {
        val p = CapsuleParser(known = setOf(0x00L, 0x41L))
        val junk = byteArrayOf(9, 9, 9)
        val bytes = junk + capsule(0x41, ByteArray(0)) + capsule(0x00, byteArrayOf(1, 2, 3))
        val got = ArrayList<Pair<Long, Int>>()
        var at = junk.size
        val consumed = p.feedOne(bytes, at, bytes.size - at) { t, v -> got += t to v.size }
        assertEquals(3, consumed, "type (two bytes) and length of the empty capsule")
        at += consumed
        // half of the next capsule: nothing completes, all of it is consumed
        val half = 3
        assertEquals(half, p.feedOne(bytes, at, half) { t, v -> got += t to v.size })
        at += half
        assertEquals(bytes.size - at, p.feedOne(bytes, at, bytes.size - at) { t, v -> got += t to v.size })
        assertEquals(listOf(0x41L to 0, 0x00L to 3), got)
        p.endOfStream()
    }

    /** The capsule ceiling is inclusive: a known capsule exactly as long as it is delivered, one byte more is H3_MESSAGE_ERROR. */
    @Test fun negative_capsuleExactlyAtTheCeiling() {
        val got = ArrayList<Int>()
        val exact = capsule(0x41, ByteArray(10))
        CapsuleParser(maxCapsuleLength = 10, known = setOf(0x41L)).feed(exact, 0, exact.size) { _, v -> got += v.size }
        assertEquals(listOf(10), got)
        val over = capsule(0x41, ByteArray(11))
        val e =
            assertFailsWith<H3ProtocolError> {
                CapsuleParser(
                    maxCapsuleLength = 10,
                    known = setOf(0x41L),
                ).feed(over, 0, over.size) { _, _ -> }
            }
        assertEquals(Http3ErrorCode.MESSAGE_ERROR, e.code)
    }

    private fun enabled(v: String) = CapsuleRules.isEnabled(Http3Headers.of("capsule-protocol" to v))

    /**
     * RFC 9297 section 3.4: the field "is an Item Structured Field" whose "value MUST be a Boolean"; "Receivers MUST ignore
     * unknown parameters", and "any other value type MUST be handled as if the field were not present". Parameters follow
     * RFC 8941 section 3.1.2: `parameters = *( ";" *SP parameter )`, `key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" /
     * "-" / "." / "*" )`, values are bare items (section 3.3). Every well-formed parameter is ignored; a malformed one makes
     * the field invalid (false), never an exception.
     */
    @Test fun negative_capsuleProtocolParameters() {
        val wellFormed =
            listOf(
                "?1;a",
                "?1; a",
                "?1;  a;b",
                "?1;*",
                "?1;z",
                "?1;a0_-.*z9",
                "?1;ba",
                "?1;k=-1",
                "?1;k=12.5",
                "?1;k=0",
                "?1;k=9",
                "?1;k=\"s\"",
                "?1;k=tok",
                "?1;k=Tok",
                "?1;k=*t",
                "?1;k=:YQ==:",
                "?1;k=?0",
                "?1;a=1;b=?1",
            )
        for (v in wellFormed) assertEquals(true, enabled(v), v)
        val malformed =
            listOf(
                "?1;",
                "?1;A",
                "?1;0a",
                "?1;_a",
                "?1;{",
                "?1;`",
                "?1;a=",
                "?1;a;",
                "?1;a=-",
                "?1;a=.5",
                "?1;aB",
                "?1;a:",
                "?1;a{",
                "?1;a/",
                "?1;a@",
                "?1;a=@",
            )
        for (v in malformed) assertEquals(false, enabled(v), v)
    }

    /**
     * The bare items of RFC 8941 section 3.3 as parameter values, at every boundary of their grammar: integers (at most 15
     * digits), decimals (at most 12 integer and 1-3 fractional digits), strings (printable ASCII 0x20-0x7E, `\"` and `\\`
     * escapes only), tokens (`( ALPHA / "*" ) *( tchar / ":" / "/" )`), byte sequences (`":" *base64 ":"`) and Booleans.
     */
    @Test fun negative_capsuleProtocolParameterValues() {
        val q = '"'
        val wellFormed =
            listOf(
                "k=19",
                "k=" + "9".repeat(15),
                "k=" + "1".repeat(12) + ".5",
                "k=1.9",
                "k=1.0",
                "k=1.123",
                "k=$q$q",
                "k=$q~$q",
                "k=$q $q",
                "k=${q}a\\${q}b$q",
                "k=${q}a\\\\$q",
                "k=a",
                "k=z",
                "k=A",
                "k=Z",
                "k=*",
                "k=aa",
                "k=az",
                "k=aA",
                "k=aZ",
                "k=a0",
                "k=a9",
                "k=a!",
                "k=a`",
                "k=a:/",
                "k=::",
                "k=:azAZ09+/=:",
                "k=?1",
            )
        for (v in wellFormed) assertEquals(true, enabled("?1;$v"), v)
        val malformed =
            listOf(
                "k=1:",
                "k=" + "9".repeat(16),
                "k=" + "1".repeat(13) + ".5",
                "k=1.",
                "k=1.:",
                "k=1.1234",
                "k=${q}abc",
                "k=${q}a\\b$q",
                "k=${q}a\\",
                "k=$q\u007f$q",
                "k=$q\u001f$q",
                "k=[",
                "k={",
                "k=@",
                "k=`",
                "k=a[",
                "k=a{",
                "k=a@",
                "k=:YQ",
                "k=:YQ==",
                "k=:a[:",
                "k=?",
                "k=?2",
            )
        for (v in malformed) assertEquals(false, enabled("?1;$v"), v)
    }
}
