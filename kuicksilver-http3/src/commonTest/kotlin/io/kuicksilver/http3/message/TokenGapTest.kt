// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.message

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** Token grammars at the edges of their character ranges. */
class TokenGapTest {
    /**
     * RFC 9110 section 5.6.2: `token = 1*tchar`, `tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" /
     * "_" / "`" / "|" / "~" / DIGIT / ALPHA`; RFC 9114 section 4.3.1 checks `:method` against it. The characters next to
     * each range (`@` `[` `` ` `` `{` `/` `:`) are not tchar except the backquote.
     */
    @Test fun negative_methodTokenRangeEdges() {
        for (t in listOf("a", "z", "A", "Z", "0", "9", "GET", "M-SEARCH", "x`y")) assertEquals(true, FieldValidator.isToken(t), t)
        for (t in listOf("", "[", "@", "{", "/", ":", "GE T", "A[", "Z@")) assertEquals(false, FieldValidator.isToken(t), t)
        // field names (RFC 9114 section 4.2: lowercase tokens; "Characters in field names MUST be converted to lowercase")
        for (n in listOf("a", "z", "0", "9", "x-a`")) assertNull(FieldValidator.checkName(n), n)
        for (n in listOf("{", "a{", "`a{", "a[", "a@", "a/", "a:", "A")) assertNotNull(FieldValidator.checkName(n), n)
    }

    /**
     * RFC 9218 section 4 carries priority parameters in a Structured Field Dictionary (RFC 8941 section 3.2); a token value
     * is `( ALPHA / "*" ) *( tchar / ":" / "/" )` (section 3.3.4). A malformed member makes the whole field invalid.
     */
    @Test fun negative_priorityTokenRangeEdges() {
        for (v in listOf("x=a", "x=z", "x=A", "x=Z", "x=*", "x=az", "x=aZ", "x=a0", "x=a9", "x=a:/", "x=a!")) {
            assertNotNull(PriorityDictionary.parse(v), v)
        }
        for (v in listOf("x={", "x=[", "x=@", "x=`", "x=a{", "x=a[", "x=a@", "x=a;")) assertNull(PriorityDictionary.parse(v), v)
        // keys (RFC 8941 section 3.2): `( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" )`
        for (k in listOf("az", "a0", "a9", "a_", "a-", "a.", "a*")) assertNotNull(PriorityDictionary.parse("$k=1"), k)
        for (k in listOf("a{", "a:", "a/", "aZ", "a`")) assertNull(PriorityDictionary.parse("$k=1"), k)
        // integers, decimals and byte sequences (RFC 8941 sections 3.3.1, 3.3.2, 3.3.5): digit and base64 range edges
        for (v in listOf("x=19", "x=1.9", "x=:YQ==:", "x=:azAZ09+/:", "x=::")) assertNotNull(PriorityDictionary.parse(v), v)
        for (v in listOf("x=1:", "x=1.:", "x=:Y===:", "x=:a[:", "x=:a{:", "x=:a@:", "x=:YQ")) assertNull(PriorityDictionary.parse(v), v)
        // inner lists (section 3.1.1) cut before their closing parenthesis
        for (v in listOf("x=(", "x=(a", "x=(a ")) assertNull(PriorityDictionary.parse(v), v)
        assertNotNull(PriorityDictionary.parse("x=(a b)"))
    }
}
