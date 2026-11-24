// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The list rules of RFC 9110 section 5.6.1 as [fieldListElements] and [connectionOptions] apply them. */
class FieldListsTest {
    /** Empty values and values of only commas and OWS are lists without elements, not errors (section 5.6.1.2). */
    @Test fun negative_emptyListsHaveNoElements() {
        for (value in listOf("", " ", "\t", ",", " , ,\t,", ",,,,")) {
            assertEquals(emptyList(), fieldListElements(listOf(value)), "'$value'")
            assertEquals(emptySet(), connectionOptions(listOf(value)), "'$value'")
        }
        assertEquals(emptySet(), connectionOptions(emptyList()))
    }

    /** OWS is SP and HTAB around each element; empty elements anywhere are skipped; lines combine; options lowercase. */
    @Test fun negative_elementsSurviveEmptyElementsOwsAndLineSplits() {
        assertEquals(listOf("foo", "bar", "charlie"), fieldListElements(listOf("foo , ,bar,charlie")))
        assertEquals(listOf("foo", "bar"), fieldListElements(listOf("foo ,bar,")))
        assertEquals(setOf("close", "upgrade"), connectionOptions(listOf("Close,\tUPGRADE")))
        assertEquals(setOf("keep-alive", "upgrade", "x-a"), connectionOptions(listOf("keep-alive", "", " Upgrade ,X-A,")))
    }

    /**
     * The names of `Sec-WebSocket-Extensions` (RFC 6455 section 9.1) lose SP and HTAB around them, never another Unicode
     * space (RFC 9110 section 5.6.3): "\u00a0permessage-deflate" is not the name "permessage-deflate". Before, Kotlin's
     * `trim()` made it one.
     */
    @Test fun negative_webSocketExtensionNamesTrimOwsOnly() {
        assertEquals(listOf("permessage-deflate", "x-a"), webSocketExtensionNames(listOf(" permessage-deflate ;\tclient_max_window_bits,\tX-A ")))
        assertEquals(listOf("\u00a0permessage-deflate"), webSocketExtensionNames(listOf("\u00a0permessage-deflate")))
        assertEquals(listOf("x-a\u2003"), webSocketExtensionNames(listOf("x-a\u2003; p=1")))
    }

    /** Random lists of tokens with empty elements and OWS mixed in read back as their tokens, whatever the split. */
    @Test fun randomListsReadBackAsTheirTokens() {
        val random = Random(20261115)
        val tokens = listOf("close", "keep-alive", "upgrade", "te", "x-y", "a")
        val glue = listOf(",", ", ", " ,", "\t,\t", ",,", ", ,", " , \t, ")
        repeat(2_000) {
            val picked = List(random.nextInt(0, 6)) { tokens[random.nextInt(tokens.size)] }
            val lines = mutableListOf<String>()
            val sb = StringBuilder(glue[random.nextInt(glue.size)].takeIf { random.nextBoolean() } ?: "")
            for ((i, t) in picked.withIndex()) {
                sb.append(if (random.nextBoolean()) t.uppercase() else t)
                if (i < picked.lastIndex) {
                    if (random.nextInt(4) == 0) {
                        lines += sb.toString()
                        sb.clear()
                    } else {
                        sb.append(glue[random.nextInt(glue.size)])
                    }
                }
            }
            if (random.nextBoolean()) sb.append(glue[random.nextInt(glue.size)])
            lines += sb.toString()
            assertEquals(picked, fieldListElements(lines).map { it.lowercase() }, lines.toString())
            assertEquals(picked.toSet(), connectionOptions(lines), lines.toString())
            assertTrue(fieldListElements(lines).none { it.isEmpty() || it.first() in " \t" || it.last() in " \t" })
        }
    }
}
