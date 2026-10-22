// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** `WT-Available-Protocols` and `WT-Protocol` as Structured Fields (RFC 9651 sections 3.1, 3.3.3). */
class WtProtocolsTest {
    @Test fun listRoundTrip() {
        val offered = listOf("chat-v1", "a \"quoted\" one", "back\\slash")
        assertEquals(offered, WtProtocols.parseList(WtProtocols.formatList(offered)))
    }

    @Test fun parametersAreIgnored() {
        assertEquals(listOf("a", "b"), WtProtocols.parseList("\"a\";q=1;x, \"b\";y=\"z\""))
        assertEquals("a", WtProtocols.parseItem(" \"a\";v=2 "))
    }

    @Test fun emptyListIsEmpty() = assertEquals(emptyList(), WtProtocols.parseList("  "))

    @Test fun negative_malformedListsAreRefused() {
        for (v in listOf("a, b", "\"a\",", "\"a\" \"b\"", "\"unterminated", "\"bad\\escape\"", "\"a\";", "\"tab\there\"")) {
            assertNull(WtProtocols.parseList(v), v)
        }
        assertNull(WtProtocols.parseItem("\"a\", \"b\""))
        assertNull(WtProtocols.parseItem("token"))
    }

    @Test fun onlyPrintableAsciiIsOffered() {
        assertTrue(WtProtocols.isValid("chat v1"))
        assertFalse(WtProtocols.isValid(""))
        assertFalse(WtProtocols.isValid("ü"))
        assertFalse(WtProtocols.isValid("a\nb"))
    }
}
