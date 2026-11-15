// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

import kotlin.test.Test
import kotlin.test.assertEquals

/** `WT-Available-Protocols` and `WT-Protocol` at the edges of their grammar (draft-ietf-webtrans-http3-16 section 3.3). */
class WtProtocolsGapTest {
    /**
     * Section 3.3: `WT-Available-Protocols` is a Structured Field List of Strings; a String is printable ASCII 0x20-0x7E
     * (RFC 9651 section 3.3.3), members are separated by "," with optional spaces, and parameters on them are ignored.
     */
    @Test fun negative_protocolListEdges() {
        assertEquals(true, WtProtocols.isValid("~"))
        assertEquals(true, WtProtocols.isValid(" "))
        assertEquals(false, WtProtocols.isValid("\u007f"))
        assertEquals(false, WtProtocols.isValid("\u001f"))
        assertEquals(listOf("a", "b"), WtProtocols.parseList("\"a\",\"b\""))
        assertEquals(listOf("a", "b"), WtProtocols.parseList("\"a\" ,  \"b\""))
        assertEquals(listOf("a", "b"), WtProtocols.parseList("\"a\";k=\"x,y\", \"b\""))
        assertEquals(listOf("a", "b"), WtProtocols.parseList("\"a\";k=v;j, \"b\""))
        assertEquals(listOf("a", "b"), WtProtocols.parseList("\"a\";k=v\t,\"b\""))
        assertEquals(listOf("~"), WtProtocols.parseList("\"~\""))
        assertEquals(null, WtProtocols.parseList("\"\u007f\""))
        assertEquals(null, WtProtocols.parseList("\"a\";k=,\"b\""))
        assertEquals(null, WtProtocols.parseList("\"a\";k=\"x"))
        assertEquals(null, WtProtocols.parseList("\"a\","))
        assertEquals("a", WtProtocols.parseItem("\"a\";q=1"))
        // parameters ending the value, an uppercase key after a value, and whitespace before ";" (RFC 9651 section 3.1.2:
        // `parameters = *( ";" *SP parameter )`, no whitespace before the ";")
        assertEquals(listOf("a"), WtProtocols.parseList("\"a\";k"))
        assertEquals(null, WtProtocols.parseList("\"a\";k="))
        assertEquals(null, WtProtocols.parseList("\"a\";k=v;J"))
        assertEquals(null, WtProtocols.parseList("\"a\";k=v\t;j"))
    }
}
