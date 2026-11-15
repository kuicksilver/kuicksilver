// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Fixtures
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.runtime.RawPeer
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/** `WT-Available-Protocols` and `WT-Protocol` at the edges of their grammar (draft-ietf-webtrans-http3-16 section 3.3). */
class WtProtocolsGapTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

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

    /**
     * Section 3.3: "Any value type other than String MUST be treated as an error that causes the entire field to be ignored
     * as recommended in [FIELDS]"; "parameters MUST be ignored", but they are still parsed as RFC 8941 parameters
     * (section 3.1.2: `key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" )`, a value is a bare item of
     * section 3.3), and a field that fails to parse is ignored as a whole (section 4.2). A parameter value that is no bare
     * item, or a key outside ASCII lowercase, makes the whole list or item invalid.
     */
    @Test fun negative_malformedParametersInvalidateTheField() {
        val badParameters =
            listOf(
                "k=@@",
                "k=:Y:",
                "k=:=YQ:",
                "k=1.2345",
                "k=\"x",
                "k=?2",
                "k=a@",
                "1k=v",
                "\u00e9=1",
                "k\u0661=1",
                "K=1",
                "k=",
            )
        for (p in badParameters) {
            assertEquals(null, WtProtocols.parseList("\"a\";$p, \"b\""), p)
            assertEquals(null, WtProtocols.parseItem("\"a\";$p"), p)
        }
        val goodParameters = listOf("k=1", "k=-1.5", "k=\"x y\"", "k=tok/en:1", "k=:YQ==:", "k=?1", "*k_-.*9=1", "k")
        for (p in goodParameters) {
            assertEquals(listOf("a", "b"), WtProtocols.parseList("\"a\";$p, \"b\""), p)
            assertEquals("a", WtProtocols.parseItem("\"a\";$p"), p)
        }
    }

    /** The same rule end to end: a request whose WT-Available-Protocols does not parse offers no protocol at all. */
    @Test fun negative_malformedAvailableProtocolsAreIgnoredAsAWhole() =
        h3Test {
            QuicPair.open(H3Fixtures.quic).useScoped { q ->
                val (c, s) = q.connect(H3Fixtures.quic)
                val server = Http3Connection.server(s, wtOn)
                val raw = RawPeer(c)
                raw.openControl(wtClientSettings)
                for ((value, expected) in listOf("\"a\";k=@@, \"b\"" to emptyList(), "\"a\";k=tok, \"b\"" to listOf("a", "b"))) {
                    val st = c.openBidi()
                    st.output.writeFully(raw.wtConnect(st, WtTokens.H3, WtProtocols.AVAILABLE_FIELD to value))
                    st.output.flush()
                    val r = withTimeout(5.seconds) { server.acceptRequest() }
                    assertEquals(expected, r.availableProtocols, value)
                    r.reset(Http3ErrorCode.REQUEST_CANCELLED)
                }
            }
        }
}
