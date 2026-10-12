// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.message

import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3Request
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.StreamPriority
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class FieldValidatorTest {
    @Test fun negative_h3FieldCrLfNul() {
        assertNotNull(FieldValidator.checkName("x\r"))
        assertNotNull(FieldValidator.checkName("x\ny"))
        assertNotNull(FieldValidator.checkName("x\u0000"))
        assertNotNull(FieldValidator.checkValue("a\nb"))
        assertNotNull(FieldValidator.checkValue("a\rb"))
        assertNotNull(FieldValidator.checkValue("a\u0000b"))
        assertNull(FieldValidator.checkName("x-ok"))
        assertNull(FieldValidator.checkValue("fine value\twith tab"))
    }

    /** Field names and values are octets: a char above U+00FF would be truncated by the Latin-1 encoder, and U+010A truncates to a raw LF. */
    @Test fun negative_h3FieldNonLatin1() {
        assertNotNull(FieldValidator.checkValue("a\u010Ab"))
        assertNotNull(FieldValidator.checkValue("\u20AC"))
        assertNotNull(FieldValidator.checkValue("a\u010Db"))
        assertNotNull(FieldValidator.checkName("a\u010A"))
        assertNull(FieldValidator.checkValue("caf\u00E9"))
    }

    @Test fun uppercaseNameRejected() {
        assertNotNull(FieldValidator.checkName("Content-Type"))
        assertNotNull(FieldValidator.checkName(""))
        assertNotNull(FieldValidator.checkName("a b"))
    }

    @Test fun leadingTrailingWhitespaceRejected() {
        assertNotNull(FieldValidator.checkValue(" a"))
        assertNotNull(FieldValidator.checkValue("a\t"))
        assertNull(FieldValidator.checkValue(""))
    }

    @Test fun connectionSpecificRejected() {
        for (n in listOf("connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade")) {
            assertFailsWith<MalformedMessage> { PseudoHeaders.parseRequest(req + (n to "x"), false) }
        }
    }

    @Test fun teOnlyTrailers() {
        PseudoHeaders.parseRequest(req + ("te" to "trailers"), false)
        assertFailsWith<MalformedMessage> { PseudoHeaders.parseRequest(req + ("te" to "gzip"), false) }
    }

    /** RFC 9110 section 10.1.4: `te` is a request field; a response (or trailers) carrying it is malformed. */
    @Test fun teInResponseIsMalformed() {
        assertFailsWith<MalformedMessage> { PseudoHeaders.parseResponse(listOf(":status" to "200", "te" to "trailers")) }
        assertFailsWith<MalformedMessage> { PseudoHeaders.parseTrailers(listOf("te" to "trailers")) }
    }

    private val req = listOf(":method" to "GET", ":scheme" to "https", ":authority" to "example.com", ":path" to "/")
}

class PseudoHeadersTest {
    private val base = listOf(":method" to "GET", ":scheme" to "https", ":authority" to "example.com", ":path" to "/a?b")

    private fun bad(
        f: List<Pair<String, String>>,
        connect: Boolean = false,
    ) = assertFailsWith<MalformedMessage> {
        PseudoHeaders.parseRequest(f, connect)
    }

    @Test fun validRequest() {
        val r = PseudoHeaders.parseRequest(base + ("accept" to "*/*"), false)
        assertEquals("GET", r.method)
        assertEquals("https", r.scheme)
        assertEquals("example.com", r.authority)
        assertEquals("/a?b", r.path)
        assertNull(r.protocol)
        assertEquals(listOf("accept" to "*/*"), r.regular.fields)
    }

    /** Nineteen digits pass a length check but can exceed Long.MAX_VALUE; such a content-length is malformed, not ignored. */
    @Test fun contentLengthOverflowIsMalformed() {
        bad(base + ("content-length" to "9223372036854775808"))
        bad(base + ("content-length" to "9999999999999999999"))
        assertEquals(
            "9223372036854775807",
            PseudoHeaders.parseRequest(base + ("content-length" to "9223372036854775807"), false).regular["content-length"],
        )
    }

    @Test fun missingPathRejected() {
        bad(base.filter { it.first != ":path" })
        bad(
            base.map {
                if (it.first ==
                    ":path"
                ) {
                    ":path" to ""
                } else {
                    it
                }
            },
        )
    }

    @Test fun missingMethodOrSchemeRejected() {
        bad(base.filter { it.first != ":method" })
        bad(base.filter { it.first != ":scheme" })
    }

    @Test fun pseudoAfterRegularRejected() {
        bad(
            listOf(
                ":method" to "GET",
                "accept" to "*/*",
                ":scheme" to "https",
                ":authority" to "a",
                ":path" to "/",
            ),
        )
    }

    @Test fun duplicatePseudoRejected() {
        bad(base + (":path" to "/x"))
    }

    @Test fun unknownOrResponsePseudoRejected() {
        bad(base + (":foo" to "x"))
        bad(base + (":status" to "200"))
    }

    @Test fun connectAuthorityOnly() {
        val r = PseudoHeaders.parseRequest(listOf(":method" to "CONNECT", ":authority" to "proxy:443"), false)
        assertEquals("proxy:443", r.authority)
        assertNull(r.path)
        bad(listOf(":method" to "CONNECT", ":authority" to "proxy:443", ":path" to "/"))
        bad(listOf(":method" to "CONNECT"))
    }

    @Test fun extendedConnectNeedsSetting() {
        val f = listOf(":method" to "CONNECT", ":protocol" to "websocket", ":scheme" to "https", ":authority" to "a", ":path" to "/chat")
        bad(f, connect = false)
        assertEquals("websocket", PseudoHeaders.parseRequest(f, true).protocol)
        bad(
            listOf(":method" to "GET", ":protocol" to "websocket", ":scheme" to "https", ":authority" to "a", ":path" to "/"),
            connect = true,
        )
    }

    @Test fun authorityHostMismatch() {
        bad(base + ("host" to "other.com"))
        PseudoHeaders.parseRequest(base + ("host" to "example.com"), false)
    }

    @Test fun hostWithoutAuthorityAccepted() {
        assertEquals(
            "h.example",
            PseudoHeaders.parseRequest(base.filter { it.first != ":authority" } + ("host" to "h.example"), false).authority,
        )
    }

    @Test fun responseStatusRange() {
        assertEquals(204, PseudoHeaders.parseResponse(listOf(":status" to "204", "x" to "y")).first)
        for (s in listOf(
            "99",
            "600",
            "20x",
            "2000",
        )) {
            assertFailsWith<MalformedMessage> { PseudoHeaders.parseResponse(listOf(":status" to s)) }
        }
        assertFailsWith<MalformedMessage> { PseudoHeaders.parseResponse(listOf("x" to "y")) }
        assertFailsWith<MalformedMessage> { PseudoHeaders.parseResponse(listOf(":status" to "200", ":path" to "/")) }
    }

    @Test fun trailersWithoutPseudo() {
        assertEquals(1, PseudoHeaders.parseTrailers(listOf("x-checksum" to "1")).size)
        assertFailsWith<MalformedMessage> { PseudoHeaders.parseTrailers(listOf(":status" to "200")) }
    }

    @Test fun buildRequestRoundTrip() {
        val r =
            Http3Request(
                "POST",
                authority = "example.com",
                path = "/up",
                headers = Http3Headers.of("content-type" to "text/plain"),
                priority = StreamPriority(1, true),
            )
        val f = PseudoHeaders.buildRequest(r)
        assertEquals(
            listOf(
                ":method" to "POST",
                ":scheme" to "https",
                ":authority" to "example.com",
                ":path" to "/up",
                "content-type" to "text/plain",
                "priority" to "u=1, i",
            ),
            f,
        )
        assertEquals("/up", PseudoHeaders.parseRequest(f, false).path)
    }
}

class PriorityFieldTest {
    @Test fun defaults() {
        assertEquals(StreamPriority.Default, PriorityField.parse(null))
        assertEquals(StreamPriority.Default, PriorityField.parse(""))
        assertNull(PriorityField.format(StreamPriority.Default))
    }

    @Test fun parsesUAndI() {
        assertEquals(StreamPriority(1, true), PriorityField.parse("u=1, i"))
        assertEquals(StreamPriority(5, false), PriorityField.parse("u=5"))
        assertEquals(StreamPriority(3, true), PriorityField.parse("i=?1"))
        assertEquals(StreamPriority(0, false), PriorityField.parse("u=0, i=?0"))
        assertEquals("u=0", PriorityField.format(StreamPriority(0, false)))
        assertEquals("i", PriorityField.format(StreamPriority(3, true)))
    }

    @Test fun ignoresUnknownAndOutOfRange() {
        assertEquals(StreamPriority.Default, PriorityField.parse("u=9, x=?1"))
        assertEquals(StreamPriority(2, false), PriorityField.parse("x=1;a=b, u=2"))
        assertEquals(StreamPriority.Default, PriorityField.parse("garbage ,,, u="))
        assertEquals(StreamPriority(3, false), PriorityField.parse("i=5"))
    }
}

class Http3ExceptionTest {
    @Test fun unknownCodeIsNoError() {
        val e = Http3Exception.fromQuic(QuicException.ConnectionLost.ApplicationClosed(0x52, "", Initiator.Peer))
        assertEquals(Http3ErrorCode.NO_ERROR, assertIs<Http3Exception.Protocol>(e).h3Code)
        assertEquals(
            Http3ErrorCode.FRAME_ERROR,
            assertIs<Http3Exception.Protocol>(
                Http3Exception.fromQuic(QuicException.ConnectionLost.ApplicationClosed(0x106, "", Initiator.Peer)),
            ).h3Code,
        )
    }

    @Test fun fromQuicMapsRejectedToRequestNotProcessed() {
        assertTrue(
            assertIs<Http3Exception.RequestNotProcessed>(
                Http3Exception.fromQuic(QuicException.StreamError.Reset(4, 0x10b, Initiator.Peer)),
            ).retrySafe,
        )
        assertEquals(
            4L,
            assertIs<Http3Exception.Protocol>(Http3Exception.fromQuic(QuicException.StreamError.Reset(4, 0x10c, Initiator.Peer))).streamId,
        )
        assertEquals(
            0x201L,
            assertIs<Http3Exception.Qpack>(
                Http3Exception.fromQuic(QuicException.ConnectionLost.ApplicationClosed(0x201, "", Initiator.Peer)),
            ).code,
        )
        val t = QuicException.ConnectionLost.StatelessReset()
        assertEquals(t, Http3Exception.fromQuic(t))
    }

    @Test fun copyable() {
        val e = Http3Exception.Protocol(Http3ErrorCode.FRAME_ERROR, Initiator.Local, 8)
        val c = e.createCopy()
        assertEquals(e.h3Code, c.h3Code)
        assertEquals(e.streamId, c.streamId)
        assertEquals(e.message, c.message)
        assertIs<kotlinx.io.IOException>(Http3Exception.Settings("x"))
    }
}

class Http3SettingsTest {
    @Test fun defaults() {
        val s = Http3Settings.Default
        assertEquals(0, s.qpackMaxTableCapacity)
        assertEquals(0, s.qpackBlockedStreams)
        assertEquals(4096, s.encoderMaxTableCapacity)
        assertEquals(65_536, s.maxFieldSectionSize)
        assertEquals(false, s.enableConnectProtocol)
        assertEquals(true, s.h3Datagram)
        assertEquals(true, s.grease)
        assertEquals(5, s.maxInformationalResponses)
        assertEquals(32, s.maxEarlyPriorityUpdates)
        assertEquals(true, s.glitchProtection)
    }

    @Test fun dynamicTableFlag() {
        val s = http3Settings { enableQpackDynamicTable() }
        assertEquals(4096, s.qpackMaxTableCapacity)
        assertEquals(16, s.qpackBlockedStreams)
    }

    @Test fun validation() {
        assertFailsWith<IllegalArgumentException> { http3Settings { maxFieldSectionSize = 0 } }
        assertFailsWith<IllegalArgumentException> {
            http3Settings {
                qpackBlockedStreams =
                    -1
            }
        }
    }
}

class Http3HeadersTest {
    @Test fun lookupIsCaseSensitiveLowercase() {
        val h = Http3Headers.of("a" to "1", "b" to "2", "a" to "3")
        assertEquals("1", h["a"])
        assertEquals(listOf("1", "3"), h.getAll("a"))
        assertEquals(3, h.size)
        assertNull(h["c"])
        assertEquals(0, Http3Headers.Empty.size)
    }
}
