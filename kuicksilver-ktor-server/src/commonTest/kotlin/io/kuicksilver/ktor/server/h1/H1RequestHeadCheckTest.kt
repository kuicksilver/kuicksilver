// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.server.h1

import io.ktor.http.cio.Request
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runTest
import kotlinx.io.readString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The checks of a request head the server makes before Ktor's parser reads it (`checkRequestHead`): the request line
 * (RFC 9112 section 3, RFC 9110 sections 6.2 and 15.6.6) and the field lines (RFC 9110 section 5).
 */
class H1RequestHeadCheckTest {
    private class Conn(
        val toServer: ByteChannel,
        val fromServer: ByteChannel,
        val job: Job,
    )

    /** A pipeline whose handler answers with the method, target and version it was given. */
    @OptIn(InternalAPI::class)
    private fun TestScope.pipeline(): Conn {
        val toServer = ByteChannel()
        val fromServer = ByteChannel()
        val job =
            backgroundScope.startH1Pipeline(H1Connection(toServer, fromServer, null, null), 45.seconds, 30.seconds) { request ->
                val body =
                    "${request.method.value} ${request.uri} ${request.version}" + (fields.getAll("X-A")?.joinToString("|", " [", "]") ?: "")
                request.release()
                output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n$body")
                output.flush()
            }
        return Conn(toServer, fromServer, job)
    }

    /** Sends [bytes] and then ends the client's side; returns what the server sent until it closed. */
    private suspend fun TestScope.exchange(bytes: ByteArray): String {
        val c = pipeline()
        backgroundScope.launch {
            c.toServer.writeFully(bytes)
            c.toServer.flushAndClose()
        }
        advanceTimeBy(1.seconds)
        assertTrue(c.job.isCompleted, "the connection is still open")
        return c.fromServer.readBuffer().readString()
    }

    private suspend fun TestScope.exchange(text: String): String = exchange(text.encodeToByteArray())

    /** method = token (RFC 9112 section 3.1): anything else is an invalid request line, 400 (section 3.2). */
    @Test fun negative_methodMustBeAToken() =
        runTest {
            for (line in listOf(
                "G\"ET / HTTP/1.1",
                "GE(T / HTTP/1.1",
                "GET\u007f / HTTP/1.1",
                "G\u00e9T / HTTP/1.1",
                "GET\u0000 / HTTP/1.1",
            )) {
                val response = exchange("$line\r\nHost: s\r\n\r\n")
                assertTrue(response.startsWith("HTTP/1.1 400 "), "${show(line)}: $response")
            }
        }

    /** A method that is a token but not one Ktor knows reaches the application. */
    @Test fun anyTokenIsAMethod() =
        runTest {
            val response = exchange("PURGE /x HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n")
            assertTrue(response.endsWith("PURGE /x HTTP/1.1"), response)
        }

    /**
     * A higher minor version of HTTP/1: the server SHOULD process the request as if it were in the highest minor version
     * it conforms to, 1.1 (RFC 9110 section 6.2). Before, Ktor's parser refused it with 400.
     */
    @Test fun higherMinorVersionIsProcessedAsHttp11() =
        runTest {
            for (version in listOf("HTTP/1.2", "HTTP/1.9")) {
                val response = exchange("GET / $version\r\nHost: s\r\nConnection: close\r\n\r\n")
                assertTrue(response.startsWith("HTTP/1.1 200 "), "$version: $response")
                assertTrue(response.endsWith("GET / HTTP/1.1"), "$version: $response")
            }
        }

    /** A major version the server does not support: 505 (RFC 9110 section 15.6.6), the connection closes. Before, 400. */
    @Test fun negative_unsupportedMajorVersionGets505() =
        runTest {
            for (line in listOf("GET / HTTP/2.0", "GET / HTTP/0.9", "GET / HTTP/3.0", "PRI * HTTP/2.0")) {
                val response = exchange("$line\r\nHost: s\r\n\r\nGET / HTTP/1.1\r\nHost: s\r\n\r\n")
                assertTrue(response.startsWith("HTTP/1.1 505 HTTP Version Not Supported\r\n"), "$line: $response")
                assertTrue(response.contains("\r\nConnection: close\r\n"), "$line: $response")
                assertEquals(1, Regex("HTTP/1.1 ").findAll(response).count(), "$line: $response")
            }
        }

    /**
     * RFC 9110 section 9.3.2: the server MUST NOT send content in the response to HEAD, also in the engine's own
     * refusals: the 400 keeps the Content-Length it has for GET (the same header fields as for GET, a SHOULD of the same
     * section) and ends at the empty line, also after leading whitespace. Before, it carried its text. (The 0.2.x 505
     * carries no content for any method.)
     */
    @Test fun negative_noContentInARefusalOfHead() =
        runTest {
            for ((head, status) in listOf(
                " HEAD / HTTP/1.1\r\nHost: s\r\nX-A: a\u0000b\r\n" to "400",
                "HEAD / HTTP/1.1\r\nHost: s\r\nX-A: a\u0000b\r\n" to "400",
                "HEAD / HTTP/1.1\r\nHost: a\r\nHost: b\r\n" to "400",
                "HEAD /\u0001 HTTP/1.1\r\nHost: s\r\n" to "400",
            )) {
                val get = exchange(head.trimStart().replaceFirst("HEAD", "GET") + "\r\n")
                val response = exchange("$head\r\nGET /next HTTP/1.1\r\nHost: s\r\n\r\n")
                assertTrue(response.startsWith("HTTP/1.1 $status "), "${show(head)}: $response")
                assertTrue(response.endsWith("\r\n\r\n"), "${show(head)}: content after the head: $response")
                val length = Regex("\r\nContent-Length: (\\d+)\r\n").find(get)!!.groupValues[1]
                assertTrue(length.toInt() > 0, get)
                assertTrue(response.contains("\r\nContent-Length: $length\r\n"), "${show(head)}: $response")
            }
        }

    /** HTTP-version = "HTTP/" DIGIT "." DIGIT, case-sensitive (RFC 9112 section 2.3); anything else: 400. */
    @Test fun negative_malformedVersionIsRejected() =
        runTest {
            for (version in listOf("http/1.1", "HTTP/1.10", "HTTP/1", "HTTP/11", "HTTP/1.x", "HTTP/1.1x")) {
                val response = exchange("GET / $version\r\nHost: s\r\n\r\n")
                assertTrue(response.startsWith("HTTP/1.1 400 "), "$version: $response")
            }
        }

    /**
     * Control characters in a request line are no separator (RFC 9112 section 3 allows SP, HTAB, VT, FF and a bare CR as
     * one) and no part of a target: 400. Nor is a non-ASCII space (U+00A0, `C2 A0`), which Ktor's parser took as one.
     */
    @Test fun negative_controlCharactersAndUnicodeSpacesInTheRequestLineAreRejected() =
        runTest {
            for (line in listOf(
                "GET /a\u0001b HTTP/1.1",
                "GET /a\u007fb HTTP/1.1",
                "GET\u00a0/ HTTP/1.1",
                "GET /\u00a0HTTP/1.1",
                "GET /\u001fHTTP/1.1",
                // a TLS ClientHello sent optimistically after `Upgrade: TLS` (RFC 9931 section 6.1): 0x16 is no tchar
                "\u0016\u0003\u0001\u0002\u0000GET / HTTP/1.1",
            )) {
                val response = exchange("$line\r\nHost: s\r\n\r\n")
                assertTrue(response.startsWith("HTTP/1.1 400 "), "${show(line)}: $response")
            }
        }

    /** The whitespace RFC 9112 section 3 lets a server take as SP still separates the parts. */
    @Test fun lenientSeparatorsAreAccepted() =
        runTest {
            for (line in listOf("GET\t/ HTTP/1.1", "GET  /  HTTP/1.1 ", "GET\u000b/\u000cHTTP/1.1")) {
                val response = exchange("$line\r\nHost: s\r\nConnection: close\r\n\r\n")
                assertTrue(response.endsWith("GET / HTTP/1.1"), "${show(line)}: $response")
            }
        }

    /**
     * RFC 9110 section 5.5: a recipient of CR, LF or NUL within a field value MUST either reject the message or replace
     * each of them with SP; field-content is VCHAR, obs-text, SP and HTAB, so the other control characters (DEL among
     * them) are invalid too. 400 and close, the pipelined request behind is not served. Before, a NUL or a VT reached the
     * application.
     */
    @Test fun negative_controlCharactersInAFieldValueAreRejected() =
        runTest {
            for (value in listOf("a\u0000b", "a\u0001b", "\u007f", "a\u001fb", "a\u000bb", "a\u000cb", "a\rb")) {
                val response = exchange("GET / HTTP/1.1\r\nHost: s\r\nX-A: $value\r\n\r\nGET /next HTTP/1.1\r\nHost: s\r\n\r\n")
                assertTrue(response.startsWith("HTTP/1.1 400 "), "${show(value)}: $response")
                assertEquals(1, Regex("HTTP/1.1 ").findAll(response).count(), "${show(value)}: $response")
            }
        }

    /** HTAB, SP and obs-text (bytes above 0x7F) are field content (RFC 9110 section 5.5) and reach the application. */
    @Test fun tabsSpacesAndObsTextInAFieldValueAreAccepted() =
        runTest {
            val response = exchange("GET / HTTP/1.1\r\nHost: s\r\nX-A: \ta\tb c\u00e9 \r\nConnection: close\r\n\r\n")
            assertTrue(response.endsWith("GET / HTTP/1.1 [a\tb c\u00e9]"), response)
        }

    /**
     * field-name = token (RFC 9110 section 5.1): a name with DEL or a byte above 0x7F is invalid, 400. Ktor's parser
     * refused only delimiters and whitespace in a name (and whitespace before the colon, RFC 9112 section 5.1).
     */
    @Test fun negative_fieldNameMustBeAToken() =
        runTest {
            for (name in listOf("X-\u007f", "X-\u00e9", "X\"A", "X-A ", "")) {
                val response = exchange("GET / HTTP/1.1\r\nHost: s\r\n$name: a\r\n\r\nGET /next HTTP/1.1\r\nHost: s\r\n\r\n")
                assertTrue(response.startsWith("HTTP/1.1 400 "), "${show(name)}: $response")
                assertEquals(1, Regex("HTTP/1.1 ").findAll(response).count(), "${show(name)}: $response")
            }
        }

    /**
     * A field value may start with obs-text (RFC 9110 section 5.5: field-content), which a recipient SHOULD treat as
     * opaque data. Ktor's parser skips any Unicode whitespace before a value, so `X-A: <U+00A0>a` reached the
     * application as `a`; the server now hands on the value as sent (only SP and HTAB are OWS, section 5.6.3), the second
     * of two lines too. Before the fix that preceded this, a 400; before that, the stripped value.
     */
    @Test fun unicodeSpaceBeforeAFieldValueIsKept() =
        runTest {
            for ((field, value) in listOf(
                "X-A: \u00a0a" to "\u00a0a",
                "X-A:\u2000a" to "\u2000a",
                "X-A: \t\u3000a \t" to "\u3000a",
                "X-A: \u00a0" to "\u00a0",
                "X-A: one\r\nx-a: \u00a0two" to "one|\u00a0two",
            )) {
                val response = exchange("GET / HTTP/1.1\r\nHost: s\r\n$field\r\nConnection: close\r\n\r\n")
                assertTrue(response.endsWith("GET / HTTP/1.1 [$value]"), "${show(field)}: $response")
            }
        }

    /**
     * The same values in a field the server reads itself are invalid there: `Content-Length: <U+00A0>5` is not `1*DIGIT`
     * and `Transfer-Encoding: <U+2009>chunked` no transfer coding (RFC 9112 section 6.3 items 4 and 5: 400 and close),
     * `Host: <U+00A0>a` no `uri-host` (section 3.2). Ktor's parser stripped the space, so the first framed a 5-byte body
     * while a front proxy that finds the value invalid frames none (CL.0 smuggling).
     */
    @Test fun negative_unicodeSpaceBeforeAFramingValueIsRejected() =
        runTest {
            val next = "GET /next HTTP/1.1\r\nHost: s\r\n\r\n"
            for (head in listOf(
                "POST / HTTP/1.1\r\nHost: s\r\nContent-Length: \u00a05\r\n\r\nhello",
                "POST / HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: \u2009chunked\r\n\r\n0\r\n\r\n",
                "GET / HTTP/1.1\r\nHost: \u00a0a\r\n\r\n",
            )) {
                val response = exchange("$head$next")
                assertTrue(response.startsWith("HTTP/1.1 400 "), "${show(head)}: $response")
                assertEquals(1, Regex("HTTP/1.1 ").findAll(response).count(), "${show(head)}: $response")
            }
        }

    /** A Unicode space inside or at the end of a value is obs-text, field content (RFC 9110 section 5.5): passed on. */
    @Test fun unicodeSpaceInsideAFieldValueIsAccepted() =
        runTest {
            val response = exchange("GET / HTTP/1.1\r\nHost: s\r\nX-A: a\u00a0b\u00a0\r\nConnection: close\r\n\r\n")
            assertTrue(response.endsWith("[a\u00a0b\u00a0]"), response)
        }

    /**
     * The request-target forms of RFC 9112 section 3.2: origin-form (RFC 3986 path and query characters), absolute-form
     * (an absolute-URI, no fragment), authority-form for CONNECT only, asterisk-form for OPTIONS only. All are served.
     */
    @Test fun validRequestTargetsAreServed() =
        runTest {
            for (line in listOf(
                "GET /a/b;c=d?e=f&g=%41:@!\$'()*+,~-._/? HTTP/1.1",
                "GET / HTTP/1.1",
                "OPTIONS * HTTP/1.1",
                "CONNECT a.example:443 HTTP/1.1",
                "CONNECT [::1]:8443 HTTP/1.1",
                "GET http://a.example/x?y HTTP/1.1",
                "GET http://a.example:8080 HTTP/1.1",
                "GET urn:example:a%41 HTTP/1.1",
            )) {
                val response = exchange("$line\r\nHost: a.example\r\nConnection: close\r\n\r\n")
                assertTrue(response.startsWith("HTTP/1.1 200 "), "$line: $response")
                assertTrue(response.endsWith(line), "$line: $response")
            }
        }

    /**
     * A request-target that breaks its grammar is an invalid request line: the server SHOULD respond with 400 (RFC 9112
     * section 3), and CONNECT to an empty or invalid port MUST be rejected (RFC 9110 section 9.3.6). Before, Ktor's parser
     * passed any run of non-whitespace to routing.
     */
    @Test fun negative_invalidRequestTargetGets400() =
        runTest {
            for (line in listOf(
                "POST /a|b HTTP/1.1",
                "POST /a%zz HTTP/1.1",
                "POST /a#b HTTP/1.1",
                "PUT /\u00e9 HTTP/1.1",
                "DELETE /a[1] HTTP/1.1",
                "GET * HTTP/1.1",
                "CONNECT /x HTTP/1.1",
                "CONNECT a.example HTTP/1.1",
                "CONNECT a.example: HTTP/1.1",
                "CONNECT a.example:0 HTTP/1.1",
                "CONNECT a.example:65536 HTTP/1.1",
                "CONNECT http://a.example/ HTTP/1.1",
                "GET http://a.example/a|b HTTP/1.1",
                "GET http://a.example/#f HTTP/1.1",
                "GET 1http://a.example/ HTTP/1.1",
                "GET a HTTP/1.1",
            )) {
                val response = exchange("$line\r\nHost: a.example\r\n\r\nGET /next HTTP/1.1\r\nHost: s\r\n\r\n")
                assertTrue(response.startsWith("HTTP/1.1 400 "), "${show(line)}: $response")
                assertEquals(1, Regex("HTTP/1.1 ").findAll(response).count(), "${show(line)}: $response")
            }
        }

    /**
     * For GET and HEAD the other answer RFC 9112 section 3.2 names for an invalid request line: 301 with the request-target
     * properly encoded. Browsers send `|`, `{`, `}`, `^` and `[` unencoded in a path or query (the WHATWG URL standard
     * leaves them), so a 400 would turn away real pages; the redirect brings them back with the target encoded.
     */
    @Test fun invalidOriginFormOfGetIsRedirectedProperlyEncoded() =
        runTest {
            for ((line, location) in listOf(
                "GET /a|b?c={d}^ HTTP/1.1" to "/a%7Cb?c=%7Bd%7D%5E",
                "HEAD /\u00e9t\u00e9 HTTP/1.1" to "/%C3%A9t%C3%A9",
                "GET /%zz%4 HTTP/1.1" to "/%25zz%254",
                "GET /a[1]?x=[2] HTTP/1.1" to "/a%5B1%5D?x=%5B2%5D",
            )) {
                val response = exchange("$line\r\nHost: a.example\r\n\r\nGET /next HTTP/1.1\r\nHost: s\r\n\r\n")
                assertTrue(response.startsWith("HTTP/1.1 301 Moved Permanently\r\n"), "${show(line)}: $response")
                assertTrue(response.contains("\r\nLocation: $location\r\n"), "${show(line)}: $response")
                assertEquals(1, Regex("HTTP/1.1 ").findAll(response).count(), "${show(line)}: $response")
            }
        }

    /**
     * A 301 for an origin-form target that starts with `//` would carry a Location that is a network-path reference
     * (RFC 3986 section 4.2): `GET //evil.example/^` redirected to `//evil.example/%5E` sends a browser to
     * `http://evil.example/` (an open redirect). Every target whose Location could name another authority, once its
     * percent-encoded `/`, `\` and `.` are decoded and its dot segments removed (section 5.2.4), as a lenient client or a
     * proxy in front may do, gets 400, and so does a target with a raw `#`: `/a%23b` names another resource than the
     * path `/a` with fragment `b` the client most likely meant (section 2.2), so no encoding of it is proper.
     */
    @Test fun negative_redirectNeverLeavesTheServer() =
        runTest {
            for (line in listOf(
                "GET //evil.example/^ HTTP/1.1",
                "HEAD //evil.example/^ HTTP/1.1",
                "GET ///evil.example/^ HTTP/1.1",
                "GET //a|b HTTP/1.1",
                "GET /\\evil.example/^ HTTP/1.1",
                "GET /\\/evil.example/^ HTTP/1.1",
                "GET //\\evil.example/^ HTTP/1.1",
                "GET /%2F%2Fevil.example/^ HTTP/1.1",
                "GET /%2f/evil.example/^ HTTP/1.1",
                "GET /%5Cevil.example/^ HTTP/1.1",
                "GET /%5c%5cevil.example/^ HTTP/1.1",
                "GET /.//evil.example/^ HTTP/1.1",
                "GET /%2E//evil.example/^ HTTP/1.1",
                "GET /a/..//evil.example/^ HTTP/1.1",
                "GET /a/%2E%2E//evil.example/^ HTTP/1.1",
                "GET /a/../../%2Fevil.example/^ HTTP/1.1",
                "GET /a\\..\\..\\/evil.example/^ HTTP/1.1",
                "GET //evil.example/\u00e9 HTTP/1.1",
                "GET //evil.example/%zz HTTP/1.1",
                "GET /a#b HTTP/1.1",
                "GET /a^#b HTTP/1.1",
                "HEAD /# HTTP/1.1",
                "GET /a?b#c HTTP/1.1",
            )) {
                val response = exchange("$line\r\nHost: a.example\r\n\r\nGET /next HTTP/1.1\r\nHost: s\r\n\r\n")
                assertTrue(response.startsWith("HTTP/1.1 400 "), "${show(line)}: $response")
                assertTrue(!response.contains("Location"), "${show(line)}: $response")
                assertEquals(1, Regex("HTTP/1.1 ").findAll(response).count(), "${show(line)}: $response")
            }
        }

    /** A valid target that starts with `//` is a path (`absolute-path` allows an empty first segment), served as before. */
    @Test fun validTargetThatStartsWithTwoSlashesIsServed() =
        runTest {
            val response = exchange("GET //evil.example/x HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n")
            assertTrue(response.startsWith("HTTP/1.1 200 "), response)
            assertTrue(response.endsWith("GET //evil.example/x HTTP/1.1"), response)
        }

    private fun show(s: String) =
        s
            .map {
                if (it.code < 0x20 ||
                    it.code >= 0x7f
                ) {
                    "\\u" + it.code.toString(16).padStart(4, '0')
                } else {
                    "$it"
                }
            }.joinToString("")
}
