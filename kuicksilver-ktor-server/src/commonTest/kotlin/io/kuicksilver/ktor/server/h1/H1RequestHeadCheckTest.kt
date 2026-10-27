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
                val body = "${request.method.value} ${request.uri} ${request.version}" + (request.headers["X-A"]?.let { " [$it]" } ?: "")
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

    /** method = token (RFC 9112 section 3.1): anything else is an invalid request line, 400 (section 3). */
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
     * OWS is `*( SP / HTAB )` (RFC 9110 section 5.6.3). Ktor's parser skips any Unicode whitespace before a value, so
     * `X-A: <U+00A0>a` reached the application as `a`, and `Content-Length: <U+00A0>5` framed a 5-byte body while a front
     * proxy that finds the value invalid frames none (CL.0 smuggling). 400 and close (RFC 9112 section 6.3 item 5 for
     * Content-Length).
     */
    @Test fun negative_unicodeSpaceBeforeAFieldValueIsRejected() =
        runTest {
            val next = "GET /next HTTP/1.1\r\nHost: s\r\n\r\n"
            for (field in listOf(
                "X-A: \u00a0a\r\n\r\n",
                "X-A:\u2000a\r\n\r\n",
                "X-A: \t\u3000a\r\n\r\n",
                "Content-Length: \u00a05\r\n\r\nhello",
                "Transfer-Encoding: \u2009chunked\r\n\r\n0\r\n\r\n",
            )) {
                val response = exchange("POST / HTTP/1.1\r\nHost: s\r\n$field$next")
                assertTrue(response.startsWith("HTTP/1.1 400 "), "${show(field)}: $response")
                assertEquals(1, Regex("HTTP/1.1 ").findAll(response).count(), "${show(field)}: $response")
            }
        }

    /** A Unicode space inside or at the end of a value is obs-text, field content (RFC 9110 section 5.5): passed on. */
    @Test fun unicodeSpaceInsideAFieldValueIsAccepted() =
        runTest {
            val response = exchange("GET / HTTP/1.1\r\nHost: s\r\nX-A: a\u00a0b\u00a0\r\nConnection: close\r\n\r\n")
            assertTrue(response.endsWith("[a\u00a0b\u00a0]"), response)
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
