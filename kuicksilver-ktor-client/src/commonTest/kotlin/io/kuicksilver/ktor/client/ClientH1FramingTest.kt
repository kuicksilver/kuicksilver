// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.setBody
import io.ktor.client.request.url
import io.ktor.client.statement.bodyAsText
import io.ktor.http.Headers
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.content.OutgoingContent
import io.ktor.http.headersOf
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.readLine
import io.ktor.utils.io.readRemaining
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.client.h1.writeBody
import io.kuicksilver.ktor.client.h1.writeHeaders
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.io.readString
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** How the client finds the end of an HTTP/1.1 response and whether the connection may carry another one (RFC 9112 section 6.3). */
class ClientH1FramingTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * Two different Content-Length values: the framing is invalid, the response is discarded and the connection closed
     * (RFC 9112 section 6.3 item 5). Before, the first value framed the body and the rest of the bytes became the
     * response to the next request on that connection (response splitting).
     */
    @Test fun negative_conflictingContentLengthFailsAndClosesConnection() =
        clientTest {
            val served = ArrayList<Int>()
            rawServerPerConnection({ index, input, output ->
                readHead(input)
                served += index
                if (index == 0) {
                    output.writeStringUtf8(
                        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 42\r\n\r\nhello" +
                            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nevil",
                    )
                } else {
                    output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ngood")
                }
                readHead(input)
            }) { port ->
                testClient().use { c ->
                    val first = runCatching { c.get("http://127.0.0.1:$port/1").bodyAsText() }
                    assertTrue(first.isFailure, "a response with conflicting Content-Length was accepted: ${first.getOrNull()}")
                    assertEquals("good", c.get("http://127.0.0.1:$port/2").bodyAsText())
                }
            }
            assertEquals(listOf(0, 1), served, "the second request went out on the first connection")
        }

    /** Content-Length is 1*DIGIT (RFC 9110 section 8.6): a sign is not a length. */
    @Test fun negative_signedContentLengthRejected() =
        clientTest {
            rawServerPerConnection({ _, input, output ->
                readHead(input)
                output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\nhello")
                readHead(input)
            }) { port ->
                testClient().use { c ->
                    val r = runCatching { c.get("http://127.0.0.1:$port/").bodyAsText() }
                    assertTrue(r.isFailure, "Content-Length: +5 was accepted: ${r.getOrNull()}")
                }
            }
        }

    /** Identical values (repeated, or a list) are one length (RFC 9110 section 8.6). */
    @Test fun identicalContentLengthsAreOneLength() =
        clientTest {
            rawServerPerConnection({ _, input, output ->
                readHead(input)
                output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5, 5\r\n\r\nhello")
                readHead(input)
            }) { port ->
                testClient().use { c -> assertEquals("hello", c.get("http://127.0.0.1:$port/").bodyAsText()) }
            }
        }

    /**
     * Content-Length together with Transfer-Encoding: the chunked coding frames the body, and the connection is not reused
     * (RFC 9112 section 6.3 item 3: a possible smuggling or splitting attempt, to be handled as an error).
     */
    @Test fun negative_contentLengthWithTransferEncodingIsNotReused() =
        clientTest {
            val served = ArrayList<Int>()
            rawServerPerConnection({ index, input, output ->
                while (true) {
                    if (readHead(input).isEmpty()) break
                    served += index
                    output.writeStringUtf8(
                        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
                    )
                }
            }) { port ->
                testClient().use { c ->
                    assertEquals("hello", c.get("http://127.0.0.1:$port/1").bodyAsText())
                    assertEquals("hello", c.get("http://127.0.0.1:$port/2").bodyAsText())
                }
            }
            assertEquals(listOf(0, 1), served, "the connection was reused after a Content-Length + Transfer-Encoding response")
        }

    /**
     * No Content-Length, no Transfer-Encoding: the body ends when the server closes the connection (RFC 9112 section 6.3
     * item 8). Before, the client failed with "Failed to parse request body".
     */
    @Test fun closeDelimitedResponseIsReadToTheEnd() =
        clientTest {
            rawServerPerConnection({ _, input, output ->
                readHead(input)
                output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nlegacy body")
            }) { port ->
                testClient().use { c -> assertEquals("legacy body", c.get("http://127.0.0.1:$port/").bodyAsText()) }
            }
        }

    /**
     * A trailer section after the last chunk (RFC 9112 section 7.1.2) ends the body like an empty one, and the connection
     * stays reusable. Before, the body failed with "Expected CR" and the connection was closed.
     */
    @Test fun chunkedTrailersAreAccepted() =
        clientTest {
            val served = ArrayList<Int>()
            rawServerPerConnection({ index, input, output ->
                readHead(input)
                served += index
                output.writeStringUtf8(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: Server-Timing\r\n\r\n" +
                        "5\r\nhello\r\n0\r\nServer-Timing: db;dur=53\r\nX-Checksum: 1\r\n\r\n",
                )
                readHead(input)
                served += index
                output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                readHead(input)
            }) { port ->
                testClient().use { c ->
                    assertEquals("hello", c.get("http://127.0.0.1:$port/1").bodyAsText())
                    assertEquals("ok", c.get("http://127.0.0.1:$port/2").bodyAsText())
                }
            }
            assertEquals(listOf(0, 0), served)
        }

    /** A trailer section is bounded: one larger than 16 KiB fails the body. */
    @Test fun negative_hugeTrailerSectionFails() =
        clientTest {
            rawServerPerConnection({ _, input, output ->
                readHead(input)
                output.writeStringUtf8("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n")
                repeat(100) { output.writeStringUtf8("X-Pad-$it: ${"a".repeat(200)}\r\n") }
                output.writeStringUtf8("\r\n")
                readHead(input)
            }) { port ->
                testClient().use { c ->
                    val r = runCatching { c.get("http://127.0.0.1:$port/").bodyAsText() }
                    assertTrue(r.isFailure, "a 20 KB trailer section was accepted")
                }
            }
        }

    /** A chunked body cut before its last chunk is incomplete (RFC 9112 section 8), not a short body. */
    @Test fun negative_chunkedBodyCutBeforeLastChunkFails() =
        clientTest {
            rawServerPerConnection({ _, input, output ->
                readHead(input)
                output.writeStringUtf8("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n")
            }) { port ->
                testClient().use { c ->
                    val r = runCatching { c.get("http://127.0.0.1:$port/").bodyAsText() }
                    assertTrue(r.isFailure, "a truncated chunked body was delivered as complete: ${r.getOrNull()}")
                }
            }
        }

    /** A body shorter than its Content-Length is incomplete (RFC 9112 section 8), not a short body. */
    @Test fun negative_contentLengthBodyCutShortFails() =
        clientTest {
            rawServerPerConnection({ _, input, output ->
                readHead(input)
                output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
            }) { port ->
                testClient().use { c ->
                    val r = runCatching { c.get("http://127.0.0.1:$port/").bodyAsText() }
                    assertTrue(r.isFailure, "a truncated body was delivered as complete: ${r.getOrNull()}")
                }
            }
        }

    /**
     * A request that says `Connection: close` is the last one on its connection (RFC 9112 section 9.6), even when the
     * server does not echo the option.
     */
    @Test fun requestConnectionCloseEndsTheConnection() =
        clientTest {
            val served = ArrayList<Int>()
            rawServerPerConnection({ index, input, output ->
                while (true) {
                    if (readHead(input).isEmpty()) break
                    served += index
                    output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                }
            }) { port ->
                testClient().use { c ->
                    assertEquals("ok", c.get("http://127.0.0.1:$port/1") { header(HttpHeaders.Connection, "close") }.bodyAsText())
                    assertEquals("ok", c.get("http://127.0.0.1:$port/2").bodyAsText())
                }
            }
            assertEquals(listOf(0, 1), served, "a request went out on a connection after one that said Connection: close")
        }

    /**
     * Whitespace other than SP and HTAB around a framing field value (VT, FF, U+00A0 sent as `C2 A0`) makes it invalid:
     * OWS is `*( SP / HTAB )` (RFC 9110 section 5.6.3), Content-Length is `1*DIGIT` (RFC 9110 section 8.6), a transfer
     * coding is a token (RFC 9112 section 6.1). The response fails and its connection is not reused (RFC 9112 section 6.3
     * item 5; an invalid Transfer-Encoding leaves the framing as unknown). Before, Kotlin's `trim()` stripped them, so the
     * client framed the body by a value that a proxy in front of it may have ignored, and the bytes behind became the
     * response to the next request (response splitting).
     */
    @Test fun negative_nonOwsWhitespaceInFramingFieldsFails() =
        clientTest {
            val cases =
                listOf(
                    "Content-Length: 5\u000b\r\n\r\nhello",
                    "Content-Length: 5\u000c\r\n\r\nhello",
                    "Content-Length: 5 \r\n\r\nhello",
                    "Transfer-Encoding: chunked \r\n\r\n5\r\nhello\r\n0\r\n\r\n",
                    "Transfer-Encoding: chunked\u000b\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
                    "Transfer-Encoding: chunked\u000c\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
                    "Transfer-Encoding: chun ked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
                    "Transfer-Encoding: chunked, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
                )
            for (case in cases) {
                val shown =
                    case
                        .substringBefore("\r\n\r\n")
                        .map {
                            if (it.code < 0x20 ||
                                it.code > 0x7e
                            ) {
                                "\\u" + it.code.toString(16).padStart(4, '0')
                            } else {
                                "$it"
                            }
                        }.joinToString("")
                val served = ArrayList<Int>()
                rawServerPerConnection({ index, input, output ->
                    while (true) {
                        if (readHead(input).isEmpty()) break
                        served += index
                        output.writeStringUtf8(
                            if (index == 0) "HTTP/1.1 200 OK\r\n$case" else "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ngood",
                        )
                    }
                }) { port ->
                    testClient().use { c ->
                        val first = runCatching { c.get("http://127.0.0.1:$port/1").bodyAsText() }
                        assertTrue(first.isFailure, "$shown was accepted: ${first.getOrNull()}")
                        assertEquals("good", c.get("http://127.0.0.1:$port/2").bodyAsText(), shown)
                    }
                }
                assertEquals(listOf(0, 1), served, "$shown: the second request went out on the first connection")
            }
        }

    /** SP and HTAB are OWS (RFC 9110 section 5.6.3) and coding names are case-insensitive (RFC 9112 section 7). */
    @Test fun owsAndCaseInFramingFieldsAreAccepted() =
        clientTest {
            for (case in listOf(
                "Content-Length: \t5 \t\r\n\r\nhello",
                "Transfer-Encoding: \t, ChUnKeD \t\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
            )) {
                val served = ArrayList<Int>()
                rawServerPerConnection({ index, input, output ->
                    while (true) {
                        if (readHead(input).isEmpty()) break
                        served += index
                        output.writeStringUtf8("HTTP/1.1 200 OK\r\n$case")
                    }
                }) { port ->
                    testClient().use { c ->
                        assertEquals("hello", c.get("http://127.0.0.1:$port/1").bodyAsText(), case)
                        assertEquals("hello", c.get("http://127.0.0.1:$port/2").bodyAsText(), case)
                    }
                }
                assertEquals(listOf(0, 0), served, "$case: the connection was not reused")
            }
        }

    /**
     * An HTTP/1.0 response with Transfer-Encoding has faulty framing, even with a Content-Length (RFC 9112 section 6.1
     * MUST): neither field frames it, so the body is read until the server closes (section 6.3 item 8), as it was sent,
     * and the connection is not reused. Before, the chunked coding of an HTTP/1.0 response was decoded.
     */
    @Test fun http10ResponseWithTransferEncodingIsCloseDelimited() =
        clientTest {
            val served = ArrayList<Int>()
            rawServerPerConnection({ index, input, output ->
                readHead(input)
                served += index
                output.writeStringUtf8("HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
            }) { port ->
                testClient().use { c ->
                    assertEquals("5\r\nhello\r\n0\r\n\r\n", c.get("http://127.0.0.1:$port/1").bodyAsText())
                    assertEquals("5\r\nhello\r\n0\r\n\r\n", c.get("http://127.0.0.1:$port/2").bodyAsText())
                }
            }
            assertEquals(listOf(0, 1), served)
        }

    /**
     * A request body with a transfer coding of its own (`Transfer-Encoding: gzip` in the content's headers) goes out with
     * `chunked` as its final coding (RFC 9112 section 6.1: a sender that applies a coding other than chunked MUST apply
     * chunked last) and without Content-Length, even when the content has a length (section 6.2: MUST NOT send both).
     * Before, the head said `Transfer-Encoding: gzip` over a chunk-encoded body, or `Content-Length: 5` and
     * `Transfer-Encoding: gzip` together.
     */
    @Test fun contentTransferEncodingEndsWithChunked() =
        runTest {
            for ((coding, length) in listOf("gzip" to null, "gzip" to 5L, "chunked" to 5L, "gzip, chunked" to null)) {
                val content =
                    object : OutgoingContent.ByteArrayContent() {
                        override val headers: Headers = headersOf(HttpHeaders.TransferEncoding, coding)
                        override val contentLength: Long? = length

                        override fun bytes() = "hello".encodeToByteArray()
                    }
                val request =
                    HttpRequestBuilder()
                        .apply {
                            url("http://127.0.0.1:8080/")
                            method = HttpMethod.Post
                            setBody(content)
                        }.build()
                val wire = ByteChannel()
                writeHeaders(request, wire, overProxy = false)
                writeBody(request, wire, coroutineContext)
                wire.flushAndClose()
                val sent = wire.readRemaining().readString()
                val head = sent.substringBefore("\r\n\r\n").lines().drop(1)
                val te = head.filter { it.startsWith("Transfer-Encoding:", ignoreCase = true) }
                val expected = if (coding.endsWith("chunked")) coding else "$coding, chunked"
                assertEquals(listOf("Transfer-Encoding: $expected"), te, "$coding/$length: $head")
                assertFalse(head.any { it.startsWith("Content-Length:", ignoreCase = true) }, "$coding/$length: $head")
                assertEquals("5\r\nhello\r\n0\r\n\r\n", sent.substringAfter("\r\n\r\n"), "$coding/$length")
            }
        }

    /** Reads a request head; returns its request line ("" at end of stream). */
    private suspend fun readHead(input: ByteReadChannel): String {
        val line = input.readLine(LineEnding.Lenient) ?: return ""
        while (input.readLine(LineEnding.Lenient)?.isNotEmpty() == true) continue
        return line
    }

    /** A plain TCP listener that runs [handler] once per accepted connection, with the connection's index, then closes it. */
    private suspend fun rawServerPerConnection(
        handler: suspend (index: Int, input: ByteReadChannel, output: ByteWriteChannel) -> Unit,
        block: suspend (Int) -> Unit,
    ) {
        val selector = SelectorManager(Dispatchers.Default)
        val listener = aSocket(selector).tcp().bind("127.0.0.1", 0)
        try {
            coroutineScope {
                val server =
                    launch {
                        var index = 0
                        while (true) {
                            val s = listener.accept()
                            val i = index++
                            launch {
                                // the client may close first (a response it refused): the server side just ends
                                s.use { runCatching { handler(i, it.openReadChannel(), it.openWriteChannel(autoFlush = true)) } }
                            }
                        }
                    }
                block((listener.localAddress as InetSocketAddress).port)
                server.cancel()
            }
        } finally {
            listener.close()
            selector.close()
        }
    }
}
