// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.header
import io.ktor.client.request.setBody
import io.ktor.client.request.url
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.cio.ParserException
import io.ktor.http.content.TextContent
import io.ktor.util.date.GMTDate
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.availableForRead
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.kuicksilver.ktor.client.h1.AfterResponse
import io.kuicksilver.ktor.client.h1.HeadLimitedInput
import io.kuicksilver.ktor.client.h1.ResponseFraming
import io.kuicksilver.ktor.client.h1.readResponse
import io.kuicksilver.ktor.client.h1.readResponseHeadBytes
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import kotlinx.io.Buffer
import kotlinx.io.IOException
import kotlinx.io.readByteArray
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.TestInfo
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Fuzz target `h1Response`: input = [mode byte][what an HTTP/1.1 server sends on one connection]. Mode bits 0-1 choose the
 * request the responses answer (GET, HEAD, a POST with `Expect: 100-continue` whose body waits for a 100, GET again);
 * bits 2-7, when not 0, cut the server's bytes into pieces of that many bytes, each handed over on its own (a line or a
 * chunk split anywhere), else they come at once.
 *
 * The client engine's own reading of a response runs on them ([readResponse]: the head with the interim 1xx heads before
 * it, their byte bound, Ktor's parser, the fields as sent, the framing, the refusals of a faulty or too large framing, and
 * the body reader), with a 4 KiB head limit; while it says the connection can be reused ([AfterResponse.Reuse]) the next
 * response is read from the same bytes, as a kept-alive connection does. Only the engine's own failures of a server's
 * bytes may come out (a [ParserException] or an [IOException], with no other exception as a cause: [engineFailure]).
 * Each body is exactly what its framing says, compared with the bytes it took: a Content-Length body is those N bytes, a
 * chunked one what a small reference decoder ([dechunk]) makes of them, a body read until the close is the rest of the
 * input, and the answer to HEAD, a 204 or a 304 takes nothing; the engine never takes more than there is. Then the heads alone, from the whole input: each takes at most the
 * limit from the connection, and what it hands on to Ktor's parser is what that parser may rely on ([checkHead]).
 */
class H1ResponseFuzzTest {
    @BeforeEach fun nameTheCase(case: TestInfo) = fuzzCase(case)

    @OptIn(InternalAPI::class)
    @FuzzTest(maxDuration = "60s")
    fun h1Response(data: ByteArray) {
        if (data.isEmpty()) return
        val mode = data[0].toInt() and 0xFF
        val wire = data.copyOfRange(1, data.size)
        val kind = mode and 3
        val piece = mode ushr 2
        val request = request(kind)
        runBlocking {
            val source = ByteChannel()
            var written = 0
            val writer =
                launch {
                    var p = 0
                    while (p < wire.size) {
                        val n = if (piece == 0) wire.size else minOf(piece, wire.size - p)
                        source.writeFully(wire, p, p + n)
                        source.flush()
                        written += n
                        p += n
                        yield()
                    }
                    source.flushAndClose()
                }
            val input = HeadLimitedInput(source, MAX_HEAD)
            // the bytes the engine has taken from the connection: those written, less those still in either buffer
            val taken = { written - source.availableForRead - (input.readBuffer as Buffer).size.toInt() }
            val callJob = Job()
            try {
                while (true) {
                    val after = CompletableDeferred<AfterResponse>()
                    val response =
                        readResponse(
                            GMTDate(),
                            request,
                            input,
                            ByteChannel(),
                            coroutineContext + callJob,
                            head = input,
                            continueBody = if (kind == 2) ({ }) else null,
                        ) { after.complete(it) }
                    val headEnd = taken()
                    val body = (response.body as ByteReadChannel).readBuffer().readByteArray()
                    val outcome = after.await()
                    val end = taken()
                    assertTrue(end <= wire.size, "the engine took $end of ${wire.size} bytes")
                    val took = wire.copyOfRange(headEnd, end)
                    val status = response.statusCode.value
                    val te = response.headers.getAll(HttpHeaders.TransferEncoding)
                    val cl = response.headers[HttpHeaders.ContentLength]
                    // whether chunked is the final coding: the engine's own reading of the field (empty list elements and
                    // quoted parameters included), the one place that decides it
                    val framing =
                        ResponseFraming.of(
                            response.headers.entries().associate { it.key to it.value },
                            http10 = response.version == HttpProtocolVersion.HTTP_1_0,
                        )
                    when {
                        request.method == HttpMethod.Head || status == 204 || status == 304 -> {
                            assertEquals(0, body.size + took.size, "a body for HEAD, a 204 or a 304 (status $status)")
                        }

                        // chunked when it is the final coding (RFC 9112 section 6.3 item 4); any other final coding is
                        // read until the close, as is every coding in HTTP/1.0
                        te != null && framing.delimited -> {
                            val reference = dechunk(took)
                            assertTrue(reference != null && reference.contentEquals(body), "a chunked body that is not what its chunks say")
                        }

                        cl != null -> {
                            val n = cl.substringBefore(',').trim().toLong()
                            assertTrue(
                                n == body.size.toLong() && took.contentEquals(body),
                                "a body of ${body.size} bytes for Content-Length $cl",
                            )
                        }

                        else -> {
                            assertTrue(end == wire.size && took.contentEquals(body), "a body read until the close that is not the rest")
                        }
                    }
                    if (outcome != AfterResponse.Reuse) break
                }
            } catch (e: ParserException) {
                engineFailure(e)
            } catch (e: IOException) {
                engineFailure(e)
            } finally {
                callJob.cancel()
                writer.cancel()
            }
        }
        runBlocking {
            val input = ByteReadChannel(wire)
            try {
                while (true) {
                    val before = input.availableForRead
                    val head = readResponseHeadBytes(input, MAX_HEAD) ?: break
                    // the limit is on what the head takes from the connection: the bytes handed on may be longer (a bare
                    // LF becomes CRLF, an invalid status code becomes 500 followed by the code sent)
                    val took = before - input.availableForRead
                    assertTrue(took <= MAX_HEAD, "a head that took $took bytes")
                    checkHead(head.bytes)
                }
            } catch (_: ParserException) {
            } catch (_: IOException) {
            }
        }
    }

    /**
     * [e] came out of the engine for a server's bytes: it and every cause under it must be a parse error or an I/O error.
     * A body reader that fails otherwise (an exception of the engine's own) closes the body's channel with it, and its
     * reader sees an I/O error that carries it as a cause.
     */
    private fun engineFailure(e: Throwable) {
        val odd = generateSequence(e) { it.cause }.firstOrNull { it !is IOException && it !is ParserException }
        if (odd != null) throw AssertionError("an engine failure that is not a parse or I/O error: $odd", e)
    }

    private fun request(kind: Int): HttpRequestData =
        HttpRequestBuilder()
            .apply {
                url("http://example.com/")
                method =
                    when (kind) {
                        1 -> HttpMethod.Head
                        2 -> HttpMethod.Post
                        else -> HttpMethod.Get
                    }
                if (kind == 2) {
                    header(HttpHeaders.Expect, "100-continue")
                    setBody(TextContent("body", ContentType.Text.Plain))
                }
            }.build()

    /**
     * A chunked body (RFC 9112 section 7.1) decoded from exactly [b]: the chunks' data, or null when [b] is not one whole
     * chunked body (sizes in hex with any extension, CRLF line ends, the last chunk and a trailer section to its empty line,
     * whose lines may end with a bare LF).
     */
    private fun dechunk(b: ByteArray): ByteArray? {
        var p = 0
        val out = java.io.ByteArrayOutputStream()

        fun line(): String? {
            var i = p
            while (i + 1 < b.size && !(b[i] == CR && b[i + 1] == LF)) i++
            if (i + 1 >= b.size) return null
            return String(b, p, i - p, Charsets.ISO_8859_1).also { p = i + 2 }
        }
        while (true) {
            val sizeLine = line() ?: return null
            val size = sizeLine.takeWhile { it in HEX }.toLongOrNull(16) ?: return null
            if (size == 0L) break
            if (size > b.size - p - 2L) return null
            out.write(b, p, size.toInt())
            p += size.toInt()
            if (b[p] != CR || b[p + 1] != LF) return null
            p += 2
        }
        // the trailer section to its empty line; its lines may end with a bare LF (RFC 9112 section 2.2), never a bare CR
        var length = 0
        while (true) {
            if (p >= b.size) return null
            val c = b[p++]
            when {
                c == CR -> if (p >= b.size || b[p] != LF) return null
                c == LF -> if (length == 0) break else length = 0
                else -> length++
            }
        }
        return if (p == b.size) out.toByteArray() else null
    }

    /**
     * What Ktor's parser may rely on in a head handed on: line ends are CRLF only (every CR before an LF, every LF after a
     * CR), the head ends with an empty line, no field line continues the one before (obs-fold is replaced), no control
     * character but HTAB, and the status line is `HTTP/1.0` or `HTTP/1.1`, SP and a code in 100..599.
     */
    private fun checkHead(b: ByteArray) {
        val shown = {
            b
                .decodeToString()
                .take(80)
                .replace("\r", "\\r")
                .replace("\n", "\\n")
        }
        for (i in b.indices) {
            val c = b[i].toInt() and 0xFF
            when (c) {
                0x0D -> assertTrue(i + 1 < b.size && b[i + 1] == LF, "a CR without LF in ${shown()}")
                0x0A -> assertTrue(i > 0 && b[i - 1] == CR, "an LF without CR in ${shown()}")
                else -> assertTrue((c >= 0x20 && c != 0x7F) || c == 0x09, "control character $c in ${shown()}")
            }
            if (c == 0x0A && i + 1 < b.size) assertTrue(b[i + 1] != SP && b[i + 1] != HTAB, "an obs-fold line in ${shown()}")
        }
        assertTrue(
            b.size >= 4 && b.copyOfRange(b.size - 4, b.size).contentEquals(END),
            "a head that does not end with CRLF CRLF: ${shown()}",
        )
        assertTrue(STATUS_LINE.containsMatchIn(b.decodeToString(0, minOf(b.size, 14))), "status line ${shown()}")
    }

    private companion object {
        const val MAX_HEAD = 4_096
        const val CR: Byte = 0x0D
        const val LF: Byte = 0x0A
        const val SP: Byte = 0x20
        const val HTAB: Byte = 0x09
        const val HEX = "0123456789abcdefABCDEF"
        val END = byteArrayOf(CR, LF, CR, LF)
        val STATUS_LINE = Regex("^HTTP/1\\.[01] [1-5][0-9][0-9][ \r]")
    }
}
