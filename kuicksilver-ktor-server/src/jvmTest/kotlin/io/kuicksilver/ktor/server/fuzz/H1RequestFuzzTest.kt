// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.cio.ParserException
import io.ktor.http.cio.parseRequest
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.charsets.TooLongLineException
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.server.h1.H1Connection
import io.kuicksilver.ktor.server.h1.HeadLimitedInput
import io.kuicksilver.ktor.server.h1.MalformedChunkedBodyException
import io.kuicksilver.ktor.server.h1.MalformedRequestBody
import io.kuicksilver.ktor.server.h1.RequestFraming
import io.kuicksilver.ktor.server.h1.RequestHeadRefused
import io.kuicksilver.ktor.server.h1.checkRequestHead
import io.kuicksilver.ktor.server.h1.requestFields
import io.kuicksilver.ktor.server.h1.skipEmptyLines
import io.kuicksilver.ktor.server.h1.startH1Pipeline
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import kotlinx.io.Buffer
import kotlinx.io.EOFException
import kotlinx.io.IOException
import kotlinx.io.readByteArray
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.TestInfo
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Fuzz target `h1Request`: input = [mode byte][what an HTTP/1.1 client sends on one connection], then the end of its side.
 * Mode bits 0-2 choose the handler (read the body, then answer with Content-Length; answer without reading the body;
 * fail; read the body, then answer chunked; answer, then read the body); bits 3-7, when not 0, cut the client's bytes into
 * pieces of that many bytes, each handed over on its own, else they come at once.
 *
 * First the server engine's pipeline ([startH1Pipeline]: the request head checks, Ktor's parser, the framing of request
 * bodies, chunked included, pipelining, `Expect: 100-continue`, unread bodies, failed handlers) runs on it with a 4 KiB
 * head limit, in virtual time. Nothing in the pipeline waits for time here, so it must have ended, its output closed,
 * before virtual time moves at all: a connection that would only end at a deadline is a hang. Every request the handler
 * gets has a method that is a token and a target without whitespace or control characters, and what the server sends is
 * a sequence of HTTP/1.1 responses ([checkResponses]): no more final responses than requests, each body as its framing
 * says (none to HEAD), and nothing after `Connection: close`. (`100 Continue` is written by the call layer above the
 * pipeline, which this target does not run.)
 *
 * The pipeline answers any failure of its head checks, of a body's decoding and of the handler with a 400 or a 500 (or
 * ends the connection), which hides a bug in them. So the same input then goes through the same steps on their own, one
 * request after another ([sequentialPass]), where only what the pipeline expects of a client's bytes may come out.
 */
class H1RequestFuzzTest {
    @BeforeEach fun nameTheCase(case: TestInfo) = fuzzCase(case)

    @OptIn(InternalAPI::class)
    @FuzzTest(maxDuration = "60s")
    fun h1Request(data: ByteArray) =
        runTest {
            if (data.isEmpty()) return@runTest
            val handlerMode = data[0].toInt() and 7
            val piece = (data[0].toInt() and 0xFF) ushr 3
            val wire = data.copyOfRange(1, data.size)
            val toServer = ByteChannel()
            val fromServer = ByteChannel()
            val wrong = ArrayList<String>() // asserted after the run: the pipeline answers a failing handler with a 500
            val job =
                backgroundScope.startH1Pipeline(
                    H1Connection(toServer, fromServer, null, null),
                    45.seconds,
                    30.seconds,
                    maxHeadBytes = MAX_HEAD,
                ) { request ->
                    val method = request.method.value
                    if (method.isEmpty() || !method.all { it in TCHAR }) wrong += "method ${method.visible()}"
                    val target = request.uri.toString()
                    if (target.any { it.code <= 0x20 || it.code == 0x7F }) wrong += "target ${target.visible()}"
                    request.release()
                    val content = if (method == "HEAD") "" else "ok"
                    when (handlerMode) {
                        1 -> {
                            output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n$content")
                        }

                        2 -> {
                            throw HandlerFailure()
                        }

                        3 -> {
                            input.readBuffer()
                            val chunks = if (method == "HEAD") "" else "2\r\nok\r\n0\r\n\r\n"
                            output.writeStringUtf8("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n$chunks")
                        }

                        4 -> {
                            output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n$content")
                            output.flush()
                            input.readBuffer()
                        }

                        else -> {
                            input.readBuffer() // the body, to its end
                            output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n$content")
                        }
                    }
                    output.flush()
                }
            // what the client receives, and how its connection ended: cleanly, or failed (a reset: a response that failed after
            // its first byte, so the client does not take the part it got for a whole one)
            val received = Buffer()
            var reset: Throwable? = null
            val reader =
                backgroundScope.launch {
                    try {
                        while (fromServer.awaitContent()) fromServer.readBuffer.transferTo(received)
                    } catch (e: Throwable) {
                        reset = e
                    }
                }
            backgroundScope.launch {
                var p = 0
                while (p < wire.size) {
                    val n = if (piece == 0) wire.size else minOf(piece, wire.size - p)
                    toServer.writeFully(wire, p, p + n)
                    toServer.flush()
                    p += n
                    yield()
                }
                toServer.flushAndClose()
            }
            testScheduler.runCurrent() // virtual time stays at 0
            assertTrue(job.isCompleted, "the connection is still open after the input ended (it would end only at a deadline)")
            assertTrue(wrong.isEmpty(), "the handler got $wrong")
            assertTrue(reader.isCompleted, "the output was not closed after the connection ended")
            val heads = sequentialPass(wire)
            reset?.let { cause ->
                // a failed response: the handler's, or a malformed request body's that the handler read
                val known =
                    generateSequence(cause) { it.cause }.any {
                        it is HandlerFailure || it is MalformedRequestBody ||
                            it is IOException
                    }
                if (!known) throw AssertionError("the connection was reset by an unexpected failure: $cause", cause)
            }
            checkResponses(received.readByteArray(), heads, complete = reset == null)
        }

    /** A request head as [sequentialPass] read it: whether it was HEAD, or made a tunnel. */
    private class Head(
        val head: Boolean,
        val tunnel: Boolean = false,
    )

    /** What [sequentialPass] read: the heads in order, and whether the pipeline may read past the last one. */
    private class Pass(
        val heads: List<Head>,
        val open: Boolean,
    )

    /**
     * The pipeline's steps for each request in [data], on their own: the empty lines before a head skipped, the head
     * checks ([checkRequestHead]), Ktor's parser, the fields as sent ([requestFields]), the framing ([RequestFraming.of])
     * and the body ([RequestFraming.readBody], chunked included), until a request the pipeline would not read past (a
     * refusal, a faulty framing, CONNECT or an upgrade, a head over the limit) or the end of the input. Only a refusal
     * ([RequestHeadRefused]), a malformed chunked body, the end of the input inside a message, and the errors of Ktor's
     * own parser (a [ParserException], a line too long) may come out: anything else is a bug the pipeline would answer
     * with a 400. The pipeline's other catch-alls guard Ktor's code (`ConnectionOptions.parse`) and the handler, which
     * this pass does not run.
     */
    @OptIn(InternalAPI::class)
    private suspend fun sequentialPass(data: ByteArray): Pass {
        val input = HeadLimitedInput(ByteReadChannel(data), MAX_HEAD)
        val heads = ArrayList<Head>()
        var inHead = false
        try {
            while (true) {
                inHead = true
                input.startHead()
                if (!input.skipEmptyLines()) return Pass(heads, open = false)
                input.checkRequestHead()
                val request = parseRequest(input) ?: return Pass(heads, open = false)
                try {
                    if (input.exceeded) return Pass(heads + Head(input.headMethod), open = false)
                    input.endHead()
                    inHead = false
                    val version = HttpProtocolVersion.parse(request.version)
                    val fields = requestFields(request, input.keptFieldValues, version)
                    val method = request.method.value
                    val tunnel = method == "CONNECT" || fields["Upgrade"] != null
                    heads += Head(method == "HEAD", tunnel)
                    val framing = RequestFraming.of(request, fields)
                    if (framing.fault != null) return Pass(heads, open = false)
                    if (tunnel) return Pass(heads, open = true)
                    if (!framing.hasBody) continue
                    val out = ByteChannel()
                    coroutineScope {
                        launch { out.readBuffer() } // the handler reads the body as it comes
                        try {
                            framing.readBody(input, out)
                        } finally {
                            out.flushAndClose()
                        }
                    }
                } finally {
                    request.release()
                }
            }
        } catch (_: MalformedChunkedBodyException) {
            return Pass(heads, open = false)
        } catch (_: EOFException) {
            // inside a body (the request is counted) or inside a head the pipeline then refuses
            return Pass(if (inHead) heads + Head(input.headMethod) else heads, open = false)
        } catch (_: RequestHeadRefused) {
        } catch (_: ParserException) {
        } catch (_: TooLongLineException) {
        }
        // a refused head is answered too: count it, HEAD or not as far as its method was read
        return Pass(heads + Head(input.headMethod), open = false)
    }

    /**
     * [sent] as the sequence of responses to the requests of [pass] (the last may be cut short when the connection was reset,
     * not [complete]): each starts with an HTTP/1.1 status line and ends its
     * head with an empty line; interim responses are skipped; there are no more final responses than
     * requests; a final response's body is none for HEAD, 1xx, 204 and 304, else as its Content-Length or chunks say, or
     * the rest; and nothing follows a response that says `Connection: close`. Once past the requests the pass could follow
     * (a tunnel or an upgrade), the rest is not checked.
     */
    private fun checkResponses(
        sent: ByteArray,
        pass: Pass,
        complete: Boolean,
    ) {
        var pos = 0
        var final = 0
        val shown = { sent.decodeToString().take(200).visible() }
        while (pos < sent.size) {
            val headEnd = indexOf(sent, END, pos)
            if (headEnd < 0 && !complete) return // a reset cut the last response
            assertTrue(headEnd >= 0, "a response head without its empty line at $pos: ${shown()}")
            val lines = String(sent, pos, headEnd - pos, Charsets.ISO_8859_1).split("\r\n")
            assertTrue(STATUS_LINE.matches(lines[0]), "status line '${lines[0].visible()}' in ${shown()}")
            val status = lines[0].substring(9, 12).toInt()
            val fields = lines.drop(1).map { it.substringBefore(':').lowercase() to it.substringAfter(':').trim() }
            pos = headEnd + 4
            if (status / 100 == 1 && status != 101) continue // an interim response (the pipeline sends none of its own)
            if (final >= pass.heads.size) {
                assertTrue(pass.open, "final response ${final + 1} to ${pass.heads.size} request(s): ${shown()}")
                return
            }
            val request = pass.heads[final++]
            val te = fields.firstOrNull { it.first == "transfer-encoding" }?.second
            val cl = fields.firstOrNull { it.first == "content-length" }?.second
            when {
                request.head || status / 100 == 1 || status == 204 || status == 304 -> {}

                te != null -> {
                    pos = skipChunked(sent, pos)
                    if (pos < 0 && !complete) return
                    assertTrue(pos >= 0, "a malformed chunked response body: ${shown()}")
                }

                cl != null -> {
                    pos += cl.toInt()
                    if (pos > sent.size && !complete) return
                    assertTrue(pos <= sent.size, "a response body shorter than its Content-Length $cl: ${shown()}")
                }

                else -> {
                    pos = sent.size
                }
            }
            if ((request.tunnel && status / 100 == 2) || status == 101) return
            if (fields.any { it.first == "connection" && it.second.split(',').any { o -> o.trim().equals("close", ignoreCase = true) } }) {
                assertTrue(pos == sent.size, "${sent.size - pos} bytes after a response with Connection: close: ${shown()}")
            }
        }
    }

    /** The end of the chunked body at [from] in [b], or -1 when it is not one. */
    private fun skipChunked(
        b: ByteArray,
        from: Int,
    ): Int {
        var p = from
        while (true) {
            val eol = indexOf(b, CRLF, p)
            if (eol < 0) return -1
            val size = String(b, p, eol - p, Charsets.ISO_8859_1).substringBefore(';').trim().toIntOrNull(16) ?: return -1
            p = eol + 2
            if (size == 0) break
            p += size
            if (p + 2 > b.size || b[p] != CRLF[0] || b[p + 1] != CRLF[1]) return -1
            p += 2
        }
        while (true) {
            val eol = indexOf(b, CRLF, p)
            if (eol < 0) return -1
            val empty = eol == p
            p = eol + 2
            if (empty) return p
        }
    }

    private fun indexOf(
        b: ByteArray,
        what: ByteArray,
        from: Int,
    ): Int {
        for (i in from..b.size - what.size) if ((what.indices).all { b[i + it] == what[it] }) return i
        return -1
    }

    private fun String.visible(): String =
        map {
            if (it.code < 0x20 ||
                it.code >= 0x7F
            ) {
                "\\x%02x".format(it.code)
            } else {
                "$it"
            }
        }.joinToString("")

    /** The failure of handler mode 2. */
    private class HandlerFailure : Exception("the handler fails")

    private companion object {
        const val MAX_HEAD = 4_096
        val CRLF = byteArrayOf(0x0D, 0x0A)
        val END = byteArrayOf(0x0D, 0x0A, 0x0D, 0x0A)
        val STATUS_LINE = Regex("HTTP/1\\.1 [1-5][0-9][0-9]( .*)?")

        /** tchar (RFC 9110 section 5.6.2). */
        const val TCHAR = "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    }
}
