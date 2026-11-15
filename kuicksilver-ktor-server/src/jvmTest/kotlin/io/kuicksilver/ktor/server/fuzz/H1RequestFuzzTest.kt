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
import io.kuicksilver.ktor.server.h1.RequestFraming
import io.kuicksilver.ktor.server.h1.RequestHeadRefused
import io.kuicksilver.ktor.server.h1.checkRequestHead
import io.kuicksilver.ktor.server.h1.requestFields
import io.kuicksilver.ktor.server.h1.skipEmptyLines
import io.kuicksilver.ktor.server.h1.startH1Pipeline
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.io.EOFException
import kotlinx.io.readByteArray
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.TestInfo
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Fuzz target `h1Request`: input = what an HTTP/1.1 client sends on one connection, then the end of its side.
 *
 * First the server engine's pipeline ([startH1Pipeline]: the request head checks, Ktor's parser, the framing of request
 * bodies, chunked included, pipelining, `Expect: 100-continue`) runs on it with a 4 KiB head limit, in virtual time; the
 * handler reads each request body to its end and answers 200. Nothing in the pipeline waits for time here, so it must
 * have ended, its output closed, before virtual time moves at all: a connection that would only end at a deadline is a
 * hang. Every request the handler gets has a method that is a token and a target without whitespace or control
 * characters, and what the server sends, when anything, starts with an HTTP/1.1 status line.
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
                    input.readBuffer() // the body, to its end
                    output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    output.flush()
                }
            var sent = ByteArray(0)
            val reader = backgroundScope.launch { sent = fromServer.readBuffer().readByteArray() }
            backgroundScope.launch {
                toServer.writeFully(data)
                toServer.flushAndClose()
            }
            testScheduler.runCurrent() // virtual time stays at 0
            assertTrue(job.isCompleted, "the connection is still open after the input ended (it would end only at a deadline)")
            assertTrue(wrong.isEmpty(), "the handler got $wrong")
            assertTrue(reader.isCompleted, "the output was not closed after the connection ended")
            assertTrue(
                sent.isEmpty() || sent.decodeToString(0, minOf(9, sent.size)) == "HTTP/1.1 ",
                "sent ${sent.decodeToString().take(64).visible()}",
            )
            sequentialPass(data)
        }

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
    private suspend fun sequentialPass(data: ByteArray) {
        val input = HeadLimitedInput(ByteReadChannel(data), MAX_HEAD)
        try {
            while (true) {
                input.startHead()
                if (!input.skipEmptyLines()) return
                input.checkRequestHead()
                val request = parseRequest(input) ?: return
                try {
                    if (input.exceeded) return
                    input.endHead()
                    val fields = requestFields(request, input.keptFieldValues, HttpProtocolVersion.parse(request.version))
                    val framing = RequestFraming.of(request, fields)
                    if (framing.fault != null || request.method.value == "CONNECT" || fields["Upgrade"] != null) return
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
        } catch (_: RequestHeadRefused) {
        } catch (_: MalformedChunkedBodyException) {
        } catch (_: EOFException) {
        } catch (_: ParserException) {
        } catch (_: TooLongLineException) {
        }
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

    private companion object {
        const val MAX_HEAD = 4_096

        /** tchar (RFC 9110 section 5.6.2). */
        const val TCHAR = "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    }
}
