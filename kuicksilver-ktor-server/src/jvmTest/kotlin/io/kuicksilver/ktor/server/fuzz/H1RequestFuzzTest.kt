// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.server.h1.H1Connection
import io.kuicksilver.ktor.server.h1.HeadLimitedInput
import io.kuicksilver.ktor.server.h1.RequestHeadRefused
import io.kuicksilver.ktor.server.h1.checkRequestHead
import io.kuicksilver.ktor.server.h1.skipEmptyLines
import io.kuicksilver.ktor.server.h1.startH1Pipeline
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.io.IOException
import kotlinx.io.readByteArray
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.TestInfo
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Fuzz target `h1Request`: input = what an HTTP/1.1 client sends on one connection, then the end of its side. The server
 * engine's request head checks ([checkRequestHead], on the first head on their own: only a [RequestHeadRefused] may come
 * out) and its pipeline ([startH1Pipeline]: the same checks, Ktor's parser, the framing of request bodies, chunked
 * included, pipelining, `Expect: 100-continue`) runs on it with a 4 KiB head limit, in virtual time; the handler reads
 * each request body to its end and answers 200. The connection must end once the input has ended (no hang, no failure
 * that escapes the pipeline); every request the handler gets has a method that is a token and a target without
 * whitespace or control characters; and what the server sends, when anything, starts with an HTTP/1.1 status line.
 */
class H1RequestFuzzTest {
    @BeforeEach fun nameTheCase(case: TestInfo) = fuzzCase(case)

    @OptIn(InternalAPI::class)
    @FuzzTest(maxDuration = "60s")
    fun h1Request(data: ByteArray) =
        runTest {
            // the pipeline answers any failure of the head checks with a 400, which would hide a bug in them: they run on
            // the first head on their own first, where only a refusal or the end of the input may come out
            val head = HeadLimitedInput(ByteReadChannel(data), 4_096)
            head.startHead()
            try {
                if (head.skipEmptyLines()) head.checkRequestHead()
            } catch (_: RequestHeadRefused) {
            } catch (_: IOException) {
            }
            val toServer = ByteChannel()
            val fromServer = ByteChannel()
            val wrong = ArrayList<String>() // asserted after the run: the pipeline answers a failing handler with a 500
            val job =
                backgroundScope.startH1Pipeline(
                    H1Connection(toServer, fromServer, null, null),
                    45.seconds,
                    30.seconds,
                    maxHeadBytes = 4_096,
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
            // longer than every deadline of the pipeline (45 s), in virtual time: the background work runs only while time advances
            testScheduler.advanceTimeBy(100.seconds)
            testScheduler.runCurrent()
            assertTrue(job.isCompleted, "the connection is still open after the input ended")
            assertTrue(wrong.isEmpty(), "the handler got $wrong")
            assertTrue(reader.isCompleted, "the output was not closed after the connection ended")
            assertTrue(
                sent.isEmpty() || sent.decodeToString(0, minOf(9, sent.size)) == "HTTP/1.1 ",
                "sent ${sent.decodeToString().take(64).visible()}",
            )
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
        /** tchar (RFC 9110 section 5.6.2). */
        const val TCHAR = "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    }
}
