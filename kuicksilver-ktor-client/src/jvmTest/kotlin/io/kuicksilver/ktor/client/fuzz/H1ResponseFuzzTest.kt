// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.cio.ParserException
import io.ktor.http.cio.parseResponse
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readBuffer
import io.kuicksilver.ktor.client.h1.ResponseFraming
import io.kuicksilver.ktor.client.h1.readResponseHeadBytes
import io.kuicksilver.ktor.client.h1.responseFields
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.io.IOException
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.TestInfo
import kotlin.test.assertTrue

/**
 * Fuzz target `h1Response`: input = what an HTTP/1.1 server sends on one connection. The client engine's path for each
 * response runs on it in turn: the head ([readResponseHeadBytes], at most 4 KiB here), Ktor's `parseResponse` of the
 * bytes it hands on, the fields as sent ([responseFields]), the framing ([ResponseFraming.of]) and the body
 * ([ResponseFraming.readBody]: chunked with its trailer section, Content-Length, or until the close); interim 1xx heads
 * are skipped, a 204 or 304 has no content, and a delimited body is followed by the next response as on a kept-alive
 * connection. Only the parse errors of the engine (a [ParserException] or an [IOException], as a cut or malformed message
 * fails) may escape; a head handed on is within the limit and holds no control character but HTAB and the line ends.
 */
class H1ResponseFuzzTest {
    @BeforeEach fun nameTheCase(case: TestInfo) = fuzzCase(case)

    @FuzzTest(maxDuration = "60s")
    fun h1Response(data: ByteArray) {
        val input = ByteReadChannel(data)
        runBlocking {
            try {
                while (true) {
                    val head = readResponseHeadBytes(input, MAX_HEAD) ?: return@runBlocking
                    assertTrue(head.bytes.size <= MAX_HEAD, "a head of ${head.bytes.size} bytes")
                    for (b in head.bytes) {
                        val c = b.toInt() and 0xFF
                        assertTrue((c >= 0x20 && c != 0x7F) || c == 0x09 || c == 0x0D || c == 0x0A, "control character $c in a head")
                    }
                    val raw = parseResponse(ByteReadChannel(head.bytes)) ?: throw ParserException("no response")
                    val status = raw.status
                    val framing =
                        raw.use {
                            val fields = responseFields(raw.headers, head.keptValues)
                            if (status / 100 == 1 && status != 101) return@use null
                            ResponseFraming.of(fields, http10 = HttpProtocolVersion.parse(raw.version) == HttpProtocolVersion.HTTP_1_0)
                        } ?: continue
                    // 101: the connection is handed over (the WebSocket guard has its own target); an invalid framing ends it
                    if (status == 101 || framing.invalidLength || framing.invalidEncoding) return@runBlocking
                    if (status == 204 || status == 304) continue // no content whatever the framing says (RFC 9110 section 6.4.1)
                    val out = ByteChannel()
                    coroutineScope {
                        launch { out.readBuffer() } // the application reads the body as it comes
                        try {
                            framing.readBody(input, out)
                        } finally {
                            out.flushAndClose() // as the engine does once the body is read: the reader ends
                        }
                    }
                    if (!framing.delimited) return@runBlocking
                }
            } catch (_: ParserException) {
            } catch (_: IOException) {
            }
        }
    }

    private companion object {
        const val MAX_HEAD = 4_096
    }
}
