// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.cio.ParserException
import io.ktor.http.cio.parseResponse
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.availableForRead
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
 * fails) may escape; a head takes at most the limit from the connection, and what it hands on is what Ktor's parser may
 * rely on ([checkHead]).
 */
class H1ResponseFuzzTest {
    @BeforeEach fun nameTheCase(case: TestInfo) = fuzzCase(case)

    @FuzzTest(maxDuration = "60s")
    fun h1Response(data: ByteArray) {
        val input = ByteReadChannel(data)
        runBlocking {
            try {
                while (true) {
                    val before = input.availableForRead
                    val head = readResponseHeadBytes(input, MAX_HEAD) ?: return@runBlocking
                    // the limit is on what the head takes from the connection: the bytes handed on may be longer (a bare
                    // LF becomes CRLF, an invalid status code becomes 500 followed by the code sent)
                    val taken = before - input.availableForRead
                    assertTrue(taken <= MAX_HEAD, "a head that took $taken bytes")
                    checkHead(head.bytes)
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
        val END = byteArrayOf(CR, LF, CR, LF)
        val STATUS_LINE = Regex("^HTTP/1\\.[01] [1-5][0-9][0-9][ \r]")
    }
}
