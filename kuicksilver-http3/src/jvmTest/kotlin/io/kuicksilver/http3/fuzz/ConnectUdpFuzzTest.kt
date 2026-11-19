// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.kuicksilver.http3.frame.H3ProtocolError
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.message.CapsuleParser
import io.kuicksilver.http3.message.DatagramFilter
import io.kuicksilver.http3.message.DatagramVerdict
import io.kuicksilver.http3.message.TemplateMatch
import io.kuicksilver.http3.message.UdpHost
import io.kuicksilver.http3.message.UdpUriTemplate
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.TestInfo
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/** CONNECT-UDP (RFC 9298): the URI Template parser and matcher, and DATAGRAM capsules judged by their Context ID. */
class ConnectUdpFuzzTest {
    @BeforeEach fun nameTheCase(case: TestInfo) = fuzzCase(case)

    /**
     * Fuzz target `udpTemplate`: input = [split, 0..255][template text][request path], the text as Latin-1. A template is
     * refused only with IllegalArgumentException; a server's template matches any path without throwing, and a target it
     * reads back is a valid one (RFC 9298 section 3); a client's template that parses expands, and what the matching
     * server template reads from that expansion is the target that was expanded. The path is also read as a target host.
     */
    @FuzzTest(maxDuration = "60s")
    fun udpTemplate(data: ByteArray) {
        if (data.isEmpty()) return
        val split = 1 + (data[0].toInt() and 0xff).coerceAtMost(data.size - 1)
        val template = String(data, 1, split - 1, Charsets.ISO_8859_1)
        val path = String(data, split, data.size - split, Charsets.ISO_8859_1)
        fuzzOp { "template [1, $split), path [$split, ${data.size})" }
        UdpHost.parse(path)?.let { h -> assertTrue(UdpHost.parse(h.text)?.text == h.text, "host text does not parse back: $h") }
        val server =
            try {
                UdpUriTemplate.parsePath(template)
            } catch (_: IllegalArgumentException) {
                null
            }
        if (server != null) {
            when (val m = server.match(path)) {
                is TemplateMatch.Target -> {
                    assertTrue(m.port in 1..65535)
                    assertTrue(UdpHost.parse(m.host.text) != null)
                }

                is TemplateMatch.Invalid, TemplateMatch.NoMatch -> {}
            }
        }
        val client =
            try {
                UdpUriTemplate.parseAbsolute(template)
            } catch (_: IllegalArgumentException) {
                return
            }
        // the template's path and query, which a server would serve
        val pathTemplate = template.substring(template.indexOf('/', template.indexOf("://") + 3))
        val back =
            try {
                UdpUriTemplate.parsePath(pathTemplate)
            } catch (_: IllegalArgumentException) {
                null // a template a client may use but a server could not read back
            }
        for ((host, port) in listOf("192.0.2.1" to 443, "2001:db8::1" to 1, "a.example" to 65535)) {
            val e = client.expand(host, port)
            if (back == null) continue
            when (val m = back.match(e.pathAndQuery)) {
                is TemplateMatch.Target -> {
                    assertEquals(port, m.port)
                    assertEquals(UdpHost.parse(host)!!.text, m.host.text)
                }

                else -> {
                    fail("the expansion $e of $template does not match its own path template: $m")
                }
            }
        }
    }

    /**
     * Fuzz target `udpDatagrams`: input = [cut, 0..255][capsules], fed in two pieces and then the stream's FIN, through the
     * parser of a CONNECT-UDP stream: Context ID 0 delivered up to 1200 bytes of payload, longer ones above 65527 bytes
     * aborted with H3_DATAGRAM_ERROR, others and every other Context ID skipped. Nothing skipped is buffered, a delivered
     * datagram starts with Context ID 0, and errors are only H3ProtocolError.
     */
    @FuzzTest(maxDuration = "60s")
    fun udpDatagrams(data: ByteArray) {
        if (data.isEmpty()) return
        val cut = (data[0].toInt() and 0xff) % data.size
        fuzzOp { "capsules [1, ${1 + maxOf(0, cut - 1)}) then [${maxOf(1, cut)}, ${data.size}) then FIN" }
        val filter =
            DatagramFilter { ctx, len ->
                when {
                    ctx != 0L -> DatagramVerdict.Skip
                    len > 65_527 -> DatagramVerdict.Abort
                    len > 1200 -> DatagramVerdict.Skip
                    else -> DatagramVerdict.Deliver
                }
            }
        val parser = CapsuleParser(maxCapsuleLength = 4096, maxDatagramLength = 1208, known = setOf(0x00), filter = filter)
        val check = { t: Long, b: ByteArray ->
            assertEquals(0L, t)
            assertEquals(0L, VarInt.read(b, 0, b.size))
            assertTrue(b.size - VarInt.encodedLength(b[0]) <= 1200)
        }
        try {
            parser.feed(data, 1, maxOf(0, cut - 1), check)
            parser.feed(data, maxOf(1, cut), data.size - maxOf(1, cut), check)
            parser.endOfStream()
        } catch (_: H3ProtocolError) {
        }
        assertTrue(parser.maxBuffered <= 1208, "buffered ${parser.maxBuffered}")
    }
}
