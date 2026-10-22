// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.kuicksilver.http3.frame.FrameAction
import io.kuicksilver.http3.frame.FrameHeaders
import io.kuicksilver.http3.frame.FrameRules
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.H3ProtocolError
import io.kuicksilver.http3.frame.SettingsCodec
import io.kuicksilver.http3.message.CapsuleParser
import io.kuicksilver.http3.message.MalformedMessage
import io.kuicksilver.http3.message.PseudoHeaders
import io.kuicksilver.http3.qpack.DecodeResult
import io.kuicksilver.http3.qpack.QpackDecoder
import io.kuicksilver.http3.qpack.QpackError
import kotlin.test.assertTrue

/** Fuzz target `h3Frames`: input = [stream kind][frames]; frames of a control or request stream through the sans-IO rules. */
class H3FrameFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun h3Frames(data: ByteArray) {
        if (data.isEmpty()) return
        val control = data[0].toInt() and 1 == 0
        val server = data[0].toInt() and 2 == 0
        var p = 1
        var first = true
        try {
            while (p < data.size) {
                val h = FrameHeaders.parse(data, p, data.size) ?: return
                p += h.headerSize
                val action = if (control) FrameRules.checkControl(h.type, first, server) else FrameRules.checkRequest(h.type, server)
                first = false
                if (h.length > data.size - p) return // the payload is not all here: a reader would wait (or skip as it streams)
                val payload = data.copyOfRange(p, p + h.length.toInt())
                p += h.length.toInt()
                if (action == FrameAction.Skip) continue
                if (control) {
                    FrameRules.checkControlLength(h.type, h.length)
                    if (h.type ==
                        FrameType.SETTINGS
                    ) {
                        SettingsCodec.decode(payload)
                    }
                }
                if (!control && h.type == FrameType.HEADERS) qpackContract { QpackDecoder(4096, 16, 65_536).decode(0, payload) }
            }
        } catch (_: H3ProtocolError) {
        }
    }

    /**
     * Capsules (RFC 9297 section 3.2) split at an input-chosen point, then the stream's FIN: the parser never holds more
     * than one capsule within its limits, and a cut capsule is only ever an H3ProtocolError.
     */
    @FuzzTest(maxDuration = "60s")
    fun capsules(data: ByteArray) {
        if (data.isEmpty()) return
        val cut = (data[0].toInt() and 0xff) % data.size
        val parser = CapsuleParser(maxCapsuleLength = 4096, maxDatagramLength = 1024, known = setOf(0x00, 0x2843))
        try {
            parser.feed(data, 1, maxOf(0, cut - 1)) { _, _ -> }
            parser.feed(data, maxOf(1, cut), data.size - maxOf(1, cut)) { t, b ->
                assertTrue(b.size <= if (t == CapsuleParser.DATAGRAM) 1024 else 4096)
            }
            parser.endOfStream()
        } catch (_: H3ProtocolError) {
        }
        assertTrue(parser.maxBuffered <= 4096)
    }
}

/** Fuzz target `qpackDecode`: input = [encoder-stream length, 0..255][encoder stream][field section]. */
class QpackDecodeFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun qpackDecode(data: ByteArray) {
        if (data.size < 2) return
        val n = minOf(data[0].toInt() and 0xff, data.size - 1)
        val d = QpackDecoder(4096, 16, 65_536)
        qpackContract {
            d.onEncoderStream(data, 1, n)
            when (val r = d.decode(0, data.copyOfRange(1 + n, data.size))) {
                is DecodeResult.Decoded -> {
                    assertTrue(r.decodedSize <= 65_536)
                    try {
                        PseudoHeaders.parseRequest(r.fields, true)
                    } catch (
                        _: MalformedMessage,
                    ) {
                    }
                }

                else -> {}
            }
            d.drainDecoderStream()
        }
    }
}

/** QPACK errors are the decoder's contract for bad input; anything else escaping is a finding. */
internal inline fun qpackContract(block: () -> Unit) {
    try {
        block()
    } catch (_: QpackError) {
    }
}
