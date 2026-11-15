// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.frame

import io.kuicksilver.http3.Http3ErrorCode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull

/** Frame placement rules that no other test pinned frame type by frame type, and the header parser at value 0. */
class FrameGapTest {
    private fun code(block: () -> Unit): Long = assertFailsWith<H3ProtocolError> { block() }.code

    /**
     * RFC 9114 section 7.2.5: "If a PUSH_PROMISE frame is received on the control stream, the client MUST respond with a
     * connection error of type H3_FRAME_UNEXPECTED." A server reading the client's control stream does the same (section
     * 7.2.5: "A client MUST NOT send a PUSH_PROMISE frame"; section 6.2.1 lists the frames allowed there).
     */
    @Test fun negative_pushPromiseOnTheControlStream() {
        for (server in listOf(false, true)) {
            assertEquals(
                Http3ErrorCode.FRAME_UNEXPECTED,
                code { FrameRules.checkControl(FrameType.PUSH_PROMISE, first = false, isServer = server) },
            )
        }
    }

    /**
     * RFC 9218 section 7.2: "Receiving a PRIORITY_UPDATE frame on a stream other than the client control stream MUST be
     * treated as a connection error of type H3_FRAME_UNEXPECTED" -- both types, 0xF0700 and 0xF0701, on a request stream.
     */
    @Test fun negative_priorityUpdateOfEitherTypeOnARequestStream() {
        for (type in listOf(FrameType.PRIORITY_UPDATE_REQUEST, FrameType.PRIORITY_UPDATE_PUSH)) {
            for (server in listOf(false, true)) {
                assertEquals(Http3ErrorCode.FRAME_UNEXPECTED, code { FrameRules.checkRequest(type, isServerSide = server) })
            }
        }
    }

    /**
     * RFC 9114 section 7.1: "A frame payload that contains additional bytes after the identified fields or a frame payload
     * that terminates before the end of the identified fields MUST be treated as a connection error of type
     * H3_FRAME_ERROR." GOAWAY and MAX_PUSH_ID carry one variable-length integer (sections 7.2.6, 7.2.7): a Length above 8
     * (the longest one) is that error from the header alone, whatever its size; the payload cap of section 10.5
     * (H3_EXCESSIVE_LOAD) is for frames whose payload is a list or a string.
     */
    @Test fun negative_oneIntegerFrameLongerThanAnIntegerIsFrameError() {
        for (type in listOf(FrameType.GOAWAY, FrameType.MAX_PUSH_ID)) {
            for (len in listOf(9L, FrameRules.MAX_CONTROL_PAYLOAD, FrameRules.MAX_CONTROL_PAYLOAD + 1, (1L shl 62) - 1)) {
                assertEquals(Http3ErrorCode.FRAME_ERROR, code { FrameRules.checkControlLength(type, len) }, "type $type length $len")
            }
            for (len in 1L..8L) FrameRules.checkControlLength(type, len)
        }
        // variable payloads keep the cap: SETTINGS (a list) and PRIORITY_UPDATE (an ID and a field value)
        for (type in listOf(FrameType.SETTINGS, FrameType.PRIORITY_UPDATE_REQUEST, FrameType.PRIORITY_UPDATE_PUSH)) {
            FrameRules.checkControlLength(type, FrameRules.MAX_CONTROL_PAYLOAD)
            assertEquals(Http3ErrorCode.EXCESSIVE_LOAD, code { FrameRules.checkControlLength(type, FrameRules.MAX_CONTROL_PAYLOAD + 1) })
        }
    }

    /** RFC 9114 section 7.1: type 0 (DATA) and length 0 are ordinary values; a whole header is never "not here yet". */
    @Test fun zeroTypeAndZeroLengthParse() {
        val f = FrameHeaders.frame(FrameType.DATA, ByteArray(0))
        val h = assertNotNull(FrameHeaders.parse(f, 0, f.size))
        assertEquals(FrameType.DATA, h.type)
        assertEquals(0L, h.length)
        assertEquals(2, h.headerSize)
    }
}
