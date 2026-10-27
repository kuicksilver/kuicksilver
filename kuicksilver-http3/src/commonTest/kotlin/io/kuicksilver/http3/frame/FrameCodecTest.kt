// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.frame

import io.kuicksilver.http3.Http3ErrorCode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class VarIntTest {
    @Test fun roundTripBoundaries() {
        val values = listOf(0L, 63L, 64L, 16383L, 16384L, (1L shl 30) - 1, 1L shl 30, (1L shl 62) - 1)
        val sizes = listOf(1, 1, 2, 2, 4, 4, 8, 8)
        for ((v, s) in values.zip(sizes)) {
            assertEquals(s, VarInt.size(v))
            val buf = ByteArray(8)
            assertEquals(s, VarInt.write(v, buf, 0))
            assertEquals(v, VarInt.read(buf, 0, s))
            assertEquals(s, VarInt.encodedLength(buf[0]))
        }
    }

    @Test fun truncatedNeedsMore() {
        assertEquals(-1L, VarInt.read(byteArrayOf(0x40, 0x00), 0, 1))
        assertEquals(-1L, VarInt.read(ByteArray(0), 0, 0))
    }

    @Test fun tooLargeRejected() {
        assertFailsWith<IllegalArgumentException> { VarInt.size(1L shl 62) }
    }
}

class FrameHeaderTest {
    @Test fun parsesIncrementally() {
        val buf = ByteArray(16)
        val n = FrameHeaders.write(0x1, 300, buf, 0)
        assertEquals(3, n)
        assertNull(FrameHeaders.parse(buf, 0, 0))
        assertNull(FrameHeaders.parse(buf, 0, 1))
        assertNull(FrameHeaders.parse(buf, 0, 2))
        val h = assertNotNull(FrameHeaders.parse(buf, 0, 3))
        assertEquals(0x1L, h.type)
        assertEquals(300L, h.length)
        assertEquals(3, h.headerSize)
    }

    @Test fun negative_h3ReservedFrameHugeLength() {
        // A reserved (GREASE) frame announcing 2^62-1 bytes: the header parses, the rules say "skip", nothing is sized by the length.
        val buf = ByteArray(16)
        val n = FrameHeaders.write(0x21, (1L shl 62) - 1, buf, 0)
        val h = assertNotNull(FrameHeaders.parse(buf, 0, n))
        assertEquals((1L shl 62) - 1, h.length)
        assertEquals(FrameAction.Skip, FrameRules.checkRequest(h.type, isServerSide = true))
        assertEquals(FrameAction.Skip, FrameRules.checkControl(h.type, first = false, isServer = true))
    }
}

class SettingsCodecTest {
    @Test fun roundTrip() {
        val values =
            listOf(
                SettingsId.QPACK_MAX_TABLE_CAPACITY to 4096L,
                SettingsId.MAX_FIELD_SECTION_SIZE to 65_536L,
                SettingsId.H3_DATAGRAM to 1L,
            )
        assertEquals(values.toMap(), SettingsCodec.decode(SettingsCodec.encode(values)))
    }

    private fun err(block: () -> Unit): Long = assertFailsWith<H3ProtocolError> { block() }.code

    @Test fun h2SettingRejected() {
        for (id in listOf(0x0L, 0x2L, 0x3L, 0x4L, 0x5L)) {
            assertEquals(
                Http3ErrorCode.SETTINGS_ERROR,
                err {
                    SettingsCodec.decode(
                        SettingsCodec.encode(
                            listOf(id to 1L),
                        ),
                    )
                },
            )
        }
    }

    @Test fun duplicateRejected() {
        assertEquals(
            Http3ErrorCode.SETTINGS_ERROR,
            err {
                SettingsCodec.decode(
                    SettingsCodec.encode(
                        listOf(0x6L to 1L, 0x6L to 2L),
                    ),
                )
            },
        )
    }

    @Test fun booleanSettingOutOfRange() {
        assertEquals(
            Http3ErrorCode.SETTINGS_ERROR,
            err {
                SettingsCodec.decode(
                    SettingsCodec.encode(
                        listOf(SettingsId.ENABLE_CONNECT_PROTOCOL to 2L),
                    ),
                )
            },
        )
        assertEquals(
            Http3ErrorCode.SETTINGS_ERROR,
            err { SettingsCodec.decode(SettingsCodec.encode(listOf(SettingsId.H3_DATAGRAM to 2L))) },
        )
    }

    @Test fun truncatedIsFrameError() {
        val b = SettingsCodec.encode(listOf(0x6L to 100_000L))
        assertEquals(
            Http3ErrorCode.FRAME_ERROR,
            err {
                SettingsCodec.decode(
                    b.copyOf(b.size - 1),
                )
            },
        )
    }

    @Test fun unknownAndGreaseIgnored() {
        val m = SettingsCodec.decode(SettingsCodec.encode(listOf(0x21L to 7L, 0x1234L to 1L, 0x6L to 10L)))
        assertEquals(10L, m[0x6L])
        assertEquals(7L, m[0x21L])
        assertEquals(3, m.size) // kept: the caller ignores what it does not know
    }
}

class FrameRulesTest {
    private fun err(block: () -> Unit): Long = assertFailsWith<H3ProtocolError> { block() }.code

    @Test fun controlFirstMustBeSettings() {
        assertEquals(Http3ErrorCode.MISSING_SETTINGS, err { FrameRules.checkControl(FrameType.GOAWAY, first = true, isServer = false) })
        assertEquals(Http3ErrorCode.MISSING_SETTINGS, err { FrameRules.checkControl(0x21, first = true, isServer = false) })
        assertEquals(FrameAction.Process, FrameRules.checkControl(FrameType.SETTINGS, first = true, isServer = false))
    }

    /**
     * RFC 9114 section 6.2.1: any first frame other than SETTINGS is H3_MISSING_SETTINGS, the WebTransport signal included
     * (draft-ietf-webtrans-http3 makes it H3_FRAME_ERROR elsewhere on the control stream).
     */
    @Test fun wtStreamFirstOnControlIsMissingSettings() {
        assertEquals(
            Http3ErrorCode.MISSING_SETTINGS,
            err { FrameRules.checkControl(FrameType.WT_STREAM, first = true, isServer = true, webTransport = true) },
        )
        assertEquals(
            Http3ErrorCode.FRAME_ERROR,
            err { FrameRules.checkControl(FrameType.WT_STREAM, first = false, isServer = true, webTransport = true) },
        )
    }

    @Test fun secondSettingsUnexpected() {
        assertEquals(Http3ErrorCode.FRAME_UNEXPECTED, err { FrameRules.checkControl(FrameType.SETTINGS, first = false, isServer = true) })
    }

    @Test fun dataOnControlUnexpected() {
        assertEquals(Http3ErrorCode.FRAME_UNEXPECTED, err { FrameRules.checkControl(FrameType.DATA, first = false, isServer = true) })
        assertEquals(Http3ErrorCode.FRAME_UNEXPECTED, err { FrameRules.checkControl(FrameType.HEADERS, first = false, isServer = true) })
    }

    @Test fun h2FramesUnexpected() {
        for (t in listOf(0x2L, 0x6L, 0x8L, 0x9L)) {
            assertEquals(Http3ErrorCode.FRAME_UNEXPECTED, err { FrameRules.checkControl(t, first = false, isServer = true) })
            assertEquals(Http3ErrorCode.FRAME_UNEXPECTED, err { FrameRules.checkRequest(t, isServerSide = true) })
        }
    }

    @Test fun pushPromiseCodesByRole() {
        assertEquals(Http3ErrorCode.ID_ERROR, err { FrameRules.checkRequest(FrameType.PUSH_PROMISE, isServerSide = false) })
        assertEquals(Http3ErrorCode.FRAME_UNEXPECTED, err { FrameRules.checkRequest(FrameType.PUSH_PROMISE, isServerSide = true) })
        assertEquals(Http3ErrorCode.ID_ERROR, err { FrameRules.checkControl(FrameType.CANCEL_PUSH, first = false, isServer = false) })
        assertEquals(
            Http3ErrorCode.FRAME_UNEXPECTED,
            err { FrameRules.checkControl(FrameType.MAX_PUSH_ID, first = false, isServer = false) },
        )
    }

    /**
     * RFC 9114 sections 7.2.7 and 7.1: a server reads MAX_PUSH_ID (to catch a decreasing value), and a payload that is not
     * exactly one variable-length integer is H3_FRAME_ERROR.
     */
    @Test fun maxPushIdProcessedOnServer() {
        assertEquals(FrameAction.Process, FrameRules.checkControl(FrameType.MAX_PUSH_ID, first = false, isServer = true))
        assertEquals(1L shl 40, ControlFrames.parseMaxPushId(ControlFrames.maxPushIdPayload(1L shl 40)))
        assertEquals(Http3ErrorCode.FRAME_ERROR, err { ControlFrames.parseMaxPushId(ByteArray(0)) })
        assertEquals(Http3ErrorCode.FRAME_ERROR, err { ControlFrames.parseMaxPushId(byteArrayOf(5, 0)) })
        assertEquals(Http3ErrorCode.FRAME_ERROR, err { ControlFrames.parseMaxPushId(byteArrayOf(0x40)) })
    }

    @Test fun settingsOnRequestUnexpected() {
        for (t in listOf(
            FrameType.SETTINGS,
            FrameType.GOAWAY,
            FrameType.MAX_PUSH_ID,
            FrameType.CANCEL_PUSH,
            FrameType.PRIORITY_UPDATE_REQUEST,
        )) {
            assertEquals(Http3ErrorCode.FRAME_UNEXPECTED, err { FrameRules.checkRequest(t, isServerSide = true) })
        }
    }

    @Test fun greaseIsSkipped() {
        assertTrue(FrameType.isGrease(0x21))
        assertTrue(FrameType.isGrease(0x21 + 0x1f * 5))
        assertTrue(FrameType.isGrease(FrameType.grease(1000)))
        assertEquals(FrameAction.Skip, FrameRules.checkRequest(0x40, isServerSide = false))
        assertEquals(FrameAction.Process, FrameRules.checkRequest(FrameType.DATA, isServerSide = false))
    }

    @Test fun controlPayloadCap() {
        assertEquals(Http3ErrorCode.EXCESSIVE_LOAD, err { FrameRules.checkControlLength(FrameType.SETTINGS, 4097) })
        FrameRules.checkControlLength(FrameType.SETTINGS, 4096)
    }

    @Test fun goAwayAndPriorityUpdateCodec() {
        assertEquals(1L shl 40, ControlFrames.parseGoAway(ControlFrames.goAwayPayload(1L shl 40)))
        val (id, v) = ControlFrames.parsePriorityUpdate(ControlFrames.priorityUpdatePayload(8, "u=1, i"))
        assertEquals(8L, id)
        assertEquals("u=1, i", v)
        assertEquals(Http3ErrorCode.FRAME_ERROR, err { ControlFrames.parseGoAway(ByteArray(0)) })
    }
}
