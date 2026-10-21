// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteReadChannel
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.VarInt
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/** The request-stream frame reader's HEADERS bound (0.2.1 review). */
class RequestFramesTest {
    /**
     * With `maxFieldSectionSize` at its documented maximum of 2^30 the HEADERS bound is 2^31, which an Int cannot hold: a
     * declared length of 2^31 passed the check and became a negative buffer size (a connection error H3_INTERNAL_ERROR).
     * It must be refused unread like any other HEADERS frame above the bound.
     */
    @Test fun negative_headersLengthAboveIntRangeIsTooLarge() =
        runTest {
            for (len in listOf(1L shl 31, 1L shl 32)) {
                val input = ByteReadChannel(VarInt.encode(FrameType.HEADERS) + VarInt.encode(len))
                val frame = RequestFrames(input, isServerSide = true, maxHeadersFrame = 2L * (1L shl 30)).next()
                assertEquals(len, assertIs<RequestFrame.HeadersTooLarge>(frame, "length $len").length)
            }
        }
}
