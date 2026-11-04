// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.readRemaining
import io.ktor.utils.io.writeFully
import io.kuicksilver.ktor.network.websocket.WebSocketInflate
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.io.readByteArray
import kotlin.test.Test
import kotlin.test.assertEquals

/** The engines' frame guard (RFC 6455 section 5.2) on its own, with and without permessage-deflate. */
class WebSocketFrameGuardTest {
    private fun bytes(vararg b: Int) = ByteArray(b.size) { b[it].toByte() }

    private fun guarded(
        input: ByteArray,
        inflate: WebSocketInflate?,
    ): ByteArray =
        runBlocking {
            val raw = ByteChannel()
            launch {
                raw.writeFully(input)
                raw.flushAndClose()
            }
            guardWebSocketInput(raw, WS_RSV1, untilClose = false, peerMasks = false, context = coroutineContext, inflate = inflate)
                .readRemaining()
                .readByteArray()
        }

    /** RFC 6455 section 5.2: the most significant bit of a 64-bit payload length MUST be 0; such a frame fails with 1002. */
    @Test fun negative_lengthWithTopBitClosesWith1002() {
        val frame = bytes(0x81, 0x7f, 0x80, 0, 0, 0, 0, 0, 0, 1, 0x61)
        for (inflate in listOf(null, WebSocketInflate(noContextTakeover = false, maxMessageSize = 1024))) {
            val out = guarded(bytes(0x81, 0x01, 0x62) + frame, inflate)
            assertEquals(listOf(0x81, 0x01, 0x62, 0x88), out.take(4).map { it.toInt() and 0xff }, "the frame before passes, then a Close")
            assertEquals(1002, ((out[5].toInt() and 0xff) shl 8) or (out[6].toInt() and 0xff))
        }
    }
}
