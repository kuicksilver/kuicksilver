// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h3

import io.kuicksilver.ktor.client.h1.WebSocketTransportEnd
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * How an HTTP/3 WebSocket's stream ends ([h3WebSocketStreamEnd]): a FIN only for a stream that is whole (the frame guard
 * between frames) and not cut by the close wait, the server's FIN first when the session ended in order; RESET_STREAM
 * H3_REQUEST_CANCELLED otherwise (RFC 9220 section 3).
 */
class H3WebSocketStreamEndTest {
    /**
     * Ktor's `WebSocketWriter` cancelled inside a frame still ends its channel with `flushAndClose()`, so the writer looks
     * done while the frame guard is inside the frame. Before, that writer alone sent a FIN (`flushAndClose` on the
     * stream) after the cut frame, a truncated stream presented as whole; now the stream is reset.
     */
    @Test fun negative_aWriterThatEndedInsideAFrameIsReset() {
        for (inOrder in listOf(true, false)) {
            for (cut in listOf(true, false)) {
                assertEquals(
                    WebSocketTransportEnd.Reset,
                    h3WebSocketStreamEnd(
                        endedInOrder = inOrder,
                        failed = false,
                        writerDone = true,
                        atFrameBoundary = false,
                        drained = true,
                        cutByCloseWait = cut,
                    ),
                    "in order: $inOrder, cut by the close wait: $cut",
                )
            }
        }
    }

    /**
     * A session the close wait cut with frames still queued in front of QUIC's send buffer, its stream whole and its writer
     * done: reset, so nothing it queued leaves after T1. Before, its writer's end sent a FIN, and the stream went on sending
     * what was queued. Everything handed to the transport (its Close in flight): a FIN, never a reset that could discard it
     * (`ClientWebSocketExtensionsTest.closeSentBeforeACancelledCallIsNotResetH3`).
     */
    @Test fun negative_aSessionCutByTheCloseWaitWithFramesQueuedIsReset() {
        assertEquals(
            WebSocketTransportEnd.Reset,
            h3WebSocketStreamEnd(
                endedInOrder = false,
                failed = false,
                writerDone = true,
                atFrameBoundary = true,
                drained = false,
                cutByCloseWait = true,
            ),
        )
        assertEquals(
            WebSocketTransportEnd.Orderly,
            h3WebSocketStreamEnd(
                endedInOrder = false,
                failed = false,
                writerDone = true,
                atFrameBoundary = true,
                drained = true,
                cutByCloseWait = true,
            ),
        )
    }

    /** A session cancelled by its call between frames, not cut by the close wait: a FIN (its Close may still be in flight). */
    @Test fun aWholeStreamNotCutGetsAFin() {
        for (writerDone in listOf(true, false)) {
            assertEquals(
                WebSocketTransportEnd.Orderly,
                h3WebSocketStreamEnd(
                    endedInOrder = false,
                    failed = false,
                    writerDone = writerDone,
                    atFrameBoundary = true,
                    drained = false,
                    cutByCloseWait = false,
                ),
                "writer done: $writerDone",
            )
        }
        assertEquals(
            WebSocketTransportEnd.AfterServer,
            h3WebSocketStreamEnd(
                endedInOrder = true,
                failed = false,
                writerDone = true,
                atFrameBoundary = true,
                drained = false,
                cutByCloseWait = false,
            ),
        )
    }
}
