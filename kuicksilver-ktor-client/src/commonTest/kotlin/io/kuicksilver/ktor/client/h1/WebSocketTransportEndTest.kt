// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * How an HTTP/1.1 WebSocket's connection ends ([webSocketTransportEnd]): reset only for a frame cut in the middle, a
 * failed writer, or frames still queued when the close wait cut the session; whole frames still queued in front of the
 * socket otherwise go out in order. Every combination of the inputs is checked against that rule.
 */
class WebSocketTransportEndTest {
    /**
     * A session cancelled by its call while idle, its writer done, its last frame handed to the connection but not yet
     * taken by the socket's writer (a loaded host): before, the connection was reset and the frame the application had
     * sent was cut off (ClientWebSocketCloseOrderTest.negative_anIdleCancelledPlainSessionClosesCleanly failed about once
     * in 400 runs with two busy threads); now the frame goes out, then a FIN.
     */
    @Test fun negative_wholeFramesStillQueuedWhenTheCallIsCancelledGoOutInOrder() {
        for (writerDone in listOf(true, false)) {
            assertEquals(
                WebSocketTransportEnd.Orderly,
                webSocketTransportEnd(
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
    }

    @Test fun negative_framesStillQueuedWhenTheCloseWaitCutTheSessionAreReset() {
        assertEquals(
            WebSocketTransportEnd.Reset,
            webSocketTransportEnd(
                endedInOrder = false,
                failed = false,
                writerDone = false,
                atFrameBoundary = true,
                drained = false,
                cutByCloseWait = true,
            ),
        )
    }

    /**
     * Ktor's `WebSocketWriter` cancelled inside a large frame (the close wait cut it while a server did not read) still
     * ends its channel with `flushAndClose()`, so the writer looks done although the frame guard is inside the frame and
     * the rest of the frame and the Close never reached the connection. Before, that writer counted as done, the
     * connection got a FIN after the cut frame, and the server read `[binary 16777216, cut]` as a clean end
     * (`ClientWebSocketCloseTest.negative_anUnwrittenCloseIsBoundedByTheCloseWait` in the local matrix's Docker step,
     * 2026-11-18); now it is reset.
     */
    @Test fun negative_aWriterThatEndedInsideAFrameIsReset() {
        for (drained in listOf(true, false)) {
            for (cut in listOf(true, false)) {
                assertEquals(
                    WebSocketTransportEnd.Reset,
                    webSocketTransportEnd(
                        endedInOrder = false,
                        failed = false,
                        writerDone = true,
                        atFrameBoundary = false,
                        drained = drained,
                        cutByCloseWait = cut,
                    ),
                    "drained: $drained, cut by the close wait: $cut",
                )
            }
        }
    }

    @Test fun everyCombinationFollowsTheRule() {
        val b = listOf(false, true)
        for (inOrder in b) {
            for (failed in b) {
                for (done in b) {
                    for (boundary in b) {
                        for (drained in b) {
                            for (cut in b) {
                                val writerDone = done && !failed // as the engine computes it
                                val got = webSocketTransportEnd(inOrder, failed, writerDone, boundary, drained, cut)
                                val want =
                                    when {
                                        inOrder && writerDone -> WebSocketTransportEnd.AfterServer

                                        failed -> WebSocketTransportEnd.Reset

                                        !boundary -> WebSocketTransportEnd.Reset

                                        // a frame cut in the middle, whether or not the writer ended its channel
                                        !drained && cut -> WebSocketTransportEnd.Reset

                                        // queued data never leaves after the close wait
                                        else -> WebSocketTransportEnd.Orderly
                                    }
                                assertEquals(
                                    want,
                                    got,
                                    "inOrder=$inOrder failed=$failed done=$done boundary=$boundary drained=$drained cut=$cut",
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
