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

                                        !writerDone && !boundary -> WebSocketTransportEnd.Reset

                                        // a frame cut in the middle
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
