// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * One stream's end never takes the connection with it (RFC 9113 section 5.4.2: a stream error affects that stream only),
 * and the server never answers a client's RST_STREAM with one of its own (section 5.4.2: "MUST NOT send a RST_STREAM
 * frame in response to a RST_STREAM frame").
 */
class ServerH2StreamTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Reads frames until stream [id] ends (a frame with END_STREAM or a RST_STREAM), returning all of them. */
    private suspend fun RawH2Client.untilEnd(id: Int): List<RawFrame> {
        val seen = ArrayList<RawFrame>()
        withTimeout(10.seconds) {
            while (true) {
                val f = readFrame() ?: error("the connection ended before stream $id did; read $seen")
                seen += f
                if (f.stream == id && (f.endStream && f.type != RawFrame.WINDOW_UPDATE || f.type == RawFrame.RST_STREAM)) break
            }
        }
        return seen
    }

    /** Sends a PING and returns the frames read up to its acknowledgement: everything the server wrote before it. */
    private suspend fun RawH2Client.roundTrip(): List<RawFrame> {
        val payload = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        write(RawH2Client.frame(RawFrame.PING, 0, 0, payload))
        val seen = ArrayList<RawFrame>()
        withTimeout(10.seconds) {
            while (true) {
                val f = readFrame() ?: error("the connection ended; read $seen")
                if (f.type == RawFrame.PING && f.flags and 1 == 1 && f.payload.contentEquals(payload)) break
                seen += f
            }
        }
        return seen
    }

    @Test fun negative_clientResetOfOneStreamLeavesTheOthers() = resetOfOneStreamLeavesTheOthers(throwOnCancel = false)

    /** As above, with a handler that throws an exception of its own once cancelled (its failure is not the connection's). */
    @Test fun negative_handlerThrowingAfterItsStreamWasResetLeavesTheOthers() = resetOfOneStreamLeavesTheOthers(throwOnCancel = true)

    /** As above, with a handler that answers anyway once cancelled: the answer fails (the stream is gone), the connection stays. */
    @Test fun negative_handlerAnsweringAResetStreamLeavesTheOthers() =
        resetOfOneStreamLeavesTheOthers(throwOnCancel = false, answerOnCancel = true)

    private fun resetOfOneStreamLeavesTheOthers(
        throwOnCancel: Boolean,
        answerOnCancel: Boolean = false,
    ) = serverTest {
        val started = CompletableDeferred<Unit>()
        val cancelled = CompletableDeferred<Unit>()
        val second = CompletableDeferred<Unit>()
        val secondStarted = CompletableDeferred<Unit>()
        val (server, port) =
            h2TlsServer {
                routing {
                    get("/hold") {
                        started.complete(Unit)
                        try {
                            awaitCancellation()
                        } catch (e: kotlinx.coroutines.CancellationException) {
                            if (throwOnCancel) throw IllegalStateException("the handler's own failure")
                            if (answerOnCancel) {
                                kotlinx.coroutines.withContext(
                                    kotlinx.coroutines.NonCancellable,
                                ) { call.respondText("late") }
                            }
                            throw e
                        } finally {
                            cancelled.complete(Unit)
                        }
                    }
                    get("/second") {
                        secondStarted.complete(Unit)
                        second.await()
                        call.respondText("second")
                    }
                }
            }
        try {
            RawH2Client.connect(port).use { raw ->
                raw.preface()
                raw.headers(1, RawH2Client.get("/hold"))
                raw.headers(3, RawH2Client.get("/second"))
                withTimeout(10.seconds) {
                    started.await()
                    secondStarted.await()
                }
                raw.rstStream(1, 0x8) // CANCEL
                withTimeout(10.seconds) { cancelled.await() }
                second.complete(Unit)
                val frames = raw.untilEnd(3) + raw.roundTrip()
                val last = frames.last { it.stream == 3 }
                assertEquals(3, last.stream, "$frames")
                assertEquals(RawFrame.DATA, last.type, "the other stream completes: $frames")
                assertTrue(frames.none { it.type == RawFrame.GOAWAY }, "the connection goes on: $frames")
                assertTrue(
                    frames.none { it.stream == 1 && it.type != RawFrame.WINDOW_UPDATE },
                    "nothing after the client's reset on stream 1: $frames",
                )
            }
        } finally {
            server.stop(100, 500)
        }
    }

    /** A request whose content turns out malformed under a running handler fails that stream only. */
    @Test fun negative_malformedBodyUnderARunningHandlerLeavesTheConnection() =
        serverTest {
            val (server, port) =
                h2TlsServer {
                    routing {
                        post("/") { call.respondText(call.receiveText()) }
                        get("/") { call.respondText("fine") }
                    }
                }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    val post = listOf(":method" to "POST", ":scheme" to "https", ":authority" to "server.test", ":path" to "/")
                    raw.headers(1, post + ("content-length" to "5"), endStream = false)
                    raw.data(1, "ab".encodeToByteArray(), endStream = false)
                    raw.data(1, "c".encodeToByteArray(), endStream = true)
                    val rst = assertNotNull(raw.await { it.stream == 1 && it.type == RawFrame.RST_STREAM })
                    assertEquals(0x1L, rst.errorCode)
                    raw.headers(3, RawH2Client.get())
                    val frames = raw.untilEnd(3)
                    assertEquals(RawFrame.DATA, frames.last().type, "$frames")
                    assertTrue(frames.none { it.type == RawFrame.GOAWAY }, "$frames")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A client RST_STREAM with NO_ERROR on a request it sent completely still cancels the request (RFC 9113 section 8.1
     * gives NO_ERROR a special meaning only from a server after its complete response).
     */
    @Test fun negative_clientResetWithNoErrorCancelsTheHandler() =
        serverTest {
            val started = CompletableDeferred<Unit>()
            val cancelled = CompletableDeferred<Unit>()
            val (server, port) =
                h2TlsServer {
                    routing {
                        get("/") {
                            started.complete(Unit)
                            try {
                                awaitCancellation()
                            } finally {
                                cancelled.complete(Unit)
                            }
                        }
                    }
                }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    raw.headers(1, RawH2Client.get())
                    withTimeout(10.seconds) { started.await() }
                    raw.rstStream(1, 0x0) // NO_ERROR
                    withTimeout(10.seconds) { cancelled.await() }
                }
            } finally {
                server.stop(100, 500)
            }
        }
}
