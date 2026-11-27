// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.runtime

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.io.IOException
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * [H2BodyChannel.cancel] on real threads against a reader that keeps reading while the server keeps sending, as in
 * `HttpStatement.execute {}`: Ktor's copier reads the body on a dispatcher thread while the call's end cancels it from
 * another (AbandonableBody) and the call job's completion handler cancels it again. Before, the cancel cleared the
 * buffer the reader was reading and threw (an EOFException from `Buffer.clear`), the stream was never reset, and the
 * call's resources stayed open. Every cancel must return, the reader must fail with a cancel's cause, and the server must
 * see one RST_STREAM CANCEL (RFC 9113 section 8.1).
 */
class H2BodyCancelRaceTest {
    @Test fun cancelsRacingAReaderAndArrivingDataNeverThrow() {
        repeat(ROUNDS) { round -> round(round) }
    }

    private fun round(round: Int) =
        runBlocking {
            val toServer = ByteChannel()
            val toClient = ByteChannel()
            val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
            try {
                val close = {
                    toServer.close()
                    toClient.close()
                }
                val server = H2ServerConnection.start(toServer, toClient, Http2Settings(), scope, close)
                val client = H2ClientConnection.start(toClient, toServer, Http2Settings(), scope, Duration.INFINITE, close)
                val reset = CompletableDeferred<Http2ErrorCode?>()
                scope.async {
                    val r = server.requests.receive()
                    try {
                        r.respond(200)
                        // more than the windows hold: the server sends as the reader reads, up to the cancel
                        val e = runCatching { r.sendBody(ByteReadChannel(ByteArray(8 shl 20)), end = false) }.exceptionOrNull()
                        reset.complete((e as? Http2Exception.StreamReset)?.code)
                    } finally {
                        r.release()
                    }
                }
                assertTrue(client.tryReserve())
                val s = client.open("POST", "https", "example.com", "/", emptyList(), endStream = false)
                s.response()
                val body = s.body
                val reader =
                    scope.async {
                        val buf = ByteArray(97) // odd: reads end inside the buffer's segments
                        var total = 0L
                        runCatching {
                            while (true) {
                                val n = body.readAvailable(buf, 0, buf.size)
                                if (n < 0) break
                                total += n
                            }
                        }.exceptionOrNull()
                    }
                // let the reader and the server get going, a different distance each round
                val spin = System.nanoTime() + (round % 7) * 150_000L
                while (System.nanoTime() < spin) Thread.onSpinWait()
                val causes = List(CANCELLERS) { IOException("cancel $it") }
                val thrown = AtomicReference<Throwable?>(null)
                val start = CyclicBarrier(CANCELLERS)
                val threads =
                    causes.map { c ->
                        thread(name = "h2-cancel-race") {
                            start.await()
                            try {
                                body.cancel(c)
                            } catch (e: Throwable) {
                                thrown.compareAndSet(null, e)
                            }
                        }
                    }
                threads.forEach { it.join() }
                thrown.get()?.let { throw AssertionError("round $round: cancel threw", it) }
                val readFailure = withTimeout(10.seconds) { reader.await() }
                if (readFailure !in causes) fail("round $round: the reader ended with $readFailure, not a cancel's cause")
                assertTrue(body.closedCause in causes, "round $round: ${body.closedCause}")
                assertEquals(Http2ErrorCode.CANCEL, withTimeout(10.seconds) { reset.await() }, "round $round")
                s.release()
                assertNull(thrown.get())
            } finally {
                scope.cancel()
            }
        }

    private companion object {
        const val ROUNDS = 300
        const val CANCELLERS = 3
    }
}
