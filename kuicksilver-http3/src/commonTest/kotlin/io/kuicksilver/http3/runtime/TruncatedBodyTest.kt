// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A body the peer never finished must not look complete: only a FIN after all DATA ends the channel, every other end
 * (a lost connection, a reset) fails the read with its cause. `readAvailable` returned -1 for both before 0.2.0 (release
 * gate: the interop client wrote a truncated download).
 */
class TruncatedBodyTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun causes(t: Throwable): Sequence<Throwable> = generateSequence(t) { it.cause }

    /** Reads [n] bytes, as an application that trusts -1 would. */
    private suspend fun ByteReadChannel.readSome(n: Int): Int {
        var got = 0
        val buf = ByteArray(n)
        while (got < n) {
            val r = readAvailable(buf, got, n - got)
            if (r < 0) break
            got += r
        }
        return got
    }

    @Test fun connectionLostMidBodyFailsTheRead() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val partRead = CompletableDeferred<Unit>()
                launch {
                    val r = p.server.acceptRequest()
                    val w = r.respond(200, Http3Headers.of("content-length" to "20"))
                    w.output.writeFully(ByteArray(10) { 1 })
                    w.output.flush()
                    partRead.await()
                    p.server.close(Http3ErrorCode.INTERNAL_ERROR, "gone")
                }
                val resp = p.client.request(get("/x"))
                assertEquals(10, resp.body.readSome(10))
                partRead.complete(Unit)
                // the pump has given up (the trailers fail with it) before the application reads on: the end is already known
                assertFailsWith<Throwable> { withTimeout(10.seconds) { resp.trailers.await() } }
                val e = assertFailsWith<Throwable> { withTimeout(10.seconds) { resp.body.readSome(10) } }
                assertTrue(causes(e).any { it is Http3Exception || it is QuicException.ConnectionLost }, "$e")
                assertFalse(resp.body.isClosedForRead, "a failed body is not at its end")
                assertNotNull(resp.body.closedCause)
                assertFailsWith<Throwable> { resp.body.readSome(1) }
            }
        }

    @Test fun resetMidBodyFailsTheRead() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val partRead = CompletableDeferred<Unit>()
                launch {
                    val r = p.server.acceptRequest()
                    val w = r.respond(200)
                    w.output.writeFully(ByteArray(10) { 1 })
                    w.output.flush()
                    partRead.await()
                    r.reset(Http3ErrorCode.INTERNAL_ERROR)
                }
                val resp = p.client.request(get("/x"))
                assertEquals(10, resp.body.readSome(10))
                partRead.complete(Unit)
                assertFailsWith<Throwable> { withTimeout(10.seconds) { resp.trailers.await() } }
                val e = assertFailsWith<Throwable> { withTimeout(10.seconds) { resp.body.readSome(10) } }
                assertTrue(causes(e).any { it is Http3Exception }, "$e")
                assertFalse(resp.body.isClosedForRead, "a reset body is not at its end")
            }
        }

    /** The request body on the server fails the same way when the client's connection goes. */
    @Test fun connectionLostMidRequestBodyFailsTheServerRead() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val partRead = CompletableDeferred<Unit>()
                val serverSaw = CompletableDeferred<Throwable>()
                launch {
                    val r = p.server.acceptRequest()
                    assertEquals(10, r.body.readSome(10))
                    partRead.complete(Unit)
                    serverSaw.complete(assertFailsWith<Throwable> { withTimeout(10.seconds) { r.body.readSome(10) } })
                }
                val body = ByteChannel()
                val call = launch { runCatching { p.client.request(http3Request("POST", "server.test", "/up") { this.body = body }) } }
                body.writeFully(ByteArray(10) { 2 })
                body.flush()
                partRead.await()
                p.client.close(Http3ErrorCode.INTERNAL_ERROR, "gone")
                val e = serverSaw.await()
                assertTrue(causes(e).any { it is Http3Exception || it is QuicException.ConnectionLost }, "$e")
                call.cancel()
            }
        }

    @Test fun finAfterAllDataIsTheEnd() =
        h3Test {
            H3Pair.open().useScoped { p ->
                launch {
                    val r = p.server.acceptRequest()
                    val w = r.respond(200)
                    w.output.writeFully(ByteArray(10) { 1 })
                    w.finish()
                }
                val resp = p.client.request(get("/x"))
                assertEquals(10, resp.body.readSome(10))
                assertTrue(resp.body.readAvailable(ByteArray(4), 0, 4) < 0, "EOF after FIN")
                assertTrue(resp.body.isClosedForRead)
                assertEquals(null, resp.body.closedCause)
            }
        }
}
