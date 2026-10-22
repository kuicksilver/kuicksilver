// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.cancel
import io.ktor.utils.io.readFully
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import kotlinx.coroutines.async
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/** The STOP_SENDING code the peer sent on [st]: waits until our output is closed by it. */
private suspend fun stoppedCode(st: QuicStream): Long {
    withTimeout(5.seconds) { while (!st.output.isClosedForWrite) yield() }
    val stop =
        generateSequence(st.output.closedCause) { it.cause }.filterIsInstance<QuicException.StreamError.Stopped>().firstOrNull()
    return stop?.code ?: throw AssertionError("output closed without STOP_SENDING: ${st.output.closedCause}")
}

/**
 * An application that cancels a body it no longer wants releases the stream at once with STOP_SENDING, not only when
 * the peer happens to send more: a peer that pauses would otherwise keep the stream and its flow-control credit.
 */
class BodyCancelTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun cancelledRequestBodyStopsTheStreamAtOnce() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                val post = listOf(":method" to "POST", ":scheme" to "https", ":authority" to "server.test", ":path" to "/")
                st.output.writeFully(raw.headers(st.id, post) + raw.data("part".encodeToByteArray()))
                st.output.flush() // and then nothing more: the client pauses
                val req = withTimeout(5.seconds) { server.acceptRequest() }
                withTimeout(5.seconds) { req.body.readFully(ByteArray(4)) } // the pump has handed over all it got
                req.body.cancel()
                assertEquals(Http3ErrorCode.NO_ERROR, stoppedCode(st))
            }
        }

    @Test fun cancelledResponseBodyStopsTheStreamAtOnce() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val raw = RawPeer(s)
                raw.openControl()
                val client = Http3Connection.client(c)
                val response = async { client.request(http3Request("GET", "server.test", "/")) }
                val st = withTimeout(5.seconds) { s.acceptBidi() }
                st.output.writeFully(raw.headers(st.id, listOf(":status" to "200")) + raw.data("part".encodeToByteArray()))
                st.output.flush() // and then nothing more: the server pauses
                val body = withTimeout(5.seconds) { response.await() }.body
                withTimeout(5.seconds) { body.readFully(ByteArray(4)) } // the pump has handed over all it got
                body.cancel()
                assertEquals(Http3ErrorCode.REQUEST_CANCELLED, stoppedCode(st))
            }
        }
}
