// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3ServerRequest
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.ControlFrames
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.StreamPriority
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

class PriorityTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private suspend fun RawPeer.priorityUpdate(
        id: Long,
        value: String,
    ) {
        control.output.writeFully(frame(FrameType.PRIORITY_UPDATE_REQUEST, ControlFrames.priorityUpdatePayload(id, value)))
        control.output.flush()
    }

    private suspend fun RawPeer.request(fields: List<Pair<String, String>> = GET): Long {
        val st = quic.openBidi()
        st.output.writeFully(headers(st.id, fields))
        st.output.flushAndClose()
        return st.id
    }

    private val u1 = StreamPriority(1, false)

    @Test fun headerAppliedOnServer() =
        h3Test {
            H3Pair.open().useScoped { p ->
                launch {
                    p.client.request(
                        http3Request("GET", "server.test", "/") {
                            priority = StreamPriority(1, true)
                        },
                    )
                }
                val r = p.server.acceptRequest()
                assertEquals(StreamPriority(1, true), r.priority.value)
                assertEquals(StreamPriority(1, true), (r as ServerRequestImpl).stream.priority)
                r.respond(200).finish()
            }
        }

    @Test fun priorityUpdateOverridesHeader() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val id = raw.request(GET + ("priority" to "u=5"))
                val r = server.acceptRequest()
                assertEquals(StreamPriority(5), r.priority.value)
                raw.priorityUpdate(id, "u=1")
                withTimeout(5.seconds) { r.priority.first { it == u1 } }
                assertEquals(u1, (r as ServerRequestImpl).stream.priority)
            }
        }

    @Test fun earlyPriorityUpdateRemembered() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                raw.priorityUpdate(8, "u=1")
                delay(100)
                repeat(3) { raw.request(GET + ("priority" to "u=6")) } // streams 0, 4, 8: the header of 8 is ignored, the early update wins
                val got = (0 until 3).map { server.acceptRequest() }.associate { it.streamId to it.priority.value }
                assertEquals(mapOf(0L to StreamPriority(6), 4L to StreamPriority(6), 8L to u1), got)
            }
        }

    @Test fun negative_priorityUpdateBufferCap() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                for (k in 1..40) raw.priorityUpdate(4L * k, "u=1") // 40 updates for streams not open yet: 32 are kept
                delay(200)
                repeat(41) { raw.request() }
                val got = (0 until 41).map { server.acceptRequest() }.associate { it.streamId to it.priority.value }
                assertEquals((1..32).map { 4L * it }.toSet(), got.filterValues { it == u1 }.keys)
                assertEquals(StreamPriority.Default, got[4L * 33])
            }
        }

    @Test fun oversizedPriorityUpdateIgnored() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                raw.priorityUpdate(0, "u=1, x=\"" + "a".repeat(300) + "\"")
                delay(100)
                raw.request()
                assertEquals(StreamPriority.Default, server.acceptRequest().priority.value)
            }
        }

    @Test fun serverPriorityWins() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val id = raw.request(GET + ("priority" to "u=5"))
                val r = server.acceptRequest()
                r.respond(200, priority = StreamPriority(0))
                raw.priorityUpdate(id, "u=6")
                withTimeout(5.seconds) { r.priority.first { it == StreamPriority(6) } }
                assertEquals(StreamPriority(0), (r as ServerRequestImpl).stream.priority)
            }
        }

    @Test fun clientRejectsPriorityUpdate() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                Http3Connection.client(c)
                val raw = RawPeer(s)
                raw.openControl()
                peerMayHaveClosed { raw.priorityUpdate(0, "u=1") }
                assertEquals(Http3ErrorCode.FRAME_UNEXPECTED, peerSawClose(s))
            }
        }

    @Test fun badElementIdIsIdError() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                peerMayHaveClosed { raw.priorityUpdate(2, "u=1") } // a unidirectional stream id
                assertEquals(Http3ErrorCode.ID_ERROR, peerSawClose(c))
            }
        }

    @Test fun clientUpdatePriorityReachesServer() =
        h3Test {
            H3Pair.open().useScoped { p ->
                var served: Http3ServerRequest? = null
                launch {
                    val r = p.server.acceptRequest()
                    served = r
                    r.respond(200).output.writeFully(ByteArray(10))
                }
                val resp = p.client.request(get())
                resp.updatePriority(StreamPriority(2, true))
                withTimeout(5.seconds) { while (served?.priority?.value != StreamPriority(2, true)) delay(10) }
                resp.cancel()
            }
        }

    /** A `priority` field given as a header schedules the client's own stream too, and goes out once. */
    @Test fun headerFieldDrivesClientScheduling() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val seen = kotlinx.coroutines.CompletableDeferred<List<String>>()
                launch {
                    val r = p.server.acceptRequest()
                    seen.complete(r.headers.getAll("priority"))
                    r.respond(200).finish()
                }
                val resp =
                    p.client.request(
                        http3Request("GET", "server.test", "/") {
                            headers =
                                io.kuicksilver.http3.Http3Headers
                                    .of("priority" to "u=1, i")
                        },
                    )
                assertEquals(StreamPriority(1, true), (resp as ResponseImpl).stream.priority)
                assertEquals(listOf("u=1, i"), withTimeout(5.seconds) { seen.await() })
            }
        }

    /** RFC 9218 section 8: the response's `priority` field merges into the client's signal for our own scheduling. */
    @Test fun responseFieldMergesIntoServerScheduling() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val id = raw.request(GET + ("priority" to "u=5, i"))
                val r = server.acceptRequest()
                r.respond(
                    200,
                    io.kuicksilver.http3.Http3Headers
                        .of("priority" to "u=1"),
                )
                assertEquals(StreamPriority(1, true), (r as ServerRequestImpl).stream.priority)
                raw.priorityUpdate(id, "u=6") // the server's choice stays, as with an explicit priority
                withTimeout(5.seconds) { r.priority.first { it == StreamPriority(6) } }
                assertEquals(StreamPriority(1, true), r.stream.priority)
                // an explicit argument is stronger than the field
                raw.request(GET + ("priority" to "u=5, i"))
                val r2 = server.acceptRequest()
                r2.respond(
                    200,
                    io.kuicksilver.http3.Http3Headers
                        .of("priority" to "u=1"),
                    priority = StreamPriority(4),
                )
                assertEquals(StreamPriority(4), (r2 as ServerRequestImpl).stream.priority)
            }
        }

    /** RFC 9218 sections 10.1, 11: a tunnel without a signal shares bandwidth (incremental) on both sides. */
    @Test fun connectTunnelDefaultsToIncremental() =
        h3Test {
            H3Pair.open(serverSettings = io.kuicksilver.http3.http3Settings { enableConnectProtocol = true }).useScoped { p ->
                val plain = kotlinx.coroutines.CompletableDeferred<Http3ServerRequest>()
                val explicit = kotlinx.coroutines.CompletableDeferred<Http3ServerRequest>()
                launch {
                    for (d in listOf(plain, explicit)) {
                        val r = p.server.acceptRequest()
                        r.acceptConnect()
                        d.complete(r)
                    }
                }
                val tunnel = p.client.connect(connectReq(), "echo")
                assertEquals(StreamPriority(3, true), tunnel.priority)
                val r = withTimeout(5.seconds) { plain.await() }
                assertEquals(StreamPriority.Default, r.priority.value) // the client's signal is not rewritten
                assertEquals(StreamPriority(3, true), (r as ServerRequestImpl).stream.priority)
                val u2 =
                    p.client.connect(
                        http3Request("CONNECT", "server.test", "/chat") {
                            headers =
                                io.kuicksilver.http3.Http3Headers
                                    .of("priority" to "u=2")
                        },
                        "echo",
                    )
                assertEquals(StreamPriority(2, false), u2.priority)
                assertEquals(StreamPriority(2, false), (withTimeout(5.seconds) { explicit.await() } as ServerRequestImpl).stream.priority)
            }
        }
}
