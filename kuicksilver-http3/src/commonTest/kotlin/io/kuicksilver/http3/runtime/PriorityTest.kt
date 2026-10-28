// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3ServerRequest
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.ControlFrames
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
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

    /**
     * RFC 8941 section 4.2: a Priority Field Value that is not a valid dictionary is ignored as a whole, so the frame
     * carries no parameter, and RFC 9218 section 7: "A PRIORITY_UPDATE frame communicates a complete set of all priority
     * parameters [...] Omitting a priority parameter is a signal to use its default value": the defaults, not the earlier
     * u=5. The connection stays open (the section 7 connection error is a MAY we do not take).
     */
    @Test fun invalidPriorityUpdateValueMeansDefaults() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val id = raw.request(GET + ("priority" to "u=5"))
                val r = server.acceptRequest()
                assertEquals(StreamPriority(5), r.priority.value)
                raw.priorityUpdate(id, "u=1, i,")
                withTimeout(5.seconds) { r.priority.first { it == StreamPriority.Default } }
                assertFalse(server.closed.isCompleted)
            }
        }

    /** RFC 8941 section 4.2: field lines of the same name are combined (RFC 9110 section 5.3) before parsing. */
    @Test fun priorityFieldLinesAreCombined() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                raw.request(GET + ("priority" to "u=1") + ("priority" to "i"))
                assertEquals(StreamPriority(1, true), server.acceptRequest().priority.value)
                raw.request(GET + ("priority" to "u=1") + ("priority" to "i=?2"))
                assertEquals(StreamPriority.Default, server.acceptRequest().priority.value)
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

    /**
     * RFC 9218 section 7: a PRIORITY_UPDATE for a request stream the transport opened (stream 8 arrived first, so 0 and
     * 4 exist) whose HEADERS have not come yet is kept and applied once they do, not taken for a finished request.
     */
    @Test fun earlyPriorityUpdateForReorderedStreamApplies() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val streams = (0 until 3).map { c.openBidi() }
                streams[2].output.writeFully(raw.headers(streams[2].id, GET))
                streams[2].output.flushAndClose()
                val r8 = withTimeout(5.seconds) { server.acceptRequest() }
                assertEquals(8L, r8.streamId)
                raw.priorityUpdate(4, "u=0")
                raw.priorityUpdate(8, "u=1") // the control stream is read in order: once 8 has it, the update for 4 was seen
                withTimeout(5.seconds) { r8.priority.first { it == u1 } }
                streams[1].output.writeFully(raw.headers(streams[1].id, GET + ("priority" to "u=6")))
                streams[1].output.flushAndClose()
                val r4 = withTimeout(5.seconds) { server.acceptRequest() }
                assertEquals(4L, r4.streamId)
                assertEquals(StreamPriority(0), r4.priority.value)
            }
        }

    /** RFC 9218 section 7.2: a PRIORITY_UPDATE naming a stream beyond the limit we granted (MAX_STREAMS) is H3_ID_ERROR. */
    @Test fun priorityUpdateBeyondStreamLimitIsIdError() =
        h3Test {
            QuicPair.open(serverQuic = quicConfig { maxBidiStreams = 10 }).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                raw.priorityUpdate(36, "u=1") // the tenth stream: within the limit, kept
                raw.request()
                withTimeout(5.seconds) { server.acceptRequest() }.respond(204).finish() // the connection lives on
                peerMayHaveClosed { raw.priorityUpdate(40, "u=1") } // the eleventh
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

    /**
     * Our control and QPACK streams go before every request stream whatever the peer's signal: a client that asks u=0
     * (non-incremental, stream 0 has the lowest id) for a large response must not hold back the QPACK insert its trailers
     * need behind the whole body. The server's packets are held while the body and then the trailers are queued, so what
     * it sends first after that is the scheduler's choice alone.
     */
    @Test fun criticalStreamsGoBeforeAnUrgentResponse() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, http3Settings { enableQpackDynamicTable() })
                val raw = RawPeer(c)
                raw.openControl(listOf(SettingsId.QPACK_MAX_TABLE_CAPACITY to 4096L, SettingsId.QPACK_BLOCKED_STREAMS to 16L))
                // (encoder stream bytes so far, connection bytes received when they arrived)
                val encoder = MutableStateFlow(0L to 0L)
                launch {
                    runCatching {
                        while (true) {
                            val st = c.acceptStream()
                            if (st.readVarInt() != StreamType.QPACK_ENCODER) continue
                            val b = ByteArray(256)
                            while (true) {
                                val n = st.input.readAvailable(b, 0, b.size)
                                if (n < 0) break
                                encoder.update { (total, _) -> total + n to c.stats.bytesReceived }
                            }
                        }
                    }
                }
                raw.request(GET + ("priority" to "u=0"))
                val r = server.acceptRequest()
                withTimeout(5.seconds) { server.peerSettings.filterNotNull().first() }
                // Set Dynamic Table Capacity follows the client's SETTINGS: in before the test begins
                val capacitySent = withTimeout(5.seconds) { encoder.first { it.first > 0 } }.first
                // a 40 ms round trip paces the flights, so the reader below sees the insert before the next flights land
                q.net.delay = 20.milliseconds
                val serverAddress = InetSocketAddress("10.0.0.2", 443)
                val held = Channel<Pair<InetSocketAddress, ByteArray>>(Channel.UNLIMITED)
                q.net.drop = { from, to, b -> from == serverAddress && held.trySend(to to b).isSuccess }
                val body = 384 * 1024 // within the client's stream and connection windows: nothing but the scheduler stops it
                val w = r.respond(200)
                w.output.writeFully(ByteArray(body))
                w.output.flush()
                w.finish(Http3Headers.of("x-probe" to "trailer")) // a new field: the encoder stream gets an insert
                q.net.drop = null
                val base = c.stats.bytesReceived
                held.close()
                for ((to, b) in held) q.net.deliver(serverAddress, to, b)
                val before = withTimeout(10.seconds) { encoder.first { it.first > capacitySent } }.second - base
                assertTrue(before < body / 2, "$before bytes reached the client before the QPACK insert")
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

    /** A response field on an unsignalled tunnel merges into its local schedule: `u=1` keeps the incremental default. */
    @Test fun responseFieldKeepsTunnelIncremental() =
        h3Test {
            H3Pair.open(serverSettings = io.kuicksilver.http3.http3Settings { enableConnectProtocol = true }).useScoped { p ->
                val accepted = kotlinx.coroutines.CompletableDeferred<Http3ServerRequest>()
                launch {
                    val r = p.server.acceptRequest()
                    r.acceptConnect(
                        io.kuicksilver.http3.Http3Headers
                            .of("priority" to "u=1"),
                    )
                    accepted.complete(r)
                }
                p.client.connect(connectReq(), "echo")
                val r = withTimeout(5.seconds) { accepted.await() }
                assertEquals(StreamPriority(1, true), (r as ServerRequestImpl).stream.priority)
            }
        }
}
