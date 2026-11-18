// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.qlog

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.CollectingHandler
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.wire.AckFrameView
import io.kuicksilver.quic.wire.FrameDecoder
import io.kuicksilver.quic.wire.FrameEncoder
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.quic.wire.WireReader
import io.kuicksilver.quic.wire.WireWriter
import io.kuicksilver.tls.TlsRole
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

/**
 * The frames of `transport:packet_sent` and `packet_received` (draft-ietf-quic-qlog-quic-events-04 section 8.11): every
 * frame type we send or receive, as read from a payload we built and as recorded on the receive path, checked against
 * the draft's definitions ([QuicQlogSchema]), with a negative control for each type: the checker refuses the frame without
 * each required member, or with a value its type does not allow.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class QlogFramesTest {
    private val token = byteArrayOf(0xde.toByte(), 0xad.toByte(), 0xbe.toByte(), 0xef.toByte(), 0x5e, 0xc2.toByte(), 0xe7.toByte())
    private val cid = byteArrayOf(0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11)
    private val resetToken = ByteArray(16) { (0xa0 + it).toByte() }

    /** One frame of each type, written by [FrameEncoder]; the type's qlog name and what its object must hold. */
    private class Case(
        val type: String,
        val write: (WireWriter, PacketBuffer) -> Unit,
        val expect: Map<String, Any?> = emptyMap(),
        /** Values its type does not allow, for types with few required members: each must be refused. */
        val bad: List<Pair<String, Any?>> = emptyList(),
    )

    private val cases =
        listOf(
            Case("padding", { w, _ -> FrameEncoder.padding(w, 5) }, mapOf("payload_length" to 5.0)),
            Case("ping", { w, _ -> FrameEncoder.ping(w) }, bad = listOf("length" to -1.0, "extra" to 1.0)),
            Case(
                "ack",
                { w, _ -> FrameEncoder.ack(w, longArrayOf(9, 12, 3, 3, 0, 1), 3, 1000, longArrayOf(4, 5, 6)) },
                mapOf(
                    "ack_delay" to 8.0, // 1000 x 2^3 microseconds
                    "acked_ranges" to listOf(listOf(9.0, 12.0), listOf(3.0), listOf(0.0, 1.0)),
                    "ect0" to 4.0,
                    "ect1" to 5.0,
                    "ce" to 6.0,
                ),
                bad =
                    listOf(
                        "acked_ranges" to listOf(listOf(5.0, 3.0)),
                        "acked_ranges" to emptyList<Any>(),
                        "ack_delay" to -1.0,
                        "ce" to -1.0,
                    ),
            ),
            Case(
                "reset_stream",
                { w, _ -> FrameEncoder.resetStream(w, 4, 7, 100) },
                mapOf(
                    "stream_id" to 4.0,
                    "error_code" to 7.0,
                    "final_size" to 100.0,
                ),
            ),
            Case("stop_sending", { w, _ -> FrameEncoder.stopSending(w, 8, 0x10c) }, mapOf("stream_id" to 8.0, "error_code" to 268.0)),
            Case(
                "reset_stream_at",
                { w, _ -> FrameEncoder.resetStreamAt(w, 4, 0x52e4a40fa8dbL, 100, 40) },
                // a WebTransport application error code is above 2^32: the extension string of $ApplicationError
                mapOf(
                    "stream_id" to 4.0,
                    "error_code" to "application_error_0x52e4a40fa8db",
                    "final_size" to 100.0,
                    "reliable_size" to 40.0,
                ),
            ),
            Case("crypto", { w, b -> FrameEncoder.crypto(w, 1000, b, 0, 3) }, mapOf("offset" to 1000.0, "length" to 3.0)),
            Case(
                "new_token",
                { w, _ -> FrameEncoder.newToken(w, token) },
                mapOf("token" to mapOf("type" to "resumption", "raw" to mapOf("length" to 7.0))),
            ),
            Case(
                "stream",
                { w, b -> FrameEncoder.stream(w, 4, 0, b, 0, 3, fin = false, withLength = true) },
                mapOf(
                    "stream_id" to 4.0,
                    "offset" to 0.0,
                    "length" to 3.0,
                ),
            ),
            Case(
                "stream",
                { w, b -> FrameEncoder.stream(w, 8, 70000, b, 0, 3, fin = true, withLength = false) },
                mapOf("stream_id" to 8.0, "offset" to 70000.0, "length" to 3.0, "fin" to true),
                bad = listOf("fin" to false),
            ),
            Case("max_data", { w, _ -> FrameEncoder.maxData(w, 1L shl 20) }, mapOf("maximum" to 1048576.0)),
            Case("max_stream_data", { w, _ -> FrameEncoder.maxStreamData(w, 4, 65536) }, mapOf("stream_id" to 4.0, "maximum" to 65536.0)),
            Case(
                "max_streams",
                { w, _ -> FrameEncoder.maxStreams(w, true, 100) },
                mapOf(
                    "stream_type" to "bidirectional",
                    "maximum" to 100.0,
                ),
                listOf("stream_type" to "both"),
            ),
            Case(
                "max_streams",
                { w, _ -> FrameEncoder.maxStreams(w, false, 3) },
                mapOf("stream_type" to "unidirectional", "maximum" to 3.0),
            ),
            Case("data_blocked", { w, _ -> FrameEncoder.dataBlocked(w, 500) }, mapOf("limit" to 500.0)),
            Case("stream_data_blocked", { w, _ -> FrameEncoder.streamDataBlocked(w, 4, 9) }, mapOf("stream_id" to 4.0, "limit" to 9.0)),
            Case(
                "streams_blocked",
                { w, _ -> FrameEncoder.streamsBlocked(w, false, 3) },
                mapOf(
                    "stream_type" to "unidirectional",
                    "limit" to 3.0,
                ),
            ),
            Case(
                "new_connection_id",
                { w, _ -> FrameEncoder.newConnectionId(w, 2, 1, cid, resetToken) },
                mapOf(
                    "sequence_number" to 2.0,
                    "retire_prior_to" to 1.0,
                    "connection_id_length" to 8.0,
                    "connection_id" to "0a0b0c0d0e0f1011",
                ),
                bad = listOf("connection_id" to "not hex", "sequence_number" to 4294967296.0),
            ),
            Case("retire_connection_id", { w, _ -> FrameEncoder.retireConnectionId(w, 3) }, mapOf("sequence_number" to 3.0)),
            Case(
                "path_challenge",
                { w, _ -> FrameEncoder.pathChallenge(w, 0x0102030405060708L) },
                mapOf("data" to "0102030405060708"),
                listOf("data" to "0102"),
            ),
            Case(
                "path_response",
                { w, _ -> FrameEncoder.pathResponse(w, -1L) },
                mapOf("data" to "ffffffffffffffff"),
                listOf("data" to 5.0),
            ),
            Case(
                "connection_close",
                { w, _ -> FrameEncoder.connectionClose(w, false, 0x0a, 0x08, "bad \"stream\"".encodeToByteArray()) },
                mapOf(
                    "error_space" to "transport",
                    "error_code" to "protocol_violation",
                    "error_code_value" to 10.0,
                    "reason" to "bad \"stream\"",
                    "trigger_frame_type" to "stream",
                ),
                bad = listOf("error_space" to "network", "error_code" to "made_up_error"),
            ),
            Case(
                "connection_close",
                { w, _ -> FrameEncoder.connectionClose(w, false, 0x128, 0x06, ByteArray(0)) },
                // section 8.11.19 has no CryptoError: the code is in error_code_value alone
                mapOf("error_code" to null, "error_code_value" to 296.0, "trigger_frame_type" to "crypto"),
                bad = listOf("error_code" to "crypto_error_0x128", "error_code_value" to 1.5),
            ),
            Case(
                "connection_close",
                { w, _ -> FrameEncoder.connectionClose(w, true, 0x100, 0, "done".encodeToByteArray()) },
                mapOf("error_space" to "application", "error_code" to 256.0, "error_code_value" to 256.0, "reason" to "done"),
                bad = listOf("error_code" to -3.0),
            ),
            Case("handshake_done", { w, _ -> FrameEncoder.handshakeDone(w) }, bad = listOf("extra" to 1.0)),
            Case(
                "datagram",
                { w, _ -> FrameEncoder.datagram(w, byteArrayOf(1, 2, 3, 4), 0, 4) },
                mapOf("length" to 4.0),
                listOf("length" to -4.0),
            ),
        )

    private fun parse(out: CharSequence): List<Map<*, *>> = (StrictJson.parse("[$out]") as List<*>).map { it as Map<*, *> }

    /** The case's frame as our builder's payload, read by [QlogFrames.sent], and as received, recorded by [QlogFrames.receiving]. */
    private fun bothWays(c: Case): Pair<String, String> {
        val data = PacketBuffer.of(byteArrayOf(0x61, 0x62, 0x63))
        val buf = PacketBuffer.allocate(256)
        try {
            val w = WireWriter(buf, 0, 256)
            c.write(w, data)
            val end = w.pos
            val q = QlogFrames()
            q.sent(buf, 0, end, PacketType.OneRtt, 3)
            assertTrue(q.ready, "${c.type}: the sent payload was read")
            val sent = q.out.toString()
            q.abandon()
            val handler = CollectingHandler()
            FrameDecoder.decode(WireReader(buf, 0, end), PacketType.OneRtt, q.receiving(handler, 3), AckFrameView())
            assertEquals(1, handler.frames.size, "${c.type}: the connection's own handler got the frame")
            return sent to q.out.toString()
        } finally {
            buf.close()
            data.close()
        }
    }

    @Test fun everyFrameTypeIsTypedSentAndReceived() {
        val seen = HashSet<String>()
        for (c in cases) {
            val (sent, received) = bothWays(c)
            assertEquals(sent, received, "${c.type}: the same object either way")
            val f = parse(sent).single()
            QuicQlogSchema.frame(f)
            assertEquals(c.type, f["frame_type"])
            for ((k, v) in c.expect) assertEquals(v, f[k], "${c.type}.$k in $f")
            seen += c.type
        }
        assertEquals(QuicQlogSchema.frameTypes, seen, "a case for every frame type section 8.11 and our extensions define")
    }

    /** Negative controls, one or more per frame type: without a required member, or with a value its type does not allow. */
    @Test fun negative_eachFrameTypeRefusesWhatTheDraftDoesNot() {
        for (c in cases) {
            val f = parse(bothWays(c).first).single()
            val broken =
                QuicQlogSchema.required[c.type].orEmpty().map { k -> f.filterKeys { it != k } } +
                    c.bad.map { (k, v) -> f + (k to v) }
            assertTrue(broken.isNotEmpty(), "${c.type} has no negative control")
            for (b in broken) assertTrue(runCatching { QuicQlogSchema.frame(b) }.isFailure, "${c.type}: accepted $b")
        }
    }

    /**
     * Never in a trace: a NEW_TOKEN's token (it lets its holder skip address validation) and the stateless reset token of a
     * NEW_CONNECTION_ID (whoever holds it can end the connection); payloads of STREAM, CRYPTO and DATAGRAM frames.
     */
    @Test fun negative_tokensAndPayloadsNeverReachTheTrace() {
        val all = cases.joinToString { bothWays(it).first + bothWays(it).second }
        assertFalse("deadbeef5ec2e7" in all, "the NEW_TOKEN token")
        assertFalse(resetToken.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') } in all, "the reset token")
        assertFalse("abc" in all || "616263" in all, "a payload")
        assertTrue("0a0b0c0d0e0f1011" in all, "the connection ID itself is required (section 8.11.15)")
    }

    /**
     * The send and receive paths record into recorders of their own: a packet built while a received one is being decoded
     * (a frame handler that sends at once) leaves both packets' frames whole.
     */
    @Test fun aPacketSentWhileOneIsReceivedKeepsBothFrameLists() {
        val w = QlogWriter(QlogLifecycleTest.Traces(), 1L shl 20, io.kuicksilver.quic.TimeMark(0), TlsRole.Client, "0a0b", false)
        val received = PacketBuffer.allocate(64)
        val sent = PacketBuffer.allocate(64)
        val data = PacketBuffer.of(byteArrayOf(1, 2, 3))
        try {
            val rw = WireWriter(received, 0, 64)
            FrameEncoder.ping(rw)
            FrameEncoder.maxData(rw, 77)
            val sw = WireWriter(sent, 0, 64)
            FrameEncoder.stream(sw, 4, 0, data, 0, 3, fin = false, withLength = true)
            val inner = CollectingHandler()
            val handler =
                object : io.kuicksilver.quic.wire.FrameHandler by inner {
                    override fun ping() {
                        inner.ping()
                        w.sentFrames.sent(sent, 0, sw.pos, PacketType.OneRtt, 3)
                    }
                }
            FrameDecoder.decode(WireReader(received, 0, rw.pos), PacketType.OneRtt, w.receivedFrames.receiving(handler, 3), AckFrameView())
            assertEquals(listOf("ping", "max_data"), parse(w.receivedFrames.out).map { it["frame_type"] })
            assertEquals(listOf("stream"), parse(w.sentFrames.out).map { it["frame_type"] })
        } finally {
            received.close()
            sent.close()
            data.close()
        }
    }

    /** A payload the decoder refuses leaves no frames rather than a partial list. */
    @Test fun negative_aPayloadThatDoesNotDecodeLeavesNoFrames() {
        val buf = PacketBuffer.of(byteArrayOf(0x01, 0x40)) // PING, then a truncated varint frame type
        try {
            val q = QlogFrames()
            q.sent(buf, 0, 2, PacketType.OneRtt, 3)
            assertFalse(q.ready)
            assertEquals(0, q.out.length)
        } finally {
            buf.close()
        }
    }

    /** Collects every record of every trace in memory. */
    private class MemorySink : QlogSink {
        val traces = LinkedHashMap<String, ArrayList<String>>()

        override fun open(
            odcidHex: String,
            role: TlsRole,
        ): QlogTrace {
            val l = ArrayList<String>()
            traces[role.name.lowercase()] = l
            return object : QlogTrace {
                override fun write(record: String) {
                    l += record
                }

                override fun close() {}
            }
        }
    }

    /** A real exchange: every packet_sent and packet_received at both ends has typed frames that follow the draft. */
    @Test fun aRealExchangeLogsTypedFramesBothWays() {
        val sink = MemorySink()
        val p = CorePair(clientQuic = quicConfig { qlog = sink }, serverQuic = quicConfig { qlog = sink })
        try {
            assertTrue(p.handshake())
            val id = p.client.openStream(true, StreamPriority.Default)
            p.client.writeStream(id, ByteArray(5000), 0, 5000, true)
            val buf = ByteArray(8192)
            var read = 0
            assertTrue(
                p.runUntil(limit = 5_000.milliseconds) {
                    while (true) {
                        val n = p.server!!.readStream(id, buf, 0, buf.size)
                        if (n > 0) read += n else break
                    }
                    read == 5000
                },
            )
            p.client.close(0, "bye", p.now)
            p.runUntil(limit = 1_000.milliseconds) { false }
            for ((role, records) in sink.traces) {
                val types = HashMap<String, HashSet<String>>()
                for (r in records.drop(1)) {
                    val e = StrictJson.parse(r.substring(1, r.length - 1)) as Map<*, *>
                    val name = e["name"] as String
                    // every transport event, not only the packets (connectivity, recovery)
                    QuicQlogSchema.event(name, e["data"] as Map<*, *>)
                    if (name != "transport:packet_sent" && name != "transport:packet_received") continue
                    val frames = QuicQlogSchema.packet(e["data"] as Map<*, *>)
                    types.getOrPut(name) { HashSet() } += frames.map { it["frame_type"] as String }
                }
                for (name in listOf("transport:packet_sent", "transport:packet_received")) {
                    val t = types[name].orEmpty()
                    assertTrue(t.containsAll(listOf("crypto", "ack")), "$role $name: $t")
                }
                assertTrue(types.values.flatten().contains("stream"), "$role: $types")
                assertTrue(types.values.flatten().contains("handshake_done"), "$role: $types")
                assertTrue(types.values.flatten().contains("connection_close"), "$role: $types")
            }
        } finally {
            p.close()
        }
    }
}
