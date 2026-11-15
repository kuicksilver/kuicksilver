// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.fuzz

import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.SettingId
import io.kuicksilver.http2.hpack.HpackEncoder
import java.io.ByteArrayOutputStream
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertNotNull

/**
 * The structured seeds of the HTTP/2 fuzz targets (`seed-*`, next to the kept reproducers `finding-*` and the first
 * hand-made inputs): conversations of a client with the server core (`connectionServer`) and of a server with the client
 * core (`connectionClient`) that reach every frame type, every setting, window shrinks and growth, CONTINUATION chains,
 * PING and SETTINGS floods, GOAWAY, RST_STREAM, Extended CONNECT (RFC 8441) and one protocol error each, under the modes
 * of [Mode] (limits, reading, clock, driver actions); their frames alone for `frames`, their field blocks for
 * `hpackDecode`, and field lists with table size changes for `hpackRoundTrip`. With `KUICKSILVER_FUZZ_SEEDS_OUT` set
 * (`tools/fuzz/gen-seeds.sh`) the seeds are written to that directory in Jazzer's `<Class>Inputs/<method>/` layout;
 * otherwise the committed seeds must match. [H2FuzzReachTest] checks what they reach.
 */
class H2SeedCorpusTest {
    @Test fun corpusMatchesGenerator() {
        val seeds = generate()
        val out = System.getenv("KUICKSILVER_FUZZ_SEEDS_OUT")
        if (out != null) {
            for ((path, bytes) in seeds) {
                File(out, path).apply {
                    parentFile.mkdirs()
                    writeBytes(bytes)
                }
            }
            return
        }
        for ((path, bytes) in seeds) {
            val committed = javaClass.getResourceAsStream(path)?.use { it.readBytes() }
            assertNotNull(committed, "seed $path is missing: run tools/fuzz/gen-seeds.sh")
            assertContentEquals(bytes, committed, "seed $path is stale: run tools/fuzz/gen-seeds.sh")
        }
    }

    private fun cat(vararg parts: ByteArray): ByteArray = ByteArrayOutputStream().also { o -> parts.forEach { o.write(it) } }.toByteArray()

    private fun settings(vararg kv: Pair<Int, Long>) =
        FrameEncoder.settings(
            kv
                .map {
                    it.first
                }.toIntArray(),
            kv.map { it.second }.toLongArray(),
        )

    private val ack = FrameEncoder.settingsAck()

    private fun mode(
        preset: Int = 0,
        connect: Boolean = false,
        drain: Mode.Drain = Mode.Drain.EVERY_PIECE,
        slow: Boolean = false,
        actions: Boolean = false,
        serverFirst: Boolean = false,
    ): Int =
        preset or (if (connect) 4 else 0) or (drain.ordinal shl 3) or (if (slow) 0x20 else 0) or (if (actions) 0x40 else 0) or
            (if (serverFirst) 0x80 else 0)

    private fun u32(v: Int) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    /** A client's frames: requests HPACK-encoded in order by one encoder (whose table follows [tableSize]). */
    private class Peer(
        tableSize: Int = 4_096,
    ) {
        val hpack = HpackEncoder(maxTableSize = tableSize)
        val blocks = mutableListOf<ByteArray>()

        fun block(fields: List<Pair<String, String>>): ByteArray = hpack.encode(fields).also { blocks += it }

        fun headers(
            id: Int,
            fields: List<Pair<String, String>>,
            endStream: Boolean = true,
        ) = FrameEncoder.headers(id, block(fields), endStream, true)
    }

    private fun get(
        path: String = "/",
        vararg extra: Pair<String, String>,
    ) = listOf(":method" to "GET", ":scheme" to "https", ":authority" to "example.com", ":path" to path) + extra

    private val connect =
        listOf(
            ":method" to "CONNECT",
            ":protocol" to "websocket",
            ":scheme" to "https",
            ":authority" to "example.com",
            ":path" to "/chat",
            "sec-websocket-version" to "13",
        )

    private fun data(
        id: Int,
        n: Int,
        end: Boolean = false,
        pad: Int = 0,
    ) = FrameEncoder.data(id, ByteArray(n) { 'a'.code.toByte() }, 0, n, end, pad)

    /** The split byte of a conversation that needs its own piece size (the others take turns of the default splits). */
    private val splitOf = HashMap<String, Int>()

    /** Client conversations for `connectionServer`, after the preface: name to (mode, frames, the peer's blocks). */
    private fun serverConversations(): Map<String, Triple<Int, ByteArray, List<ByteArray>>> {
        val all = LinkedHashMap<String, Triple<Int, ByteArray, List<ByteArray>>>()

        fun conv(
            name: String,
            mode: Int,
            peer: Peer = Peer(),
            split: Int? = null,
            build: (Peer) -> ByteArray,
        ) {
            val bytes = build(peer)
            all[name] = Triple(mode, bytes, peer.blocks.toList())
            split?.let { splitOf[name] = it }
        }
        conv("get-post-trailers", mode()) { p ->
            cat(
                settings(),
                ack,
                p.headers(1, get()),
                p.headers(
                    3,
                    listOf(
                        ":method" to "POST",
                        ":scheme" to "https",
                        ":authority" to "example.com",
                        ":path" to "/up",
                        "content-length" to "5",
                    ),
                    endStream = false,
                ),
                data(3, 2),
                data(3, 3, pad = 4),
                p.headers(5, get("/t"), endStream = false),
                data(5, 4),
                p.headers(5, listOf("x-sum" to "1")),
                FrameEncoder.windowUpdate(0, 1 shl 20),
                FrameEncoder.windowUpdate(1, 1 shl 16),
            )
        }
        conv("hpack-dynamic-table", mode(preset = 3)) { p ->
            cat(
                settings(SettingId.HEADER_TABLE_SIZE to 0),
                ack,
                p.headers(1, get("/a", "cookie" to "a=1", "x-custom" to "v")),
                p.headers(3, get("/a", "cookie" to "a=1", "x-custom" to "v")),
                p.headers(5, get("/b", "x-custom" to "w".repeat(200))),
            )
        }
        conv("continuation-chain", mode()) { p ->
            val b = p.block(get("/long", "x-a" to "1".repeat(40), "x-b" to "2".repeat(40)))
            cat(
                settings(),
                ack,
                FrameEncoder.headers(1, b.copyOfRange(0, 10), true, false),
                FrameEncoder.continuation(1, b.copyOfRange(10, 50), false),
                FrameEncoder.continuation(1, b.copyOfRange(50, b.size), true),
                FrameEncoder.ping(false, 7),
            )
        }
        for (preset in listOf(0, 1)) {
            conv("continuation-flood-p$preset", mode(preset = preset)) { p ->
                cat(
                    settings(),
                    ack,
                    FrameEncoder.headers(1, p.block(get()), true, false),
                    *Array(10) { FrameEncoder.continuation(1, ByteArray(0), false) },
                )
            }
        }
        conv("ping-answered", mode(actions = true)) {
            cat(settings(), ack, *Array(6) { i -> FrameEncoder.ping(false, i.toLong()) }, FrameEncoder.ping(true, 1))
        }
        for (preset in listOf(0, 1)) {
            conv("ping-flood-unread-p$preset", mode(preset = preset, drain = Mode.Drain.AT_THE_END)) {
                cat(settings(), ack, *Array(80) { i -> FrameEncoder.ping(false, i.toLong()) })
            }
            conv("settings-flood-unread-p$preset", mode(preset = preset, drain = Mode.Drain.AT_THE_END)) {
                cat(settings(), ack, *Array(80) { i -> settings(SettingId.INITIAL_WINDOW_SIZE to 1L + (i and 1)) })
            }
        }
        conv("settings-every-id", mode(connect = true)) { p ->
            cat(
                settings(
                    SettingId.HEADER_TABLE_SIZE to 0,
                    SettingId.HEADER_TABLE_SIZE to 4_096,
                    SettingId.ENABLE_PUSH to 0,
                    SettingId.MAX_CONCURRENT_STREAMS to 10,
                    SettingId.INITIAL_WINDOW_SIZE to 1_000,
                    SettingId.MAX_FRAME_SIZE to 20_000,
                    SettingId.MAX_HEADER_LIST_SIZE to 8_000,
                    SettingId.ENABLE_CONNECT_PROTOCOL to 1,
                    SettingId.NO_RFC7540_PRIORITIES to 1,
                    0x99 to 5,
                ),
                ack,
                p.headers(1, get()),
            )
        }
        for (drain in listOf(Mode.Drain.EVERY_PIECE, Mode.Drain.SHORT_READS, Mode.Drain.EVERY_FOURTH)) {
            conv("window-shrink-grow-${drain.name.lowercase()}", mode(drain = drain)) { p ->
                cat(
                    settings(SettingId.INITIAL_WINDOW_SIZE to 30_000),
                    ack,
                    p.headers(1, get()),
                    p.headers(3, get("/2")),
                    settings(SettingId.INITIAL_WINDOW_SIZE to 100),
                    FrameEncoder.windowUpdate(1, 50),
                    FrameEncoder.windowUpdate(3, 5_000),
                    settings(SettingId.INITIAL_WINDOW_SIZE to 0),
                    FrameEncoder.windowUpdate(0, 100_000),
                    settings(SettingId.INITIAL_WINDOW_SIZE to 70_000),
                    FrameEncoder.windowUpdate(1, 1),
                    FrameEncoder.windowUpdate(3, 1),
                    settings(SettingId.INITIAL_WINDOW_SIZE to 65_535),
                )
            }
        }
        conv("window-dribble", mode(drain = Mode.Drain.SHORT_READS)) { p ->
            cat(settings(SettingId.INITIAL_WINDOW_SIZE to 0), ack, p.headers(1, get()), *Array(40) { FrameEncoder.windowUpdate(1, 1) })
        }
        conv("window-errors", mode()) { p ->
            cat(
                settings(),
                ack,
                p.headers(1, get()),
                FrameEncoder.windowUpdate(1, 0x7fff_ffff), // the stream window above 2^31 - 1: FLOW_CONTROL_ERROR on it
                p.headers(3, get()),
                FrameEncoder.windowUpdate(3, 0), // WINDOW_UPDATE of 0: PROTOCOL_ERROR on it
                FrameEncoder.windowUpdate(0, 0x7fff_ffff), // the connection window above 2^31 - 1
            )
        }
        conv("receive-window-overrun", mode(preset = 2), Peer(tableSize = 0)) { p ->
            cat(
                settings(),
                ack,
                p.headers(1, get(), endStream = false),
                data(1, 100),
                p.headers(3, get(), endStream = false),
                *Array(5) {
                    data(3, 16_000)
                },
            )
        }
        conv("goaway-then-requests", mode(actions = true)) { p ->
            cat(
                settings(),
                ack,
                p.headers(1, get()),
                FrameEncoder.goAway(1, 0, "bye".encodeToByteArray()),
                p.headers(3, get()),
                FrameEncoder.ping(false, 1),
            )
        }
        conv("rst-after-requests", mode(drain = Mode.Drain.SHORT_READS)) { p ->
            cat(
                settings(SettingId.INITIAL_WINDOW_SIZE to 10),
                ack,
                p.headers(1, get()),
                p.headers(3, get("/x")),
                FrameEncoder.rstStream(1, Http2ErrorCode.CANCEL.code),
                FrameEncoder.windowUpdate(3, 1_000),
                FrameEncoder.rstStream(3, Http2ErrorCode.REFUSED_STREAM.code),
                data(3, 1),
            )
        }
        conv("extended-connect", mode(connect = true)) { p ->
            cat(settings(), ack, p.headers(1, connect, endStream = false), data(1, 20), data(1, 0, end = true))
        }
        conv("extended-connect-not-offered", mode()) { p -> cat(settings(), ack, p.headers(1, connect, endStream = false)) }
        conv("malformed-requests", mode(actions = true)) { p ->
            cat(
                settings(),
                ack,
                p.headers(1, get("/", "Upper" to "x")),
                p.headers(3, listOf(":method" to "GET", ":scheme" to "https", ":authority" to "a")),
                p.headers(5, get("/", "connection" to "close")),
                p.headers(7, get("/", "content-length" to "3")),
                FrameEncoder.headers(9, ByteArray(0), true, true),
                p.headers(11, get(), endStream = false),
                data(11, 2, end = true),
            )
        }
        conv("too-large-431", mode(preset = 1)) { p -> cat(settings(), ack, p.headers(1, get("/", "x-big" to "v".repeat(300)))) }
        conv(
            "empty-data-flood",
            mode(preset = 1),
        ) { p -> cat(settings(), ack, p.headers(1, get(), endStream = false), *Array(10) { data(1, 0) }) }
        conv("priority-flood", mode(preset = 1)) {
            cat(
                settings(),
                ack,
                *Array(20) { i -> FrameEncoder.priority(1 + 2 * i, 3 + 2 * i) },
                *Array(10) { i -> FrameEncoder.priorityUpdate(1 + 2 * i, "u=${i % 8}, i") },
            )
        }
        conv("priority-update-and-unknown", mode(), split = 255) { p ->
            cat(
                settings(),
                ack,
                FrameEncoder.priorityUpdate(3, "u=1"),
                p.headers(1, get(), endStream = false),
                p.headers(3, get()),
                FrameEncoder.priorityUpdate(1, "u=0"),
                FrameEncoder.raw(0xfa, 0xff, 1, ByteArray(5)),
                FrameEncoder.altSvc(0, "o", "h3=\":443\""),
                FrameEncoder.priority(1, 0, 200),
                data(1, 1, end = true),
            )
        }
        conv(
            "refused-streams",
            mode(preset = 1),
        ) { p -> cat(settings(), ack, *Array(14) { i -> p.headers(1 + 2 * i, get(), endStream = false) }) }
        conv("rapid-reset-p1", mode(preset = 1)) { p ->
            cat(settings(), ack, *Array(10) { i -> cat(p.headers(1 + 2 * i, get()), FrameEncoder.rstStream(1 + 2 * i, 8)) })
        }
        // 18 bytes a second (the SETTINGS and the ACK in the first piece): the field block outlives maxHeaderBlockTime (10 s)
        conv("slow-field-block", mode(slow = true), split = 17) { p ->
            val b = p.block(get("/", "x-pad" to "p".repeat(300)))
            cat(
                settings(),
                ack,
                FrameEncoder.headers(1, b.copyOfRange(0, 4), true, false),
                FrameEncoder.continuation(1, b.copyOfRange(4, b.size), true),
            )
        }
        conv(
            "settings-never-acknowledged",
            mode(slow = true),
        ) { p -> cat(settings(), p.headers(1, get()), *Array(40) { i -> FrameEncoder.ping(false, i.toLong()) }) }
        conv("graceful-goaway-actions", mode(actions = true, slow = true)) { p ->
            cat(settings(), ack, *Array(12) { i -> cat(p.headers(1 + 2 * i, get("/$i")), FrameEncoder.ping(false, i.toLong())) })
        }
        conv(
            "hpack-table-zero",
            mode(preset = 2),
            Peer(tableSize = 0),
        ) { p -> cat(settings(SettingId.HEADER_TABLE_SIZE to 0), ack, p.headers(1, get()), p.headers(3, get())) }
        // one protocol error each (a connection error ends the conversation)
        val errors =
            mapOf(
                "data-idle" to { _: Peer -> data(9, 1) },
                "continuation-alone" to { _: Peer -> FrameEncoder.continuation(1, ByteArray(1), true) },
                "frame-inside-block" to
                    { p: Peer -> cat(FrameEncoder.headers(1, p.block(get()), true, false), FrameEncoder.ping(false, 1)) },
                "even-stream" to { p: Peer -> p.headers(2, get()) },
                "stream-goes-down" to { p: Peer -> cat(p.headers(5, get()), p.headers(3, get())) },
                "push-promise" to { _: Peer -> FrameEncoder.pushPromise(1, 2, ByteArray(1), true) },
                "settings-ack-payload" to { _: Peer -> FrameEncoder.raw(0x4, 0x1, 0, ByteArray(6)) },
                "ping-length" to { _: Peer -> FrameEncoder.raw(0x6, 0, 0, ByteArray(7)) },
                "window-update-length" to { _: Peer -> FrameEncoder.raw(0x8, 0, 0, ByteArray(3)) },
                "self-dependency" to { p: Peer -> cat(p.headers(1, get(), endStream = false), FrameEncoder.priority(1, 1)) },
                "rst-idle" to { _: Peer -> FrameEncoder.rstStream(7, 8) },
                "priority-update-stream-0" to { _: Peer -> FrameEncoder.priorityUpdate(0, "u=1") },
                "hpack-garbage" to
                    { _: Peer ->
                        FrameEncoder.headers(1, byteArrayOf(0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0x7f), true, true)
                    },
                "settings-initial-window-too-big" to { _: Peer -> settings(SettingId.INITIAL_WINDOW_SIZE to 0x8000_0000L) },
                "settings-frame-size-too-small" to { _: Peer -> settings(SettingId.MAX_FRAME_SIZE to 100) },
                "settings-push-2" to { _: Peer -> settings(SettingId.ENABLE_PUSH to 2) },
                "headers-stream-0" to { _: Peer -> FrameEncoder.raw(0x1, 0x5, 0, byteArrayOf(0x82.toByte())) },
                "oversized-frame" to { _: Peer -> cat(byteArrayOf(0x01, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 1), ByteArray(10)) },
                "padding-too-long" to { _: Peer -> cat(byteArrayOf(0, 0, 3, 0, 0x8, 0, 0, 0, 1, 9, 0, 0)) },
            )
        for ((name, frames) in errors) conv("error-$name", mode()) { p -> cat(settings(), ack, frames(p)) }
        conv("error-first-frame-not-settings", mode()) { FrameEncoder.ping(false, 1) }
        return all
    }

    /** Server conversations for `connectionClient` (after the server's empty SETTINGS): name to (streams byte, mode, frames). */
    private fun clientConversations(): Map<String, Triple<Int, Int, ByteArray>> {
        val all = LinkedHashMap<String, Triple<Int, Int, ByteArray>>()

        fun conv(
            name: String,
            streams: Int,
            mode: Int,
            build: (Peer) -> ByteArray,
        ) {
            all[name] = Triple(streams, mode, build(Peer()))
        }
        val ok = listOf(":status" to "200")
        conv("responses-trailers", 3, mode()) { p ->
            cat(
                ack,
                p.headers(1, ok, endStream = false),
                data(1, 5, end = true),
                p.headers(3, listOf(":status" to "103", "link" to "</s.css>; rel=preload"), endStream = false),
                p.headers(3, ok + ("content-length" to "2"), endStream = false),
                data(3, 2),
                p.headers(3, listOf("x-sum" to "1")),
                FrameEncoder.windowUpdate(0, 1 shl 20),
                FrameEncoder.windowUpdate(5, 1 shl 16),
            )
        }
        conv("continuation-response", 1, mode()) { p ->
            val b = p.block(ok + ("x-a" to "1".repeat(60)))
            cat(
                ack,
                FrameEncoder.headers(1, b.copyOfRange(0, 5), false, false),
                FrameEncoder.continuation(1, b.copyOfRange(5, b.size), true),
                data(1, 1, end = true),
            )
        }
        conv("ping-and-flood-unread", 1, mode(preset = 1, drain = Mode.Drain.AT_THE_END)) {
            cat(ack, *Array(40) { i -> FrameEncoder.ping(false, i.toLong()) })
        }
        conv("settings-flood-unread", 1, mode(preset = 1, drain = Mode.Drain.AT_THE_END)) {
            cat(
                ack,
                *Array(40) {
                    settings(SettingId.HEADER_TABLE_SIZE to 100)
                },
            )
        }
        for (drain in listOf(Mode.Drain.EVERY_PIECE, Mode.Drain.SHORT_READS)) {
            // stream 5 is a POST with 100 000 bytes to send
            conv("settings-every-id-${drain.name.lowercase()}", 3, mode(connect = true, drain = drain, actions = true)) { p ->
                cat(
                    settings(
                        SettingId.HEADER_TABLE_SIZE to 0,
                        SettingId.ENABLE_PUSH to 0,
                        SettingId.MAX_CONCURRENT_STREAMS to 5,
                        SettingId.INITIAL_WINDOW_SIZE to 100,
                        SettingId.MAX_FRAME_SIZE to 30_000,
                        SettingId.MAX_HEADER_LIST_SIZE to 10_000,
                        SettingId.ENABLE_CONNECT_PROTOCOL to 1,
                        0x77 to 1,
                    ),
                    ack,
                    FrameEncoder.windowUpdate(5, 900),
                    settings(SettingId.INITIAL_WINDOW_SIZE to 70_000),
                    FrameEncoder.windowUpdate(0, 200_000),
                    settings(SettingId.INITIAL_WINDOW_SIZE to 10),
                    FrameEncoder.windowUpdate(5, 5),
                    p.headers(7, ok, endStream = false),
                    data(7, 4), // the Extended CONNECT tunnel (stream 7): 200, then its bytes
                    p.headers(1, ok),
                    FrameEncoder.windowUpdate(5, 100_000),
                    p.headers(5, ok),
                )
            }
        }
        conv("connect-setting-taken-back", 1, mode(connect = true)) {
            cat(settings(SettingId.ENABLE_CONNECT_PROTOCOL to 1), ack, settings(SettingId.ENABLE_CONNECT_PROTOCOL to 0))
        }
        // the server answers before it could have read the request: a connection error (section 5.1, an idle stream)
        conv("response-before-request", 1, mode(serverFirst = true)) { p -> cat(ack, p.headers(1, ok)) }
        // stream 1 stays open, so the connection outlives the GOAWAY: HEADERS on refused stream 3 is STREAM_CLOSED
        conv(
            "goaway-refuses",
            4,
            mode(),
        ) { p -> cat(ack, p.headers(1, ok, endStream = false), FrameEncoder.goAway(1, 0, ByteArray(0)), p.headers(3, ok)) }
        conv("rst-streams", 3, mode(drain = Mode.Drain.SHORT_READS)) { p ->
            cat(
                ack,
                p.headers(1, ok, endStream = false),
                FrameEncoder.rstStream(1, Http2ErrorCode.NO_ERROR.code),
                FrameEncoder.rstStream(3, Http2ErrorCode.REFUSED_STREAM.code),
                FrameEncoder.rstStream(5, Http2ErrorCode.CANCEL.code),
            )
        }
        conv("push-promise-before-ack", 1, mode()) { p ->
            FrameEncoder.pushPromise(
                1,
                2,
                p.block(
                    listOf(
                        ":method" to "GET",
                        ":scheme" to "https",
                        ":authority" to "a",
                        ":path" to "/p",
                    ),
                ),
                true,
            )
        }
        conv("altsvc-and-unknown", 1, mode()) {
            cat(
                ack,
                FrameEncoder.altSvc(0, "https://example.com", "h3=\":443\""),
                FrameEncoder.altSvc(1, "", "h3=\":8443\""),
                FrameEncoder.raw(0xfa, 0, 0, ByteArray(3)),
            )
        }
        conv("priority-update-from-server", 1, mode()) { cat(ack, FrameEncoder.priorityUpdate(1, "u=1")) }
        conv("malformed-responses", 4, mode(actions = true)) { p ->
            cat(
                ack,
                p.headers(1, listOf(":status" to "101")),
                p.headers(3, listOf("x-no-status" to "1")),
                p.headers(
                    5,
                    ok + ("Upper" to "1"),
                ),
                p.headers(7, ok + ("content-length" to "3")),
            )
        }
        conv("empty-data-flood", 1, mode(preset = 1)) { p -> cat(ack, p.headers(1, ok, endStream = false), *Array(10) { data(1, 0) }) }
        conv("too-large-response", 1, mode(preset = 1)) { p -> cat(ack, p.headers(1, ok + ("x-big" to "v".repeat(400)))) }
        conv("ping-actions-slow", 2, mode(actions = true, slow = true)) { p ->
            cat(
                ack,
                *Array(12) { i -> cat(FrameEncoder.ping(false, i.toLong()), FrameEncoder.ping(true, (i + 1).toLong())) },
                p.headers(1, ok),
            )
        }
        val errors =
            mapOf(
                "data-idle" to { _: Peer -> data(9, 1) },
                "headers-even-idle" to { p: Peer -> p.headers(2, ok) },
                "settings-push-1" to { _: Peer -> settings(SettingId.ENABLE_PUSH to 1) },
                "window-update-0" to { _: Peer -> FrameEncoder.windowUpdate(0, 0) },
                "continuation-alone" to { _: Peer -> FrameEncoder.continuation(1, ByteArray(1), true) },
                "goaway-short" to { _: Peer -> FrameEncoder.raw(0x7, 0, 0, ByteArray(4)) },
                // RFC 9218 section 2.1: the value may not change after the first SETTINGS (the preface left it at 0)
                "no-rfc7540-priorities-changed" to { _: Peer -> settings(SettingId.NO_RFC7540_PRIORITIES to 1) },
            )
        for ((name, frames) in errors) conv("error-$name", 1, mode()) { p -> cat(ack, frames(p)) }
        return all
    }

    private fun generate(): Map<String, ByteArray> {
        val seeds = LinkedHashMap<String, ByteArray>()
        val splits = intArrayOf(255, 31, 7, 0)
        var i = 0
        val server = serverConversations()
        for ((name, c) in server) {
            val (mode, frames, blocks) = c
            val split = splitOf[name] ?: splits[i++ % splits.size]
            seeds["H2ConnectionFuzzTestInputs/connectionServer/seed-$name"] = cat(byteArrayOf(split.toByte(), mode.toByte()), frames)
            seeds["H2FrameFuzzTestInputs/frames/seed-$name"] = cat(byteArrayOf(split.toByte()), frames)
            if (blocks.size >= 2) {
                // [settings byte: table 4096, list limit 16 KiB][length of block 1][block 1][block 2]
                val b1 = blocks[0]
                seeds["HpackDecodeFuzzTestInputs/hpackDecode/seed-$name"] =
                    cat(byteArrayOf((2 or (2 shl 2)).toByte(), (b1.size ushr 8).toByte(), b1.size.toByte()), b1, blocks[1])
            }
        }
        for ((name, c) in clientConversations()) {
            val (streams, mode, frames) = c
            val split = splits[i++ % splits.size]
            seeds["H2ClientConnectionFuzzTestInputs/connectionClient/seed-$name"] =
                cat(byteArrayOf(split.toByte(), (streams - 1).toByte(), mode.toByte()), frames)
        }

        // hpackRoundTrip: [op][fields...] where op % 8 fields follow; 0xff [size >> 4] changes the peer's table size
        fun field(
            nameIndex: Int,
            value: String,
        ) = cat(byteArrayOf(0, nameIndex.toByte()), byteArrayOf(value.length.toByte()), value.encodeToByteArray())
        seeds["HpackRoundTripFuzzTestInputs/hpackRoundTrip/seed-evict-and-resize"] =
            cat(
                byteArrayOf(3),
                field(0, "/a"),
                field(4, "v".repeat(30)),
                field(2, "c=1"),
                byteArrayOf(3),
                field(0, "/a"),
                field(4, "v".repeat(30)),
                field(2, "c=1"),
                byteArrayOf(0xff.toByte(), 2),
                byteArrayOf(2),
                field(4, "w".repeat(39)),
                field(1, "secret"),
                byteArrayOf(0xff.toByte(), 0),
                byteArrayOf(1),
                field(6, "now"),
                byteArrayOf(0xff.toByte(), 0xff.toByte()),
                byteArrayOf(2),
                field(5, "text/html"),
                field(4, "x".repeat(39)),
            )
        return seeds
    }
}
