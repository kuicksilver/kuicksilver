// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.DatagramPacketWriter
import io.kuicksilver.quic.DatagramSender
import io.kuicksilver.quic.Dgram
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.ksl
import io.kuicksilver.tls.QuicCrypto
import java.io.ByteArrayOutputStream
import kotlin.time.Duration.Companion.milliseconds

/**
 * Stateful connection fuzzer: a client/server pair of [ConnectionCore]s (as `CorePair` joins them, virtual time) runs a
 * program of operations read from the input — frames sealed by one side into packets of any level (raw bytes or
 * structured frames with fuzzed fields), application actions on either side (streams, resets, STOP_SENDING, reads,
 * datagrams, key updates, close), network effects (drop, duplicate, reorder, ECN marks, NAT rebinding) and time.
 * Frames are injected into the sender's packet builder (`ConnectionCore.testInjectFrames`), so with [connectionTls] they
 * travel under the keys of a real TLS handshake and reach the receiver's frame handlers exactly as a peer's would.
 *
 * After every step both cores must hold: no exception out of the core, no crash isolated as
 * [QuicException.ConnectionLost.Internal], a Closed event for every closing connection, the flow-control and stream-state
 * invariants of `StreamManager.invariantViolationForTest`, and bounded per-connection collections
 * (`ConnectionCore.sizesForTest`). The input format is [ConnProgram].
 */
@OptIn(ExperimentalKuicksilverApi::class)
class ConnectionFuzzTest {
    /** `connectionNull`: the program over a NullCryptoProvider pair (fast: no TLS, plaintext packets). */
    @FuzzTest(maxDuration = "60s")
    fun connectionNull(data: ByteArray) {
        ConnectionFuzz(data, NullCryptoProvider).run()
    }

    /** `connectionTls`: the program over a pair that completes a real TLS 1.3 handshake through ksl/OpenSSL. */
    @FuzzTest(maxDuration = "60s")
    fun connectionTls(data: ByteArray) {
        ConnectionFuzz(data, ksl).run()
    }
}

/**
 * The input format of [ConnectionFuzzTest], shared with the seed generator.
 *
 * `[flags][op]*`. Flags: bit 0 — operations start with the first datagram (Initial and Handshake levels are live)
 * instead of after both sides completed the handshake; bit 1 — small limits (4 streams, 1 KiB stream and 4 KiB
 * connection windows, 2 connection IDs, 4 queued datagrams), so the limits are reachable; bit 2 — PMTUD off.
 *
 * An op byte `o`: kind `o & 7`, side `(o >> 3) & 1` (0: the client acts or sends, so the server receives; 1: the
 * server), argument `o >> 4`:
 * - 0 RAW: `[u16 length][bytes]` written verbatim into the next packet of level `arg & 3` (0 Initial, 1 0-RTT,
 *   2 Handshake, 3 1-RTT); at most [MAX_FRAME] bytes.
 * - 1 FRAME: `[selector][fields]` — a well-formed frame from [FRAME_KINDS] whose fields are [num]s, into level `arg & 3`.
 * - 2 STEP: `arg * 5` ms pass, then one round (timers, delivery, polling); `arg & 8`: the applications read datagrams.
 * - 3 APP: action `arg & 7` on that side — 0 open a stream (`arg & 8`: unidirectional) and write [num] bytes, then
 *   `[fin]`; 1 write [num] bytes to stream `[index]`; 2 read up to [num] bytes from stream `[index]`; 3 reset stream
 *   `[index]` with code [num]; 4 STOP_SENDING on stream `[index]` with code [num]; 5 key update; 6 queue a datagram of
 *   [num] bytes; 7 close with application code [num].
 * - 4 NET: on the datagrams queued towards the other side — `arg & 3`: 0 drop the first, 1 duplicate it, 2 reverse the
 *   queue, 3 mark them ECT(0) (`arg & 4`: CE); `arg & 8`: they come from a new source address (NAT rebinding).
 * - 5 TICK: `arg * 100` ms (15: 3 s) pass, then one round.
 * - 6 BLOCK: `arg & 1` toggles dropping every datagram from that side to the other (`arg & 1 == 0`: one round). A
 *   blocked direction holds one side at an encryption level the other has left, so it still sends CRYPTO there
 *   (Initial or Handshake data past what TLS consumed: the sealed CRYPTO streams, RFC 9001 section 4.1.3).
 * - 7: one round.
 *
 * A [num] is one byte `b` < 0xf8 for its own value, else `b - 0xf7` big-endian bytes masked to 62 bits.
 */
internal object ConnProgram {
    const val MAX_FRAME = 1000
    const val MAX_OPS = 400

    /** Frame selectors of the FRAME op. */
    val FRAME_KINDS =
        listOf(
            "PADDING",
            "PING",
            "ACK",
            "ACK_ECN",
            "RESET_STREAM",
            "STOP_SENDING",
            "CRYPTO",
            "NEW_TOKEN",
            "STREAM",
            "MAX_DATA",
            "MAX_STREAM_DATA",
            "MAX_STREAMS_BIDI",
            "MAX_STREAMS_UNI",
            "DATA_BLOCKED",
            "STREAM_DATA_BLOCKED",
            "STREAMS_BLOCKED_BIDI",
            "STREAMS_BLOCKED_UNI",
            "NEW_CONNECTION_ID",
            "RETIRE_CONNECTION_ID",
            "PATH_CHALLENGE",
            "PATH_RESPONSE",
            "CONNECTION_CLOSE",
            "CONNECTION_CLOSE_APP",
            "HANDSHAKE_DONE",
            "DATAGRAM",
            "DATAGRAM_LEN",
            "UNKNOWN",
        )

    fun num(v: Long): ByteArray {
        if (v in 0 until 0xf8) return byteArrayOf(v.toByte())
        var n = 1
        while (n < 8 && (v ushr (8 * n)) != 0L) n++
        return ByteArray(n + 1) { if (it == 0) (0xf7 + n).toByte() else (v ushr (8 * (n - it))).toByte() }
    }

    /** Builds programs for the seed corpus. */
    class Builder(
        flags: Int,
    ) {
        private val out = ByteArrayOutputStream().also { it.write(flags) }

        private fun op(
            kind: Int,
            side: Int,
            arg: Int,
        ) = out.write(kind or (side shl 3) or (arg shl 4))

        fun raw(
            side: Int,
            level: Int,
            bytes: ByteArray,
        ) = apply {
            op(0, side, level)
            out.write(bytes.size ushr 8)
            out.write(bytes.size and 0xff)
            out.write(bytes)
        }

        fun frame(
            side: Int,
            level: Int,
            kind: String,
            vararg fields: Long,
        ) = apply {
            op(1, side, level)
            out.write(FRAME_KINDS.indexOf(kind).also { require(it >= 0) })
            for (f in fields) out.write(num(f))
        }

        /** A FRAME op with selector [index] and its fields as given (STREAM bits, NEW_CONNECTION_ID length and seed bytes). */
        fun frameRaw(
            side: Int,
            level: Int,
            index: Int,
            vararg parts: ByteArray,
        ) = apply {
            op(1, side, level)
            out.write(index)
            for (b in parts) out.write(b)
        }

        fun step(
            ms5: Int = 1,
            readDatagrams: Boolean = false,
        ) = apply { op(2, 0, ms5 or if (readDatagrams) 8 else 0) }

        fun steps(n: Int) = apply { repeat(n) { step() } }

        fun app(
            side: Int,
            action: Int,
            vararg bytes: ByteArray,
            uni: Boolean = false,
        ) = apply {
            op(3, side, action or if (uni) 8 else 0)
            for (b in bytes) out.write(b)
        }

        fun net(
            side: Int,
            arg: Int,
        ) = apply { op(4, side, arg) }

        fun tick(hundredMs: Int) = apply { op(5, 0, hundredMs) }

        /** Toggles dropping the datagrams from [side] to the other side. */
        fun block(side: Int) = apply { op(6, side, 1) }

        fun build(): ByteArray = out.toByteArray()
    }
}

/** One run of a [ConnProgram] over a pair with [crypto]. */
@OptIn(ExperimentalKuicksilverApi::class)
internal class ConnectionFuzz(
    private val data: ByteArray,
    private val crypto: QuicCrypto,
) {
    private var p = 0
    private val flags = if (data.isEmpty()) 0 else data[0].toInt() and 0xff

    private fun u8(): Int = if (p < data.size) data[p++].toInt() and 0xff else 0

    private fun num(): Long {
        val b = u8()
        if (b < 0xf8) return b.toLong()
        var v = 0L
        repeat(b - 0xf7) { v = (v shl 8) or u8().toLong() }
        return v and ((1L shl 62) - 1)
    }

    private fun varint(
        o: ByteArrayOutputStream,
        v: Long,
    ) {
        val x = v and ((1L shl 62) - 1)
        when {
            x < 64 -> {
                o.write(x.toInt())
            }

            x < 16384 -> {
                o.write(0x40 or (x ushr 8).toInt())
                o.write(x.toInt() and 0xff)
            }

            x < (1L shl 30) -> {
                for (i in 3 downTo 0) o.write(((x ushr (8 * i)) and 0xff).toInt() or if (i == 3) 0x80 else 0)
            }

            else -> {
                for (i in 7 downTo 0) o.write(((x ushr (8 * i)) and 0xff).toInt() or if (i == 7) 0xc0 else 0)
            }
        }
    }

    private fun pattern(n: Int): ByteArray = ByteArray(n) { (it * 7 + 3).toByte() }

    /** A well-formed frame of the selected kind with fuzzed fields. */
    private fun frame(): ByteArray {
        val o = ByteArrayOutputStream()
        val kinds = ConnProgram.FRAME_KINDS
        val kind = kinds[u8() % kinds.size]
        when (kind) {
            "PADDING" -> {
                repeat(minOf(num(), 64L).toInt() + 1) { o.write(0) }
            }

            "PING" -> {
                o.write(0x01)
            }

            "ACK", "ACK_ECN" -> {
                val ecn = kind == "ACK_ECN"
                o.write(if (ecn) 0x03 else 0x02)
                varint(o, num()) // largest acknowledged
                varint(o, num()) // ack delay
                val ranges = minOf(num(), 32L)
                varint(o, ranges)
                varint(o, num()) // first range
                repeat(ranges.toInt()) {
                    varint(o, num()) // gap
                    varint(o, num()) // range length
                }
                if (ecn) repeat(3) { varint(o, num()) }
            }

            "RESET_STREAM" -> {
                o.write(0x04)
                varint(o, num())
                varint(o, num())
                varint(o, num())
            }

            "STOP_SENDING" -> {
                o.write(0x05)
                varint(o, num())
                varint(o, num())
            }

            "CRYPTO" -> {
                o.write(0x06)
                varint(o, num())
                val n = minOf(num(), 600L).toInt()
                varint(o, n.toLong())
                o.write(pattern(n))
            }

            "NEW_TOKEN" -> {
                o.write(0x07)
                val n = minOf(num(), 300L).toInt()
                varint(o, n.toLong())
                o.write(pattern(n))
            }

            "STREAM" -> {
                val bits = u8() and 0x07 // OFF, LEN, FIN
                o.write(0x08 or bits)
                varint(o, num())
                if (bits and 0x04 != 0) varint(o, num())
                val n = minOf(num(), 700L).toInt()
                if (bits and 0x02 != 0) varint(o, n.toLong())
                o.write(pattern(n))
            }

            "MAX_DATA" -> {
                o.write(0x10)
                varint(o, num())
            }

            "MAX_STREAM_DATA" -> {
                o.write(0x11)
                varint(o, num())
                varint(o, num())
            }

            "MAX_STREAMS_BIDI" -> {
                o.write(0x12)
                varint(o, num())
            }

            "MAX_STREAMS_UNI" -> {
                o.write(0x13)
                varint(o, num())
            }

            "DATA_BLOCKED" -> {
                o.write(0x14)
                varint(o, num())
            }

            "STREAM_DATA_BLOCKED" -> {
                o.write(0x15)
                varint(o, num())
                varint(o, num())
            }

            "STREAMS_BLOCKED_BIDI" -> {
                o.write(0x16)
                varint(o, num())
            }

            "STREAMS_BLOCKED_UNI" -> {
                o.write(0x17)
                varint(o, num())
            }

            "NEW_CONNECTION_ID" -> {
                o.write(0x18)
                varint(o, num()) // sequence
                varint(o, num()) // retire prior to
                val len = u8() % 24 // up to 23: lengths above 20 are invalid
                o.write(len)
                val seed = u8()
                repeat(len) { o.write(seed + it * 13) }
                repeat(16) { o.write(seed xor it) }
            }

            "RETIRE_CONNECTION_ID" -> {
                o.write(0x19)
                varint(o, num())
            }

            "PATH_CHALLENGE", "PATH_RESPONSE" -> {
                o.write(if (kind == "PATH_CHALLENGE") 0x1a else 0x1b)
                val seed = u8()
                repeat(8) { o.write(seed + it) }
            }

            "CONNECTION_CLOSE", "CONNECTION_CLOSE_APP" -> {
                val app = kind == "CONNECTION_CLOSE_APP"
                o.write(if (app) 0x1d else 0x1c)
                varint(o, num())
                if (!app) varint(o, num())
                val n = minOf(num(), 200L).toInt()
                varint(o, n.toLong())
                o.write(pattern(n))
            }

            "HANDSHAKE_DONE" -> {
                o.write(0x1e)
            }

            "DATAGRAM" -> {
                o.write(0x30)
                o.write(pattern(minOf(num(), 900L).toInt()))
            }

            "DATAGRAM_LEN" -> {
                o.write(0x31)
                val n = minOf(num(), 900L).toInt()
                varint(o, n.toLong())
                o.write(pattern(n))
            }

            else -> {
                varint(o, num()) // an unknown or reserved type
                o.write(pattern(minOf(num(), 32L).toInt()))
            }
        }
        return o.toByteArray().let { if (it.size > ConnProgram.MAX_FRAME) it.copyOf(ConnProgram.MAX_FRAME) else it }
    }

    private class Side(
        val streams: ArrayList<Long> = ArrayList(),
        val datagrams: ArrayDeque<ByteArray> = ArrayDeque(),
    ) : DatagramSender {
        override fun onTransmit(packet: DatagramPacketWriter) {
            while (true) {
                val d = datagrams.firstOrNull() ?: return
                if (d.size > packet.maxPayload) {
                    datagrams.removeFirst() // never fits: dropped, as an application would
                    continue
                }
                if (!packet.write(d, 0, d.size)) return
                datagrams.removeFirst()
            }
        }

        override fun hasPending(): Boolean = datagrams.isNotEmpty()
    }

    private val small = flags and 2 != 0
    private val config: QuicConfig =
        QuicConfig
            .Builder()
            .apply {
                if (small) {
                    maxBidiStreams = 4
                    maxUniStreams = 4
                    initialStreamWindow = 1024
                    maxStreamWindow = 8192
                    initialConnectionWindow = 4096
                    maxConnectionWindow = 16384
                    activeConnectionIdLimit = 2
                    datagramReceiveQueue = 4
                    maxSendBuffer = 65_536
                }
                if (flags and 4 != 0) pmtud = false
            }.build()

    private val sides = arrayOf(Side(), Side())

    /** BLOCK: datagrams from side 0 (client) / 1 (server) to the other are dropped. */
    private val blocked = BooleanArray(2)
    private lateinit var pair: CorePair
    private var rebind = 0

    fun run() {
        if (data.isEmpty()) return
        KslLoader.ensureLoaded()
        pair = CorePair(clientQuic = config, serverQuic = config, crypto = crypto)
        try {
            pair.client.datagramSender = sides[0]
            pair.onServerCreated = { it.datagramSender = sides[1] }
            pair.filterToServer = { _, _ -> !blocked[0] }
            pair.filterToClient = { _, _ -> !blocked[1] }
            p = 1
            if (flags and 1 == 0) {
                pair.handshake()
                checkInvariants()
            }
            var ops = 0
            while (p < data.size && ops++ < ConnProgram.MAX_OPS) operation(u8())
            repeat(8) {
                pair.advance(10.milliseconds)
                step()
            }
        } finally {
            pair.close()
        }
    }

    private fun core(side: Int): ConnectionCore? = if (side == 0) pair.client else pair.server

    private fun operation(o: Int) {
        val kind = o and 7
        val side = (o ushr 3) and 1
        val arg = o ushr 4
        when (kind) {
            0 -> {
                val n = minOf((u8() shl 8) or u8(), ConnProgram.MAX_FRAME, data.size - p)
                val bytes = data.copyOfRange(p, p + n)
                p += n
                inject(side, arg and 3, bytes)
            }

            1 -> {
                inject(side, arg and 3, frame())
            }

            2 -> {
                pair.advance((arg * 5).milliseconds)
                if (arg and 8 != 0) readDatagrams()
                step()
            }

            3 -> {
                app(side, arg)
            }

            4 -> {
                net(side, arg)
            }

            5 -> {
                pair.advance(if (arg == 15) 3_000.milliseconds else (arg * 100).milliseconds)
                step()
            }

            6 -> {
                if (arg and 1 != 0) blocked[side] = !blocked[side] else step()
            }

            else -> {
                step()
            }
        }
    }

    private fun inject(
        side: Int,
        level: Int,
        bytes: ByteArray,
    ) {
        val c = core(side) ?: return
        if (bytes.isEmpty() || c.testInjectFrames.size >= 64) return
        c.testInjectFrames += level to bytes
    }

    private fun stream(side: Int): Long? {
        val s = sides[side].streams
        val i = u8()
        return if (s.isEmpty()) null else s[i % s.size]
    }

    /** Application calls may refuse with IllegalStateException/IllegalArgumentException (their documented contract). */
    private inline fun api(block: () -> Unit) {
        try {
            block()
        } catch (_: IllegalStateException) {
        } catch (_: IllegalArgumentException) {
        }
    }

    private fun app(
        side: Int,
        arg: Int,
    ) {
        val c = core(side) ?: return
        when (arg and 7) {
            0 -> {
                val n = minOf(num(), 20_000L).toInt()
                val fin = u8() and 1 != 0
                api {
                    val id = c.openStream(bidi = arg and 8 == 0)
                    sides[side].streams += id
                    c.writeStream(id, ByteArray(n) { it.toByte() }, 0, n, fin)
                }
            }

            1 -> {
                val id = stream(side)
                val n = minOf(num(), 20_000L).toInt()
                if (id != null) api { c.writeStream(id, ByteArray(n) { (it * 3).toByte() }, 0, n, false) }
            }

            2 -> {
                val id = stream(side)
                val n = minOf(num(), 65_536L).toInt()
                if (id != null) api { c.readStream(id, ByteArray(maxOf(n, 1)), 0, n) }
            }

            3 -> {
                val id = stream(side)
                val code = num()
                if (id != null) api { c.resetStream(id, code) }
            }

            4 -> {
                val id = stream(side)
                val code = num()
                if (id != null) api { c.stopSending(id, code) }
            }

            5 -> {
                c.initiateKeyUpdate(pair.now)
            }

            6 -> {
                val n = minOf(num(), 1500L).toInt()
                if (sides[side].datagrams.size < 16) sides[side].datagrams += ByteArray(n) { 0x5a }
            }

            else -> {
                val code = num()
                api { c.close(code, "fuzz", pair.now) }
            }
        }
    }

    private fun net(
        side: Int,
        arg: Int,
    ) {
        val q = if (side == 0) pair.toServer else pair.toClient
        when (arg and 3) {
            0 -> {
                q.removeFirstOrNull()
            }

            1 -> {
                q.firstOrNull()?.let { if (q.size < 64) q.addFirst(it) }
            }

            2 -> {
                q.reverse()
            }

            else -> {
                val mark = if (arg and 4 != 0) Ecn.Ce else Ecn.Ect0
                for (i in q.indices) q[i] = Dgram(q[i].bytes, q[i].from, mark)
            }
        }
        if (arg and 8 != 0 && side == 0 && pair.server != null) {
            rebind++
            val from = InetSocketAddress("10.0.${rebind / 200}.${rebind % 200 + 3}", 40000 + rebind)
            for (i in q.indices) q[i] = Dgram(q[i].bytes, from, q[i].ecn)
        }
    }

    private fun readDatagrams() {
        val buf = ByteArray(65_536)
        for (side in 0..1) {
            val c = core(side) ?: continue
            var n = 0
            while (n++ < 64 && c.readDatagram(buf, 0) >= 0) { /* the application consumes them */ }
        }
    }

    private fun step() {
        for (side in 0..1) {
            val c = core(side) ?: continue
            // injections at a level whose keys are gone (or never came) would block the queue
            while (true) {
                val head = c.testInjectFrames.firstOrNull() ?: break
                if (c.writeKeys[head.first] != null) break
                c.testInjectFrames.removeFirst()
            }
        }
        pair.step()
        for (e in pair.serverEvents) if (e is ConnectionEvent.StreamOpened) sides[1].streams += e.id
        for (e in pair.clientEvents) if (e is ConnectionEvent.StreamOpened) sides[0].streams += e.id
        checkInvariants()
        pair.clientEvents.clear()
        pair.serverEvents.clear()
        for (s in sides) if (s.streams.size > 512) s.streams.subList(0, s.streams.size - 512).clear()
    }

    private val closedSeen = BooleanArray(2)

    private fun checkInvariants() {
        for (side in 0..1) {
            val c = core(side) ?: continue
            val events = if (side == 0) pair.clientEvents else pair.serverEvents
            for (e in events) {
                if (e !is ConnectionEvent.Closed) continue
                closedSeen[side] = true
                (e.reason as? QuicException.ConnectionLost.Internal)?.let {
                    throw IllegalStateException("${name(side)}: the connection crashed: ${it.message}", it.cause ?: it)
                }
            }
            if (c.state == ConnectionState.Closing || c.state == ConnectionState.Draining || c.state == ConnectionState.Closed) {
                check(closedSeen[side]) { "${name(side)} reached ${c.state} without a Closed event" }
            }
            c.streams.invariantViolationForTest()?.let { throw IllegalStateException("${name(side)}: $it") }
            val sizes = c.sizesForTest()
            for ((key, value) in sizes) {
                val bound = bound(key, c)
                check(value in 0..bound) { "${name(side)}: $key = $value outside 0..$bound" }
            }
        }
    }

    private fun name(side: Int) = if (side == 0) "client" else "server"

    /** Upper bounds of the per-connection collections, from the configuration: what a peer can make the core hold. */
    private fun bound(
        key: String,
        c: ConnectionCore,
    ): Long {
        val cfg = c.config
        val streams = 2 * (cfg.maxBidiStreams + cfg.maxUniStreams) + ConnProgram.MAX_OPS
        return when (key) {
            "events" -> 20_000

            "streams", "streamSendLimits", "streamsEarly" -> streams

            "streamControlFrames" -> 8 * streams + 64

            "streamEvents" -> 20_000

            // the gap limit plus the readable range at each stream's read offset, which is always taken
            "reassemblyRanges" -> cfg.limits.reassemblyRangesPerConnection + streams

            "sendBufferedBytes" -> cfg.maxSendBuffer + 20_000

            "cidsLocal" -> 2L * maxOf(cfg.activeConnectionIdLimit, 8) + 2

            "cidsPeer" -> cfg.activeConnectionIdLimit.toLong() + 1

            "cidsRetiredLocal", "cidsRetiredUntil" -> cfg.limits.retiredConnectionIds.toLong() + 1

            "cidsPendingRetire", "cidsUnackedRetire" -> 4L * cfg.limits.retiredConnectionIds + cfg.activeConnectionIdLimit

            "paths" -> 8

            "pathResponses" -> 16

            "sentInitial", "sentHandshake", "sentApplication" -> 50_000

            "ackRangesInitial", "ackRangesHandshake", "ackRangesApplication" -> cfg.limits.ackRanges.toLong() + 1

            "receiverBufferedBytes" -> cfg.limits.undecryptablePackets.toLong() * 65_536

            "cryptoBufferedBytes" -> 4L * (cfg.limits.cryptoOutOfOrderPerLevel + cfg.limits.cryptoPostHandshake)

            "datagramsQueued" -> cfg.datagramReceiveQueue.toLong()

            "challengedAddresses", "mtuUpdates" -> 64

            else -> throw IllegalStateException("no bound for $key")
        }
    }
}
