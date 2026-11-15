// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Dgram
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.core.ServerEarlyData
import io.kuicksilver.quic.core.recoveryViolationForTest
import io.kuicksilver.quic.core.sizesForTest
import io.kuicksilver.quic.core.streamEventIdForTest
import io.kuicksilver.quic.core.useTicket
import io.kuicksilver.quic.core.zeroRttHeldForTest
import io.kuicksilver.quic.core.zeroRttPacketsSentForTest
import io.kuicksilver.quic.endpoint.ZeroRttReplayRegister
import io.kuicksilver.quic.ksl
import io.kuicksilver.quic.stream.StreamIds
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
import io.kuicksilver.quic.wire.RetryPacket
import io.kuicksilver.quic.wire.VersionNegotiationPacket
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.QuicSessionTicket
import io.kuicksilver.tls.SessionTicketConfig
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsRole
import java.io.ByteArrayOutputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The input format of the 0-RTT connection fuzzer ([ZeroRttConnectionFuzz], `ZeroRttFuzzTest.zeroRttConnection`), shared
 * with the seed generator and the seeded test.
 *
 * `[outcome][flags][op]*`. The client resumes a ticket of an earlier connection (real TLS 1.3 through ksl) and the server's
 * answer to its 0-RTT is `outcome % 7`: [ACCEPT]; rejected by TLS because the application context changed
 * ([REJECT_APPLICATION]) or because the transport limits changed, lower than the remembered ones ([REJECT_LIMITS]), both
 * with the connection going on; rejected under [EarlyDataState.Required] ([REJECT_REQUIRED]) or with another ALPN
 * ([REJECT_ALPN]), both closing it; a server without 0-RTT ([NO_SERVER_EARLY_DATA]); or no answer at all, every server
 * datagram lost ([LOST]). Flags: [RETRY] the first flight gets a Retry (RFC 9000 section 17.2.5) and the 0-RTT goes
 * again; [VERSION_NEGOTIATION] it gets a Version Negotiation offering only QUIC v2, so the handshake restarts without
 * the ticket; [SMALL] the remembered limits are small (3 bidirectional and 2 unidirectional streams, 2 KiB per stream,
 * 6000 bytes per connection) so 0-RTT runs into them; [NO_RESET_AT] the client does not offer `reset_stream_at`.
 *
 * An op byte `o`: kind `o & 7`, side `(o >> 3) & 1` (0 the client, 1 the server), argument `o >> 4`:
 * - 0 APP: action `arg & 7` of that side's application — 0 open a stream (`arg & 8`: unidirectional) and write [num]
 *   bytes, then `[fin]`; 1 write [num] bytes to stream `[index]`; 2 finish stream `[index]`; 3 reset stream `[index]`
 *   with code [num]; 4 RESET_STREAM_AT on stream `[index]` with code [num] and reliable size [num]; 5 STOP_SENDING on
 *   stream `[index]` with code [num]; 6 read up to [num] bytes from stream `[index]`; 7 close with code [num].
 * - 1 STEP: `arg * 5` ms pass, then one round.
 * - 2 TICK: `arg * 100` ms (15: 3 s) pass, then one round.
 * - 3 BLOCK: toggles dropping every datagram from that side to the other.
 * - 4 NET: on the datagrams queued from that side — `arg & 3`: 0 drop the first, 1 duplicate it, 2 reverse the queue,
 *   3 drop them all.
 * - 5 SETTLE: rounds of 10 ms until the client knows the server's answer or closed (at most 64).
 * - 6 DATAGRAM: that side queues a DATAGRAM of `arg * 64` bytes (RFC 9221; the client's go in 0-RTT before the answer).
 * - 7: one round.
 *
 * Ops before the first round run while the client has only its 0-RTT keys; a [num] is as in [ConnProgram].
 */
internal object ZeroRttProgram {
    const val ACCEPT = 0
    const val REJECT_APPLICATION = 1
    const val REJECT_LIMITS = 2
    const val REJECT_REQUIRED = 3
    const val REJECT_ALPN = 4
    const val NO_SERVER_EARLY_DATA = 5
    const val LOST = 6
    const val OUTCOMES = 7

    const val RETRY = 1
    const val VERSION_NEGOTIATION = 2
    const val SMALL = 4
    const val NO_RESET_AT = 8

    const val MAX_OPS = 300

    /** Builds programs for the seed corpus and the seeded test. */
    class Builder(
        outcome: Int,
        flags: Int,
    ) {
        private val out =
            ByteArrayOutputStream().also {
                it.write(outcome)
                it.write(flags)
            }

        private fun op(
            kind: Int,
            side: Int,
            arg: Int,
        ) = out.write(kind or (side shl 3) or (arg shl 4))

        private fun num(v: Long) = out.write(ConnProgram.num(v))

        fun open(
            side: Int,
            bytes: Long,
            fin: Boolean,
            uni: Boolean = false,
        ) = apply {
            op(0, side, 0 or if (uni) 8 else 0)
            num(bytes)
            out.write(if (fin) 1 else 0)
        }

        fun write(
            side: Int,
            index: Int,
            bytes: Long,
        ) = apply {
            op(0, side, 1)
            out.write(index)
            num(bytes)
        }

        fun finish(
            side: Int,
            index: Int,
        ) = apply {
            op(0, side, 2)
            out.write(index)
        }

        fun reset(
            side: Int,
            index: Int,
            code: Long,
        ) = apply {
            op(0, side, 3)
            out.write(index)
            num(code)
        }

        fun resetAt(
            side: Int,
            index: Int,
            code: Long,
            reliable: Long,
        ) = apply {
            op(0, side, 4)
            out.write(index)
            num(code)
            num(reliable)
        }

        fun stop(
            side: Int,
            index: Int,
            code: Long,
        ) = apply {
            op(0, side, 5)
            out.write(index)
            num(code)
        }

        fun read(
            side: Int,
            index: Int,
            bytes: Long,
        ) = apply {
            op(0, side, 6)
            out.write(index)
            num(bytes)
        }

        fun close(
            side: Int,
            code: Long,
        ) = apply {
            op(0, side, 7)
            num(code)
        }

        fun step(ms5: Int = 1) = apply { op(1, 0, ms5) }

        fun tick(hundredMs: Int) = apply { op(2, 0, hundredMs) }

        fun block(side: Int) = apply { op(3, side, 0) }

        fun net(
            side: Int,
            arg: Int,
        ) = apply { op(4, side, arg) }

        fun settle() = apply { op(5, 0, 0) }

        fun datagram(
            side: Int,
            size64: Int,
        ) = apply { op(6, side, size64) }

        fun build(): ByteArray = out.toByteArray()
    }

    /**
     * A random program of [outcome] and [flags]: application calls before the first round (in 0-RTT), then a mix; without
     * [network] faults no datagram is touched and neither application closes, so the outcome is the configured one.
     */
    fun random(
        rnd: Random,
        outcome: Int,
        flags: Int,
        network: Boolean = true,
    ): ByteArray {
        val b = Builder(outcome, flags)

        fun appOp(side: Int) {
            val i = rnd.nextInt(8)
            when (rnd.nextInt(10)) {
                0, 1, 2 -> b.open(side, rnd.nextLong(0, 9000), rnd.nextInt(3) == 0, uni = rnd.nextInt(3) == 0)
                3 -> b.write(side, i, rnd.nextLong(0, 5000))
                4 -> b.finish(side, i)
                5 -> b.reset(side, i, rnd.nextLong(0, 300))
                6 -> b.resetAt(side, i, rnd.nextLong(0, 300), rnd.nextLong(0, 6000))
                7 -> b.stop(side, i, rnd.nextLong(0, 300))
                8 -> b.read(side, i, rnd.nextLong(0, 4000))
                else -> if (network && rnd.nextInt(6) == 0) b.close(side, rnd.nextLong(0, 300)) else b.write(side, i, rnd.nextLong(1, 3000))
            }
        }
        repeat(1 + rnd.nextInt(6)) { appOp(0) }
        repeat(rnd.nextInt(24)) {
            when (rnd.nextInt(if (network) 10 else 7)) {
                0 -> appOp(0)
                1 -> if (rnd.nextInt(4) == 0) b.datagram(0, rnd.nextInt(16)) else appOp(0)
                2 -> appOp(1)
                3, 4 -> b.step(rnd.nextInt(16))
                5 -> b.tick(rnd.nextInt(16))
                6 -> b.settle()
                7 -> if (rnd.nextBoolean()) b.datagram(0, rnd.nextInt(16)) else b.net(rnd.nextInt(2), rnd.nextInt(4))
                else -> b.block(rnd.nextInt(2))
            }
        }
        return b.build()
    }
}

/** How often the 0-RTT fuzzer reached each outcome and made each call before the server's answer (shared by every run in the JVM). */
internal object ZeroRttCoverage {
    val counts = ConcurrentHashMap<String, AtomicLong>()

    fun hit(key: String) {
        counts.computeIfAbsent(key) { AtomicLong() }.incrementAndGet()
    }

    fun of(key: String): Long = counts[key]?.get() ?: 0L

    fun snapshot(): Map<String, Long> = counts.entries.associate { it.key to it.value.get() }.toSortedMap()
}

/**
 * One run of a [ZeroRttProgram]: a client core resumes a ticket and sends 0-RTT to a server core under virtual time
 * (`CorePair`, real TLS through ksl), the program drives both applications and the network, and then both sides close.
 *
 * Checked after every round, and at the end, on both sides: no exception out of a core, no crash isolated as
 * [QuicException.ConnectionLost.Internal], a Closed event for every closing connection, the stream and flow-control
 * invariants (`StreamManager.invariantViolationForTest`, `sendCreditViolationForTest`), the recovery bookkeeping
 * (`recoveryViolationForTest`: bytes in flight and every congestion controller agree with the sent history) and bounded
 * collections (`sizesForTest`). On the client, once the server's answer is known or the connection ended (the 0-RTT
 * invariant, docs/architecture.md "0-RTT invariant"):
 * - nothing stays held for the answer (`zeroRttHeldForTest`, the `zeroRttHeld` size);
 * - a rejection leaves no 0-RTT packet in the sent history (so none in flight, in a congestion controller or in loss
 *   detection) and, when the connection goes on, nothing of the dropped streams in the stream manager
 *   (`zeroRttResidueForTest`: no stream, send limit, queued frame or event, no connection credit and no buffered byte);
 * - the rejection reaches the application exactly once, as [ConnectionEvent.EarlyDataRejected] when the connection goes
 *   on, as [QuicException.ConnectionLost.ZeroRttRejected] when it closes (Required mode, another ALPN), never both and
 *   never after an acceptance;
 * - no event names a stream after its [ConnectionEvent.StreamFinished] or a stream the rejection dropped, and every
 *   stream in either side's map is one its application can reach (it opened it, or a StreamOpened event announced it).
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
internal class ZeroRttConnectionFuzz(
    private val data: ByteArray,
    /** Fail unless the client sees this answer (seeded runs without network faults); null: any. */
    private val expect: Expect? = null,
    /** Called after every round, before the checks (the negative controls corrupt the state there); [answeredNow]: the client learnt the answer in it. */
    private val tamper: ((pair: CorePair, answeredNow: Boolean) -> Unit)? = null,
) {
    enum class Expect { Accepted, RejectedGoesOn, RejectedCloses }

    private var p = 2
    private val outcome = if (data.isEmpty()) 0 else (data[0].toInt() and 0xff) % ZeroRttProgram.OUTCOMES
    private val flags = if (data.size < 2) 0 else data[1].toInt() and 0xff
    private val retry = flags and ZeroRttProgram.RETRY != 0 && flags and ZeroRttProgram.VERSION_NEGOTIATION == 0
    private val vn = flags and ZeroRttProgram.VERSION_NEGOTIATION != 0
    private val small = flags and ZeroRttProgram.SMALL != 0

    private fun u8(): Int = if (p < data.size) data[p++].toInt() and 0xff else 0

    private fun num(): Long {
        val b = u8()
        if (b < 0xf8) return b.toLong()
        var v = 0L
        repeat(b - 0xf7) { v = (v shl 8) or u8().toLong() }
        return v and ((1L shl 62) - 1)
    }

    private lateinit var pair: CorePair
    private val blocked = BooleanArray(2)
    private val mode = if (outcome == ZeroRttProgram.REJECT_REQUIRED) EarlyDataState.Required else EarlyDataState.Allowed

    /** The streams each application can name (an index picks one); the client's own are forgotten at a rejection. */
    private val streams = arrayOf(ArrayList<Long>(), ArrayList<Long>())

    /** Streams each side's application opened, or learnt of from StreamOpened, since the client's last rejection. */
    private val reachable = arrayOf(HashSet<Long>(), HashSet<Long>())
    private val finished = arrayOf(HashSet<Long>(), HashSet<Long>())

    /** Client streams the rejection dropped and the application has not opened again. */
    private val dropped = HashSet<Long>()
    private val closedSeen = BooleanArray(2)
    private var closedReason: QuicException.ConnectionLost? = null
    private var rejectedEvents = 0
    private var acceptedEvents = 0
    private var ticketUsed = false
    private var answered = false
    private var retrySent = false
    private var vnSent = false

    fun run() {
        if (data.size < 2) return
        KslLoader.ensureLoaded()
        val ticket = Tickets.take(small)
        val serverQuic = serverQuic()
        val serverTls = if (outcome == ZeroRttProgram.REJECT_ALPN) Tickets.altServerTls else Tickets.serverTls
        val early =
            when (outcome) {
                ZeroRttProgram.NO_SERVER_EARLY_DATA -> null
                else -> ServerEarlyData.of(serverQuic, serverTls.alpn, earlyApplication(), ZeroRttReplayRegister(Random(7)))
            }
        pair =
            CorePair(
                clientTls = Tickets.clientTls,
                serverTls = serverTls,
                clientQuic = clientQuic(),
                serverQuic = serverQuic,
                crypto = ksl,
                clientEarly = mode,
                serverEarly = early,
                clientSetup = { c -> ticketUsed = c.useTicket(ticket) },
            )
        try {
            if (!ticketUsed) ticket.close()
            check(ticketUsed) { "the ticket gave no 0-RTT: the fuzzer would not test it" }
            ZeroRttCoverage.hit("runs")
            pair.client.datagramSender = datagrams[0]
            pair.onServerCreated = { it.datagramSender = datagrams[1] }
            pair.filterToServer = { _, b -> toServer(b) }
            pair.filterToClient = { _, _ -> !blocked[1] && outcome != ZeroRttProgram.LOST }
            var ops = 0
            while (p < data.size && ops++ < ZeroRttProgram.MAX_OPS) operation(u8())
            finish()
        } finally {
            pair.close()
        }
        expect?.let { checkExpected(it) }
    }

    private fun clientQuic(): QuicConfig =
        QuicConfig
            .Builder()
            .apply {
                resetStreamAt = flags and ZeroRttProgram.NO_RESET_AT == 0
                if (vn) versions = listOf(VersionProfile.V1, VersionProfile.V2)
            }.build()

    private fun serverQuic(): QuicConfig =
        Tickets
            .originQuic(small)
            .apply {
                if (outcome == ZeroRttProgram.REJECT_LIMITS) {
                    initialConnectionWindow = 1000
                    maxBidiStreams = 1
                }
                // one that still offered v1 would make the Version Negotiation a downgrade (RFC 9368 section 4)
                if (vn) versions = listOf(VersionProfile.V2)
            }.build()

    private fun earlyApplication(): ByteArray? =
        if (outcome == ZeroRttProgram.REJECT_APPLICATION || outcome == ZeroRttProgram.REJECT_REQUIRED) byteArrayOf(9) else null

    // ---- the network ----

    /** Datagrams to the server: the first Initial flight is answered with a Retry or a Version Negotiation when asked. */
    private fun toServer(b: ByteArray): Boolean {
        if (blocked[0]) return false
        val initial = b[0].toInt() and 0xf0 == 0xc0
        // the whole first flight is answered (a stateless server keeps nothing of it) until the client acted on the answer
        if (vn && pair.client.receivedVnVersions == null) {
            if (initial && !vnSent) {
                vnSent = true
                if (pair.client.zeroRttPacketsSealed > 0) ZeroRttCoverage.hit("vn.after0rtt")
                pair.toClient += Dgram(versionNegotiation(b), CoreFixtures.serverAddr)
            }
            return false
        }
        if (retry && !pair.client.retryReceivedForTest) {
            if (initial && !retrySent) {
                retrySent = true
                if (pair.client.zeroRttPacketsSealed > 0) ZeroRttCoverage.hit("retry.after0rtt")
                val scid = ConnectionId(ByteArray(8) { (0x50 + it).toByte() })
                pair.serverAfterRetry = pair.client.odcid to scid
                pair.toClient += Dgram(retryPacket(scid), CoreFixtures.serverAddr)
            }
            return false
        }
        return true
    }

    private fun retryPacket(scid: ConnectionId): ByteArray {
        val out = PacketBuffer.allocate(200)
        try {
            val c = pair.client
            val n = RetryPacket.write(out, c.version, c.localCid, scid, ByteArray(16) { 7 }, c.odcid, ksl, 0)
            return out.toByteArray(n)
        } finally {
            out.close()
        }
    }

    private fun versionNegotiation(initial: ByteArray): ByteArray {
        val b = PacketBuffer.of(initial)
        val out = PacketBuffer.allocate(1200)
        try {
            val v = PacketHeaderView()
            check(PacketHeaderCodec.parse(b, 0, initial.size, 8, v))
            val n =
                VersionNegotiationPacket.write(
                    out,
                    b,
                    v.scidOff,
                    v.scidLen,
                    b,
                    v.dcidOff,
                    v.dcidLen,
                    intArrayOf(VersionProfile.V2.version),
                    0x12,
                    1200,
                )
            return out.toByteArray(n)
        } finally {
            b.close()
            out.close()
        }
    }

    // ---- the program ----

    private fun core(side: Int): ConnectionCore? = if (side == 0) pair.client else pair.server

    private fun operation(o: Int) {
        val kind = o and 7
        val side = (o ushr 3) and 1
        val arg = o ushr 4
        when (kind) {
            0 -> {
                app(side, arg)
            }

            1 -> {
                pair.advance((arg * 5).milliseconds)
                step()
            }

            2 -> {
                pair.advance(if (arg == 15) 3.seconds else (arg * 100).milliseconds)
                step()
            }

            3 -> {
                blocked[side] = !blocked[side]
            }

            4 -> {
                val q = if (side == 0) pair.toServer else pair.toClient
                when (arg and 3) {
                    0 -> q.removeFirstOrNull()
                    1 -> q.firstOrNull()?.let { if (q.size < 64) q.addFirst(it) }
                    2 -> q.reverse()
                    else -> q.clear()
                }
            }

            5 -> {
                var n = 0
                while (n++ < 64 && !answeredOrClosed()) {
                    pair.advance(10.milliseconds)
                    step()
                }
            }

            6 -> {
                if (side == 0 && pair.client.earlyAccepted == null && !isClosing(pair.client)) ZeroRttCoverage.hit("early.datagram")
                datagrams[side].offer(arg * 64)
            }

            else -> {
                step()
            }
        }
    }

    /** What each application queued with DATAGRAM frames (RFC 9221), handed to the core as it polls. */
    private class Datagrams : io.kuicksilver.quic.DatagramSender {
        val queue = ArrayDeque<ByteArray>()

        fun offer(size: Int) {
            if (queue.size < 16) queue += ByteArray(size) { 0x5a }
        }

        override fun onTransmit(packet: io.kuicksilver.quic.DatagramPacketWriter) {
            while (true) {
                val d = queue.firstOrNull() ?: return
                if (d.size > packet.maxPayload) {
                    queue.removeFirst() // never fits: dropped, as an application would
                    continue
                }
                if (!packet.write(d, 0, d.size)) return
                queue.removeFirst()
            }
        }

        override fun hasPending(): Boolean = queue.isNotEmpty()
    }

    private val datagrams = arrayOf(Datagrams(), Datagrams())

    private fun answeredOrClosed(): Boolean = pair.client.earlyAccepted != null || isClosing(pair.client)

    private fun isClosing(c: ConnectionCore) =
        c.state == ConnectionState.Closing || c.state == ConnectionState.Draining || c.state == ConnectionState.Closed

    private fun stream(side: Int): Long? {
        val s = streams[side]
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

    /** One application call; its arguments are read whether or not that side exists yet, so the program parses the same. */
    private fun app(
        side: Int,
        arg: Int,
    ) {
        val c = core(side)
        val action = arg and 7
        // the client calls while its 0-RTT is unanswered: the cases the 0-RTT invariant is about
        val early = side == 0 && c != null && c.earlyAccepted == null && !isClosing(c)
        when (action) {
            0 -> {
                val n = minOf(num(), 20_000L).toInt()
                val fin = u8() and 1 != 0
                if (c == null) return
                api {
                    val id = c.openStream(bidi = arg and 8 == 0)
                    if (id >= 0) {
                        streams[side] += id
                        reachable[side] += id
                        if (side == 0) dropped -= id
                        made(early, action)
                        c.writeStream(id, ByteArray(n) { it.toByte() }, 0, n, fin)
                    }
                }
            }

            1 -> {
                val id = stream(side)
                val n = minOf(num(), 20_000L).toInt()
                call(c, id, early, action) { c!!.writeStream(it, ByteArray(n) { b -> (b * 3).toByte() }, 0, n, false) }
            }

            2 -> {
                val id = stream(side)
                call(c, id, early, action) { c!!.writeStream(it, ByteArray(0), 0, 0, true) }
            }

            3 -> {
                val id = stream(side)
                val code = num()
                call(c, id, early, action) { c!!.resetStream(it, code) }
            }

            4 -> {
                val id = stream(side)
                val code = num()
                val reliable = num()
                call(c, id, early, action) { c!!.resetStreamAt(it, code, reliable) }
            }

            5 -> {
                val id = stream(side)
                val code = num()
                call(c, id, early, action) { c!!.stopSending(it, code) }
            }

            6 -> {
                val id = stream(side)
                val n = minOf(num(), 65_536L).toInt()
                call(c, id, early, action) { c!!.readStream(it, ByteArray(maxOf(n, 1)), 0, n) }
            }

            else -> {
                val code = num()
                if (c == null) return
                made(early, action)
                api { c.close(code, "fuzz", pair.now) }
            }
        }
    }

    private fun made(
        early: Boolean,
        action: Int,
    ) {
        if (early) ZeroRttCoverage.hit("early.${ACTIONS[action]}")
    }

    private inline fun call(
        c: ConnectionCore?,
        id: Long?,
        early: Boolean,
        action: Int,
        block: (Long) -> Unit,
    ) {
        if (c == null || id == null) return
        made(early, action)
        api { block(id) }
    }

    private fun step() {
        val wasAnswered = pair.client.earlyAccepted != null
        pair.step()
        if (pair.server?.earlyDataAccepted == true) serverAcceptedEarly = true
        tamper?.invoke(pair, !wasAnswered && pair.client.earlyAccepted != null)
        observe(0, pair.clientEvents)
        observe(1, pair.serverEvents)
        pair.clientEvents.clear()
        pair.serverEvents.clear()
        if (!wasAnswered && pair.client.earlyAccepted != null) onAnswer()
        checkInvariants()
    }

    /** The events [side]'s application just took, in order. */
    private fun observe(
        side: Int,
        events: List<ConnectionEvent>,
    ) {
        val c = core(side) ?: return
        for (e in events) {
            when (e) {
                is ConnectionEvent.Closed -> {
                    closedSeen[side] = true
                    (e.reason as? QuicException.ConnectionLost.Internal)?.let {
                        throw IllegalStateException("${name(side)}: the connection crashed: ${it.message}", it.cause ?: it)
                    }
                    if (side == 0) {
                        if (closedReason == null) closedReason = e.reason
                        if (c.earlyAccepted == null && !answered) ZeroRttCoverage.hit("lostBeforeAnswer")
                    }
                }

                ConnectionEvent.EarlyDataRejected -> {
                    if (side == 0) {
                        rejectedEvents++
                        check(rejectedEvents == 1) { "client: EarlyDataRejected raised $rejectedEvents times" }
                        check(c.earlyAccepted == false) { "client: EarlyDataRejected with earlyDataAccepted ${c.earlyAccepted}" }
                        // the application forgets every stream it opened: they are gone (RFC 9001 section 4.6.2)
                        for (id in streams[0]) if (StreamIds.isLocal(id, TlsRole.Client)) dropped += id
                        streams[0].removeAll { StreamIds.isLocal(it, TlsRole.Client) }
                        reachable[0].removeAll { StreamIds.isLocal(it, TlsRole.Client) }
                        finished[0].removeAll { StreamIds.isLocal(it, TlsRole.Client) }
                        c.streams.zeroRttResidueForTest()?.let { throw IllegalStateException("client: after the rejected 0-RTT: $it") }
                    }
                }

                ConnectionEvent.EarlyDataAccepted -> {
                    if (side == 0) acceptedEvents++
                }

                ConnectionEvent.HandshakeCompleted -> {
                    if (side == 1) serverHandshakeDone = true
                }

                ConnectionEvent.DatagramsReadable -> {
                    if (side == 1) checkServerTookEarly(e)
                }

                else -> {}
            }
            val id = streamEventIdForTest(e) ?: continue
            check(id !in finished[side]) { "${name(side)}: ${e::class.simpleName} for stream $id after its StreamFinished" }
            if (side == 0) check(id !in dropped) { "client: ${e::class.simpleName} for stream $id, which the rejected 0-RTT dropped" }
            val local = StreamIds.isLocal(id, if (side == 0) TlsRole.Client else TlsRole.Server)
            if (local) {
                check(
                    id in reachable[side],
                ) { "${name(side)}: ${e::class.simpleName} for stream $id, which its application never opened" }
            }
            if (side == 1 && !local) {
                checkServerTookEarly(e)
                // RFC 9000 section 17.2.3: "A client SHOULD attempt to resend data in 0-RTT packets after it sends a new Initial packet"
                if (retrySent && e is ConnectionEvent.StreamReadable && pair.server?.streamReceivedEarly(id) == true) {
                    ZeroRttCoverage.hit("retry.earlyDataArrived")
                }
            }
            if (e is ConnectionEvent.StreamOpened) {
                if (reachable[side].add(id)) streams[side] += id
            }
            if (e is ConnectionEvent.StreamFinished) finished[side] += id
        }
    }

    private var serverHandshakeDone = false

    /**
     * RFC 9001 section 4.6.2: "When rejecting 0-RTT, a server MUST NOT process any 0-RTT packets, even if it could." Before its
     * handshake completed, the server's application learns of the client's streams and datagrams only from accepted 0-RTT.
     */
    private fun checkServerTookEarly(e: ConnectionEvent) {
        if (serverHandshakeDone) return
        // what carries the client's data (a stream's end is no new data: a stream accepted early may end later, at a close)
        if (e !is ConnectionEvent.StreamOpened && e !is ConnectionEvent.StreamReadable && e !is ConnectionEvent.DatagramsReadable) return
        val s = pair.server ?: return
        if (s.earlyDataAccepted == true) serverAcceptedEarly = true
        check(serverAcceptedEarly) {
            "server: ${e::class.simpleName} before its handshake completed, with 0-RTT ${s.earlyDataAccepted} (a rejected 0-RTT was processed)"
        }
    }

    /** The server accepted the client's 0-RTT (its session no longer answers once the connection is released). */
    private var serverAcceptedEarly = false

    /** 0-RTT packets the client had sealed when it first held 1-RTT keys; -1 before. */
    private var sealedAtOneRtt = -1L

    /** The client learnt the server's answer to its 0-RTT in this round. */
    private fun onAnswer() {
        answered = true
        val c = pair.client
        ZeroRttCoverage.hit(if (c.earlyAccepted == true) "accepted" else "rejected")
        if (c.earlyAccepted == false) {
            ZeroRttCoverage.hit(if (isClosing(c)) "rejected.closes" else "rejected.goesOn")
            ZeroRttCoverage.hit("rejected.outcome$outcome")
            if (vn) ZeroRttCoverage.hit("vn.rejected")
        }
        if (retry && retrySent) ZeroRttCoverage.hit("retry.answered")
    }

    private fun checkInvariants() {
        for (side in 0..1) {
            val c = core(side) ?: continue
            if (isClosing(c)) check(closedSeen[side]) { "${name(side)} reached ${c.state} without a Closed event" }
            c.streams.invariantViolationForTest()?.let { throw IllegalStateException("${name(side)}: $it") }
            c.streams.sendCreditViolationForTest()?.let { throw IllegalStateException("${name(side)}: $it") }
            c.recoveryViolationForTest()?.let { throw IllegalStateException("${name(side)}: $it") }
            val settled = side == 1 || answeredOrClosed()
            for ((key, value) in c.sizesForTest()) {
                val bound = if (key == "zeroRttHeld") (if (settled) 0L else Long.MAX_VALUE) else sizeBound(key, c)
                check(value in 0..bound) { "${name(side)}: $key = $value outside 0..$bound" }
            }
            // every stream in the map is one the application can reach
            val role = if (side == 0) TlsRole.Client else TlsRole.Server
            if (!isClosing(c)) {
                for (id in c.streams.streamIdsForTest()) {
                    check(id in reachable[side]) {
                        "${name(
                            side,
                        )}: stream $id (${if (StreamIds.isLocal(
                                id,
                                role,
                            )
                        ) {
                            "ours"
                        } else {
                            "the peer's"
                        }}) is in the map, its application cannot reach it"
                    }
                }
            }
        }
        val c = pair.client
        // RFC 9000 section 17.2.3: "A client MUST NOT send 0-RTT packets once it starts processing 1-RTT packets from the server"
        if (c.writeKeys[3] != null) {
            if (sealedAtOneRtt < 0) sealedAtOneRtt = c.zeroRttPacketsSealed
            check(c.zeroRttPacketsSealed == sealedAtOneRtt) { "client: 0-RTT packets sealed after the 1-RTT keys arrived" }
        }
        if (c.earlyAccepted == false) {
            check(
                c.zeroRttPacketsSentForTest() == 0,
            ) { "client: ${c.zeroRttPacketsSentForTest()} rejected 0-RTT packets still in the sent history" }
            check(acceptedEvents == 0) { "client: EarlyDataAccepted and a rejection" }
            val closes = mode == EarlyDataState.Required || (c.rememberedAlpn ?: "") != (c.negotiatedAlpn ?: "")
            if (closes) {
                check(rejectedEvents == 0) { "client: EarlyDataRejected on a connection the rejection closes" }
                check(isClosing(c)) { "client: the rejection under ${mode.name} / ALPN ${c.negotiatedAlpn} did not close the connection" }
                if (!wasClosedBeforeAnswer) {
                    check(closedReason is QuicException.ConnectionLost.ZeroRttRejected) {
                        "client: closed by the rejection with $closedReason, not ZeroRttRejected"
                    }
                }
            } else if (!isClosing(c)) {
                check(
                    rejectedEvents == 1,
                ) { "client: rejected 0-RTT, the connection goes on, but EarlyDataRejected was raised $rejectedEvents times" }
            }
        }
        if (c.earlyAccepted == true) check(rejectedEvents == 0) { "client: EarlyDataRejected after an acceptance" }
        if (!answered && isClosing(c)) wasClosedBeforeAnswer = true
    }

    private var wasClosedBeforeAnswer = false

    /** Both sides close and run until they are gone; the invariants hold at the end too. */
    private fun finish() {
        var n = 0
        while (n++ < 300 && !answeredOrClosed()) {
            pair.advance(if (n < 100) 10.milliseconds else 1.seconds)
            step()
        }
        // the connection goes on after the answer: a request and its answer in 1-RTT, both sides reading everything (so the
        // acknowledgments of 1-RTT packets meet whatever 0-RTT state is left)
        if (!isClosing(pair.client)) {
            api {
                val id = pair.client.openStream(bidi = true)
                if (id >= 0) {
                    streams[0] += id
                    reachable[0] += id
                    dropped -= id
                    pair.client.writeStream(id, ByteArray(3000) { 1 }, 0, 3000, true)
                }
            }
        }
        n = 0
        val buf = ByteArray(65_536)
        while (n++ < 60 && !isClosing(pair.client)) {
            for (side in 0..1) {
                val c = core(side) ?: continue
                for (id in streams[side].toList()) api { c.readStream(id, buf, 0, buf.size) }
                var d = 0
                while (d++ < 64 && c.readDatagram(buf, 0) >= 0) { /* the application takes them */ }
            }
            pair.advance(20.milliseconds)
            step()
        }
        api { pair.client.close(0, "end", pair.now) }
        pair.server?.let { s -> api { s.close(0, "end", pair.now) } }
        n = 0
        while (n++ < 200 &&
            (pair.client.state != ConnectionState.Closed || pair.server?.let { it.state != ConnectionState.Closed } == true)
        ) {
            pair.advance(50.milliseconds)
            step()
        }
        check(pair.client.zeroRttHeldForTest() == 0) {
            "client: ${pair.client.zeroRttHeldForTest()} items still held for the 0-RTT answer at the end"
        }
    }

    private fun checkExpected(e: Expect) {
        val c = pair.client
        val got =
            when {
                acceptedEvents > 0 -> Expect.Accepted
                rejectedEvents > 0 -> Expect.RejectedGoesOn
                closedReason is QuicException.ConnectionLost.ZeroRttRejected -> Expect.RejectedCloses
                else -> null
            }
        check(got == e) {
            "expected $e, got $got (earlyDataAccepted ${c.earlyAccepted}, closed ${closedReason?.let {
                it::class.simpleName
            }}: ${closedReason?.message})"
        }
        if (e != Expect.RejectedCloses) {
            // the connection went on until the program closed it itself
            val r = closedReason
            check(
                r is QuicException.ConnectionLost.ApplicationClosed && r.initiator == io.kuicksilver.quic.Initiator.Local && r.code == 0L,
            ) {
                "after the $e answer the connection ended with ${r?.let { it::class.simpleName }}: ${r?.message}"
            }
        }
    }

    private fun name(side: Int) = if (side == 0) "client" else "server"

    private companion object {
        val ACTIONS = listOf("open", "write", "finish", "reset", "resetAt", "stopSending", "read", "close")
    }
}

/**
 * Tickets for the 0-RTT fuzzer, made by full handshakes with the origin server (one ticket per resumption: a ticket is
 * consumed by the session that resumes it). Every server of the fuzzer shares the origin's ticket keys, so a changed
 * configuration resumes the session and refuses only its early data.
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
internal object Tickets {
    private val ticketKeys = SessionTicketConfig(keys = listOf(ByteArray(80) { (it * 11 + 3).toByte() }))

    /** The client offers both ALPNs: the origin server picks the first, the ALPN-changing one only knows the second. */
    val clientTls: TlsConfig by lazy { CoreFixtures.client { alpn = listOf("hq-interop", "hq-alt") } }
    val serverTls: TlsConfig by lazy { CoreFixtures.server { sessionTickets = ticketKeys } }
    val altServerTls: TlsConfig by lazy { CoreFixtures.server(alpn = "hq-alt") { sessionTickets = ticketKeys } }

    fun originQuic(small: Boolean): QuicConfig.Builder =
        QuicConfig.Builder().apply {
            resetStreamAt = true
            if (small) {
                maxBidiStreams = 3
                maxUniStreams = 2
                initialStreamWindow = 2048
                initialConnectionWindow = 6000
            }
        }

    private val pools = arrayOf(ArrayDeque<QuicSessionTicket>(), ArrayDeque())

    @Synchronized
    fun take(small: Boolean): QuicSessionTicket {
        val pool = pools[if (small) 1 else 0]
        if (pool.isEmpty()) pool += fresh(small)
        return pool.removeFirst()
    }

    private fun fresh(small: Boolean): List<QuicSessionTicket> {
        val quic = originQuic(small).build()
        val p =
            CorePair(
                clientTls = clientTls,
                serverTls = serverTls,
                clientQuic = QuicConfig.Builder().apply { resetStreamAt = true }.build(),
                serverQuic = quic,
                crypto = ksl,
                clientEarly = EarlyDataState.Allowed,
                serverEarly = ServerEarlyData.of(quic, serverTls.alpn, null, ZeroRttReplayRegister(Random(3))),
                seed = 11,
            )
        try {
            check(p.handshake()) { "origin handshake: ${p.closedReason(p.clientEvents)} / ${p.closedReason(p.serverEvents)}" }
            p.runUntil(limit = 2.seconds) { p.clientEvents.count { it is ConnectionEvent.SessionTicket } >= 2 }
            val tickets = p.clientEvents.filterIsInstance<ConnectionEvent.SessionTicket>().map { it.ticket }
            check(tickets.isNotEmpty() && tickets.all { it.remembered != null }) { "no ticket with remembered parameters" }
            return tickets
        } finally {
            p.close()
        }
    }
}

/** Upper bounds of the per-connection collections, from the configuration: what a peer can make the core hold. */
internal fun sizeBound(
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

        // RFC 9000 section 8.2.2: every PATH_CHALLENGE "MUST" get its PATH_RESPONSE, so every one is queued; past three
        // waiting each costs a glitch token, and the cap closes the connection. A connection closed by the flood keeps what was
        // queued until it is Closed (a closing endpoint sends only CONNECTION_CLOSE, section 10.2.1), within the cap
        "pathResponses" -> io.kuicksilver.quic.core.Paths.MAX_RESPONSES.toLong()

        "sentInitial", "sentHandshake", "sentApplication" -> 50_000

        "ackRangesInitial", "ackRangesHandshake", "ackRangesApplication" -> cfg.limits.ackRanges.toLong() + 1

        "receiverBufferedBytes" -> cfg.limits.undecryptablePackets.toLong() * 65_536

        "cryptoBufferedBytes" -> 4L * (cfg.limits.cryptoOutOfOrderPerLevel + cfg.limits.cryptoPostHandshake)

        "datagramsQueued" -> cfg.datagramReceiveQueue.toLong()

        "challengedAddresses", "mtuUpdates" -> 64

        // nothing is held for a 0-RTT answer on a connection that never attempted 0-RTT
        "zeroRttHeld" -> 0

        else -> throw IllegalStateException("no bound for $key")
    }
}
