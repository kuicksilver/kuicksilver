// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.qlog

import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.ConnectionStats
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.recovery.SpaceId
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.channels.Channel
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetch

/**
 * qlog JSON-SEQ writer (docs/guide/quic.md, "qlog"): schema `0.3` with the event names qvis opens; one record per line prefixed
 * by RS (0x1e). Writing stops silently once [maxBytes] were produced; the connection is never affected.
 *
 * The trace is opened lazily, at the first event: a server connection created for an Initial that does not decrypt emits
 * none, so a forged Initial costs no file. A sink whose `open`, `write` or `close` throws (EMFILE, ENOSPC; anything, a
 * CancellationException included) disables tracing for this connection only and is reported once to [onFailure]; [close] runs when the connection releases its resources. Records are written
 * on the loop thread: a [QlogSink] should buffer (DirectoryQlogSink does).
 *
 * The layer above (HTTP/3) adds its events through [enqueue] from any thread ([io.kuicksilver.quic.QlogRecorder]): each is
 * formatted whole by its caller and queued; the loop writes what is queued before its own next event ([drainExternal] too),
 * so the sink is only ever called on the loop and two records never interleave. The queue holds at most [MAX_QUEUED] events.
 */
@OptIn(ExperimentalAtomicApi::class)
internal class QlogWriter(
    private val sink: QlogSink,
    private val maxBytes: Long,
    private val start: TimeMark,
    private val role: TlsRole,
    private val odcidHex: String,
    /**
     * The connection may carry HTTP/3 (its ALPN list offers `h3`): the header's `protocol_type` names "HTTP3" next to
     * "QUIC" (draft-ietf-quic-qlog-quic-events-04 and -h3-events-04, section 2: MUST once an event of theirs is in the
     * trace), and only then are HTTP/3 events taken ([takesHttp3Events]).
     */
    private val http3: Boolean = false,
) {
    private var written = 0L
    private var closed = false
    private var ending = false
    private var closeLogged = false

    /** False once the trace ended ([close]); read on any thread by [enqueue] and the layer above. */
    @Volatile var enabled: Boolean = true
        private set

    /** Whether the layer above's HTTP/3 events are taken: the trace names HTTP3 and has not ended. */
    val takesHttp3Events: Boolean get() = http3 && enabled

    /** An event of the layer above: its clock reading and its `"name":...,"data":{...}` members. */
    private class Pending(
        val nanos: Long,
        val body: String,
    )

    /** Events of the layer above, formatted and waiting for the loop; at most [MAX_QUEUED] ([queued] counts them). */
    private val external = Channel<Pending>(Channel.UNLIMITED)

    /** The time of the last record written: no record gets an earlier one (main-schema-05 section 3.4.1). */
    private var lastNanos = Long.MIN_VALUE
    private val queued = AtomicInt(0)
    private val dropped = AtomicLong(0)

    /** Events of the layer above dropped because the queue was full. */
    val externalDropped: Long get() = dropped.load()

    private var trace: QlogTrace? = null

    /** The frames of the packet being logged (quic-events-04 section 8.11), filled by the packet builder and receiver. */
    val frames = QlogFrames()
    private var failure: Throwable? = null

    /**
     * Hears of the sink's first failure (the runtime logs it at warn level). Set after the first events may already have
     * failed (a server connection's first Initial is processed before the runtime exists): such a failure is reported here
     * when it is set.
     */
    var onFailure: ((Throwable) -> Unit)? = null
        set(value) {
            field = value
            val f = failure
            if (value != null && f != null) value(f)
        }

    private fun failed(e: Throwable) {
        if (failure != null) return
        failure = e
        onFailure?.invoke(e)
    }

    /**
     * Any thread: queues one event of the layer above, [data] being the members of its `data` object (already JSON). False
     * when it was not taken: the trace ended, or the queue is full (counted in [externalDropped]).
     */
    fun enqueue(
        name: String,
        data: String,
        now: TimeMark,
    ): Boolean {
        if (!takesHttp3Events) return false
        if (queued.incrementAndFetch() > MAX_QUEUED) {
            queued.decrementAndFetch()
            dropped.incrementAndFetch()
            return false
        }
        if (external.trySend(Pending(now.nanos, "\"name\":\"$name\",\"data\":{$data}")).isFailure) {
            queued.decrementAndFetch()
            return false
        }
        return true
    }

    /**
     * Loop: writes the queued events of the layer above, in the order they were queued, at [now] (the loop's clock, or the
     * time of the transport event about to be written). An event is written with its own time, kept between the last
     * record's time and [now]: one stamped on its thread later than the loop turn that writes it takes that turn's time,
     * so a transport event's time is never moved for it (main-schema-05 section 3.4.1: ascending times).
     */
    fun drainExternal(now: TimeMark) {
        while (!closed) {
            val r = external.tryReceive().getOrNull() ?: return
            queued.decrementAndFetch()
            val hi = if (now.nanos < lastNanos) lastNanos else now.nanos
            write(r.nanos.coerceAtMost(hi), r.body)
        }
    }

    private fun emit(
        nanos: Long,
        body: String,
    ) {
        drainExternal(TimeMark(nanos)) // what the layer above logged before this event comes first
        write(nanos, body)
    }

    /** Writes one event, at no earlier time than the record before it. */
    private fun write(
        nanos: Long,
        body: String,
    ) {
        if (closed) return
        val t = trace ?: open() ?: return
        if (nanos > lastNanos) lastNanos = nanos
        val record = "\u001e{\"time\":${time(TimeMark(lastNanos))},$body}\n"
        written += record.length
        try {
            t.write(record)
        } catch (e: Throwable) {
            failed(e)
            ending = true // nothing more reaches a failed sink, queued events included
            close()
            return
        }
        if (written >= maxBytes) {
            ending = true
            close()
        }
    }

    private fun open(): QlogTrace? {
        val t =
            try {
                sink.open(odcidHex, role)
            } catch (e: Throwable) {
                failed(e)
                null
            }
        if (t == null) {
            closed = true
            enabled = false
            return null
        }
        trace = t
        val header =
            "\u001e{\"qlog_format\":\"JSON-SEQ\",\"qlog_version\":\"0.3\",\"title\":\"kuicksilver\"," +
                "\"trace\":{\"vantage_point\":{\"type\":\"${role.name.lowercase()}\"}," +
                "\"common_fields\":{\"ODCID\":\"$odcidHex\",\"protocol_type\":${if (http3) "[\"QUIC\",\"HTTP3\"]" else "[\"QUIC\"]"}," +
                // main-schema-05 section 3.4.1: relative times count from the reference_time, here the trace's start
                // (section 3.4.1 allows such a reference instead of the Unix epoch, and no wall clock enters the trace)
                "\"time_format\":\"relative\",\"reference_time\":0.0}}}\n"
        written += header.length
        try {
            t.write(header)
        } catch (e: Throwable) {
            failed(e)
            ending = true
            close()
            return null
        }
        return t
    }

    /** Milliseconds since the trace's start; an event of the layer above stamped before it (another thread's clock) gets 0. */
    private fun time(now: TimeMark): String {
        val us = (now - start).inWholeMicroseconds.coerceAtLeast(0)
        return "${us / 1000}.${(us % 1000).toString().padStart(3, '0')}"
    }

    private fun event(
        now: TimeMark,
        name: String,
        data: String,
    ) = emit(now.nanos, "\"name\":\"$name\",\"data\":{$data}")

    private fun packetType(space: SpaceId) =
        when (space) {
            SpaceId.Initial -> "initial"
            SpaceId.Handshake -> "handshake"
            SpaceId.Application -> "1RTT"
        }

    /** quic-events-04 section 8.5 PacketType. */
    private fun packetType(type: PacketType) =
        when (type) {
            PacketType.Initial -> "initial"
            PacketType.ZeroRtt -> "0RTT"
            PacketType.Handshake -> "handshake"
            PacketType.OneRtt -> "1RTT"
            PacketType.Retry -> "retry"
        }

    /** The packet's header and size, and its frames when [frames] holds them for it (taken, so they are logged once). */
    private fun packet(
        type: PacketType,
        pn: Long,
        size: Int,
    ): String {
        val f = if (frames.ready) ",\"frames\":[" + frames.out + "]" else ""
        frames.abandon()
        return "\"header\":{\"packet_type\":\"${packetType(type)}\",\"packet_number\":$pn},\"raw\":{\"length\":$size}$f"
    }

    /** `transport:packet_sent` (section 5.5), with the frames [QlogFrames.sent] read from it before it was sealed. */
    fun packetSent(
        type: PacketType,
        pn: Long,
        size: Int,
        now: TimeMark,
    ) = event(now, "transport:packet_sent", packet(type, pn, size))

    /** `transport:packet_received` (section 5.6), with the frames [QlogFrames.receiving] recorded as they were processed. */
    fun packetReceived(
        type: PacketType,
        pn: Long,
        size: Int,
        now: TimeMark,
    ) = event(now, "transport:packet_received", packet(type, pn, size))

    /**
     * A packet authenticated and then dropped: qlog `transport:packet_dropped` with one of its [trigger]s and our [reason] in its
     * `details` map (the later quic-events drafts' field; qlog tools that do not know it ignore it).
     */
    fun packetDropped(
        space: SpaceId,
        pn: Long,
        size: Int,
        trigger: String,
        reason: String,
        now: TimeMark,
    ) = event(
        now,
        "transport:packet_dropped",
        "\"header\":{\"packet_type\":\"${packetType(space)}\",\"packet_number\":$pn},\"raw\":{\"length\":$size}," +
            "\"trigger\":\"$trigger\",\"details\":{\"reason\":\"$reason\"}",
    )

    /**
     * `recovery:packet_lost`, without a trigger: quic-events-04 section 7.5 names "reordering_threshold", "time_threshold"
     * and "pto_expired" apart, and the loss detector does not tell which of the first two declared the packet lost.
     */
    fun packetLost(
        space: SpaceId,
        pn: Long,
        now: TimeMark,
    ) = event(
        now,
        "recovery:packet_lost",
        "\"header\":{\"packet_type\":\"${packetType(space)}\",\"packet_number\":$pn}",
    )

    fun metricsUpdated(
        stats: ConnectionStats,
        now: TimeMark,
    ) = event(
        now,
        "recovery:metrics_updated",
        "\"min_rtt\":${stats.minRtt.inWholeMicroseconds / 1000.0},\"smoothed_rtt\":${stats.smoothedRtt.inWholeMicroseconds / 1000.0},\"rtt_variance\":${stats.rttVar.inWholeMicroseconds / 1000.0},\"congestion_window\":${stats.cwnd},\"bytes_in_flight\":${stats.bytesInFlight},\"pto_count\":${stats.ptoCount}",
    )

    fun connectionStateUpdated(
        state: ConnectionState,
        now: TimeMark,
    ) = event(now, "connectivity:connection_state_updated", "\"new\":\"${stateName(state)}\"")

    /** The ConnectionState of quic-events-04 section 4.6 (Figure 7) each of ours is. */
    private fun stateName(state: ConnectionState): String =
        when (state) {
            ConnectionState.Handshaking -> "handshake_started"
            ConnectionState.Established -> "handshake_complete"
            ConnectionState.Confirmed -> "handshake_confirmed"
            ConnectionState.Closing -> "closing"
            ConnectionState.Draining -> "draining"
            ConnectionState.Closed -> "closed"
        }

    fun connectionClosed(
        reason: QuicException.ConnectionLost,
        now: TimeMark,
    ) {
        if (closeLogged) return // one event per connection: the first reason, as the connection reports it
        closeLogged = true
        val d =
            when (reason) {
                is QuicException.ConnectionLost.TransportClosed -> {
                    "\"owner\":\"${reason.initiator.name.lowercase()}\"${connectionCode(reason.code)}," +
                        "\"reason\":\"${escape(
                            reason.reason,
                        )}\""
                }

                is QuicException.ConnectionLost.ApplicationClosed -> {
                    "\"owner\":\"${reason.initiator.name.lowercase()}\"" +
                        QlogFrames.applicationError(StringBuilder(), "application_code", reason.code) + "," +
                        "\"reason\":\"${escape(
                            reason.reason,
                        )}\""
                }

                is QuicException.ConnectionLost.Timeout -> {
                    "\"owner\":\"local\",\"trigger\":\"${reason.kind.name.lowercase()}_timeout\""
                }

                // quic-events-04 section 4.3 (Figure 4): the trigger is one of its values, the rest goes in "reason"
                is QuicException.ConnectionLost.StatelessReset -> {
                    "\"owner\":\"remote\",\"trigger\":\"stateless_reset\""
                }

                is QuicException.ConnectionLost.VersionNegotiation -> {
                    "\"owner\":\"remote\",\"trigger\":\"version_mismatch\",\"reason\":\"${escape(reason.message ?: "")}\""
                }

                else -> {
                    "\"owner\":\"local\",\"trigger\":\"error\",\"reason\":\"${escape(reason.message ?: "")}\""
                }
            }
        event(now, "connectivity:connection_closed", d)
        // the trace stays open through the closing or draining period (RFC 9000 section 10.2): the packets that carry and
        // answer the close are in it too; it ends when the connection releases its resources
    }

    /** Ends the trace (idempotent) after what the layer above queued so far; a sink whose close throws is ignored. */
    fun close() {
        if (!closed && !ending) {
            ending = true // a write below that ends the trace (cap, failure) closes it without draining again
            drainExternal(TimeMark(Long.MAX_VALUE))
        }
        closed = true
        enabled = false
        external.cancel() // what is queued from now on is dropped with the queue
        val t = trace ?: return
        trace = null
        try {
            t.close()
        } catch (e: Throwable) {
            failed(e)
        }
    }

    /** connection_code (section 4.3): TransportError or CryptoError by name, another code as a uint32, else left out. */
    private fun connectionCode(code: Long): String {
        val name = QlogFrames.transportErrorName(code)
        return when {
            name != null -> ",\"connection_code\":\"$name\""
            code in 0..0xffff_ffffL -> ",\"connection_code\":$code"
            else -> ""
        }
    }

    private fun escape(s: String): String = StringBuilder(s.length + 8).also { escapeInto(s, it) }.toString()

    internal companion object {
        /** Events of the layer above waiting for the loop at most; more are dropped. */
        const val MAX_QUEUED = 4096

        /** JSON string escaping (RFC 8259 section 7): quote, backslash, control characters and lone surrogates. */
        fun escapeInto(
            s: String,
            o: StringBuilder,
        ) {
            for (ch in s) {
                when {
                    ch == '"' -> o.append("\\\"")
                    ch == '\\' -> o.append("\\\\")
                    ch < ' ' || ch == '\u007f' || ch.isSurrogate() -> o.append("\\u").append(ch.code.toString(16).padStart(4, '0'))
                    else -> o.append(ch)
                }
            }
        }
    }
}
