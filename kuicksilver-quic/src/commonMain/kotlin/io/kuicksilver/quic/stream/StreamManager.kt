// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.flow.RecvFlowController
import io.kuicksilver.quic.flow.SendFlowController
import io.kuicksilver.quic.flow.StreamLimits
import io.kuicksilver.quic.recovery.SentFrames
import io.kuicksilver.quic.wire.FrameEncoder
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.quic.wire.VarInt
import io.kuicksilver.quic.wire.WireWriter
import io.kuicksilver.tls.TlsRole
import kotlin.time.Duration

internal enum class ControlKind {
    ResetStream,
    StopSending,
    MaxStreamData,
    StreamDataBlocked,
    DataBlocked,
    MaxData,
    MaxStreamsBidi,
    MaxStreamsUni,
    StreamsBlockedBidi,
    StreamsBlockedUni,
}

/** Control frames whose [ControlFrame.a] is an application error code, not a limit: a repeat never changes it. */
private val CODE_KINDS = setOf(ControlKind.ResetStream, ControlKind.StopSending)

/** A pending control frame: [a]/[b] carry the code, limit or final size. */
internal class ControlFrame {
    var kind: ControlKind = ControlKind.MaxData
    var id: Long = 0
    var a: Long = 0
    var b: Long = 0
}

/** Every stream of a connection, both directions, with the connection-level flow control and stream limits (RFC 9000 sections 2–4). */
internal class StreamManager(
    private val role: TlsRole,
    private val config: QuicConfig,
    private val connFlow: RecvFlowController,
    private val connSend: SendFlowController,
    private val limits: StreamLimits,
) {
    private class Entry(
        val id: Long,
    ) {
        var send: SendStream? = null
        var recv: RecvStream? = null
        var countedClosed = false

        /** Reused per stream: a readable/writable notification per packet must not allocate. */
        val readable = ConnectionEvent.StreamReadable(id)
        val writable = ConnectionEvent.StreamWritable(id)
    }

    private val streams = HashMap<Long, Entry>()
    private val scheduler = StreamScheduler()
    private val budget = RangeBudget(config.limits.reassemblyRangesPerConnection)
    private val control = ArrayDeque<ControlFrame>()
    private val controlPool = ArrayList<ControlFrame>() // frames come back through releaseControlFrame: no allocation per MAX_DATA

    private fun queueControl(
        kind: ControlKind,
        id: Long,
        a: Long,
        b: Long = 0,
    ) {
        val c =
            controlPool.removeLastOrNull() ?: ControlFrame()
        c.kind = kind
        c.id = id
        c.a = a
        c.b = b
        control += c
    }

    /** Queues [kind] for [id] unless one is already waiting, which then carries the larger value: one frame says the latest. */
    private fun queueOnce(
        kind: ControlKind,
        id: Long,
        a: Long,
        b: Long = 0,
    ) {
        for (i in 0 until control.size) {
            val c = control[i]
            if (c.kind == kind && c.id == id) {
                // a limit carries the latest (largest) value; a reset's or stop's error code stays its first one
                if (kind !in CODE_KINDS && a > c.a) c.a = a
                return
            }
        }
        queueControl(kind, id, a, b)
    }

    val events: ArrayDeque<ConnectionEvent> = ArrayDeque()
    private val nextIndex = longArrayOf(0, 0) // [bidi, uni]
    private var peerBidiLocal = 0L
    private var peerBidiRemote = 0L
    private var peerUni = 0L
    private var connReceived = 0L
    private val range = SendRange()
    private val scratch = ByteArray(2048)
    var sendBufferedBytes: Long = 0
        private set
    val reassemblyRanges: Int get() = budget.used
    var now: TimeMark = TimeMark(0)
    var smoothedRtt: Duration = config.initialRtt

    /**
     * The code of the RESET_STREAM that ended the last [read] answering -1, or null when that read found the peer's FIN:
     * the core answers -1 for both. Read right after [read], on the same thread.
     */
    var lastReadResetCode: Long? = null

    fun applyPeerParameters(
        initialMaxStreamDataBidiLocal: Long,
        initialMaxStreamDataBidiRemote: Long,
        initialMaxStreamDataUni: Long,
        maxStreamsBidi: Long,
        maxStreamsUni: Long,
    ) {
        peerBidiLocal = initialMaxStreamDataBidiLocal
        peerBidiRemote = initialMaxStreamDataBidiRemote
        peerUni = initialMaxStreamDataUni
        limits.onPeerMaxStreams(true, maxStreamsBidi)
        limits.onPeerMaxStreams(false, maxStreamsUni)
    }

    fun isOpen(id: Long): Boolean = streams.containsKey(id)

    // ---- 0-RTT (RFC 9000 section 7.4.1, ADR-0015) ----
    private val early = HashSet<Long>()

    fun markReceivedEarly(id: Long) {
        if (streams.containsKey(id)) early += id
    }

    fun receivedEarly(id: Long): Boolean = id in early

    /** After an accepted 0-RTT: streams we opened take the server's new initial limits (they only grow). */
    fun raiseLocalSendLimits(
        bidiRemote: Long,
        uni: Long,
    ) {
        for ((id, limit) in sendLimit) {
            if (!StreamIds.isLocal(id, role)) continue
            if (limit.onMaxUpdate(
                    if (StreamIds.isBidi(id)) bidiRemote else uni,
                )
            ) {
                streams[id]?.send?.let { if (it.hasPending) scheduler.reschedule(it) }
            }
        }
    }

    /**
     * After a rejected 0-RTT whose data fits ([localSendFits]): the server's new limits replace the remembered ones on every
     * stream we opened and for the stream counts, also where they are lower (RFC 9000 section 7.4.1).
     */
    fun adoptLocalSendLimits(
        bidiRemote: Long,
        uni: Long,
        maxStreamsBidi: Long,
        maxStreamsUni: Long,
    ) {
        limits.resetPeerMaxStreams(true, maxStreamsBidi)
        limits.resetPeerMaxStreams(false, maxStreamsUni)
        for ((id, limit) in sendLimit) {
            if (!StreamIds.isLocal(id, role)) continue
            limit.resetLimit(if (StreamIds.isBidi(id)) bidiRemote else uni)
        }
    }

    /** After a rejected 0-RTT: whether what our streams already used fits the server's new limits, so resending it is allowed. */
    fun localSendFits(
        bidiRemote: Long,
        uni: Long,
        maxStreamsBidi: Long,
        maxStreamsUni: Long,
    ): Boolean {
        if (limits.localOpened(true) > maxStreamsBidi || limits.localOpened(false) > maxStreamsUni) return false
        for ((id, limit) in sendLimit) {
            if (!StreamIds.isLocal(id, role)) continue
            if (limit.used > if (StreamIds.isBidi(id)) bidiRemote else uni) return false
        }
        return true
    }

    /** Receive window of stream [id] and of the connection (test hooks: auto-tuning). */
    internal fun recvWindowForTest(id: Long): Long = streams[id]?.recv?.flow?.window ?: -1

    internal val connWindowForTest: Long get() = connFlow.window

    fun takeControlFrame(): ControlFrame? = control.removeFirstOrNull()

    fun pushBackControlFrame(c: ControlFrame) {
        control.addFirst(c)
    }

    /** The builder wrote [c]; the object is reused. */
    fun releaseControlFrame(c: ControlFrame) {
        controlPool += c
    }

    fun hasControlFrames(): Boolean = control.isNotEmpty()

    fun hasStreamData(): Boolean = scheduler.next() != null

    /**
     * Fuzzing probe (stateful connection fuzzer): the first broken flow-control or stream-state invariant, or null. Data
     * received on the connection and on each stream stays within what we advertised, data we sent within what the peer
     * allowed, a final size bounds what was received, every byte a stream received was charged to the connection, and the peer
     * opened no more streams than we granted.
     */
    internal fun invariantViolationForTest(): String? {
        if (connReceived > connFlow.limit) return "connection received $connReceived beyond the advertised ${connFlow.limit}"
        var streamsReceived = 0L
        for (e in streams.values) streamsReceived += e.recv?.highest ?: 0L
        if (streamsReceived > connReceived) return "streams received $streamsReceived, the connection was charged $connReceived"
        if (connSend.used > connSend.maxLimit) return "connection sent ${connSend.used} beyond the peer's ${connSend.maxLimit}"
        // each stream may hold one range beyond the gap limit: the readable one at its read offset
        if (budget.used < 0 || budget.used > budget.max + streams.size) return "reassembly ranges ${budget.used} outside 0..${budget.max}"
        if (sendBufferedBytes < 0) return "negative send buffer $sendBufferedBytes"
        for ((id, e) in streams) {
            e.recv?.let { r ->
                if (r.highest > r.flow.limit) return "stream $id received ${r.highest} beyond the advertised ${r.flow.limit}"
                if (r.finalSize >= 0 &&
                    r.highest > r.finalSize
                ) {
                    return "stream $id received ${r.highest} beyond its final size ${r.finalSize}"
                }
            }
            e.send?.let { snd ->
                val limit = sendLimit[id]
                if (limit != null &&
                    snd.sentEnd > limit.maxLimit
                ) {
                    return "stream $id sent ${snd.sentEnd} beyond the peer's ${limit.maxLimit}"
                }
                if (snd.sentEnd > snd.written) return "stream $id sent ${snd.sentEnd} beyond what was written (${snd.written})"
            }
        }
        for (bidi in booleanArrayOf(true, false)) {
            val opened = limits.peerStreamsOpened(bidi)
            val granted = limits.peerMaxStreamsGranted(bidi)
            if (opened > granted) return "peer opened $opened ${if (bidi) "bidi" else "uni"} streams, granted $granted"
        }
        return null
    }

    /** The number of [bidi] or unidirectional streams the peer may open, as our last MAX_STREAMS (or transport parameter) said. */
    internal fun peerMaxStreamsGranted(bidi: Boolean): Long = limits.peerMaxStreamsGranted(bidi)

    /** Fuzzing probe: (streams, queued control frames, pending events) held by this manager. */
    internal fun sizesForTest(): IntArray = intArrayOf(streams.size, control.size, events.size, sendLimit.size, early.size)

    /** Range comparisons made by the send half of stream [id] (complexity tests). */
    internal fun sendRangeStepsForTest(id: Long): Long = streams[id]?.send?.rangeStepsForTest ?: -1

    /** How often a stream was handed to the scheduler, for the complexity tests. */
    internal val schedulerTouchesForTest: Long get() = scheduler.addsForTest

    private fun newEntry(id: Long): Entry {
        val local = StreamIds.isLocal(id, role)
        val bidi = StreamIds.isBidi(id)
        val e = Entry(id)
        if (local ||
            bidi
        ) {
            e.send =
                SendStream(id, StreamPriority.Default).also { s ->
                    sendLimit[id] =
                        SendFlowController(
                            if (!bidi) {
                                peerUni
                            } else if (local) {
                                peerBidiRemote
                            } else {
                                peerBidiLocal
                            },
                        )
                }
        }
        if (!local ||
            bidi
        ) {
            e.recv =
                RecvStream(
                    id,
                    Reassembler(config.limits.reassemblyRangesPerStream, budget),
                    RecvFlowController(config.initialStreamWindow, config.maxStreamWindow),
                )
        }
        streams[id] = e
        return e
    }

    private val sendLimit = HashMap<Long, SendFlowController>()

    /** An [open] of that type ([0] bidi, [1] uni) was refused at the peer's limit; MAX_STREAMS then raises StreamsAvailable. */
    private val openBlocked = BooleanArray(2)

    fun open(
        bidi: Boolean,
        priority: StreamPriority,
    ): Long {
        if (!limits.canOpenLocal(bidi)) {
            openBlocked[if (bidi) 0 else 1] = true
            limits.takeStreamsBlocked(bidi).let {
                if (it >=
                    0
                ) {
                    queueControl(if (bidi) ControlKind.StreamsBlockedBidi else ControlKind.StreamsBlockedUni, 0, it)
                }
            }
            return -1
        }
        val i = if (bidi) 0 else 1
        val id = StreamIds.of(role, bidi, nextIndex[i])
        nextIndex[i]++
        limits.onLocalOpened(bidi)
        newEntry(id).send!!.priority = priority
        return id
    }

    /**
     * The entry a frame for [id] refers to, opening peer streams on the way (RFC 9000 section 3.2). Null when the stream
     * was already closed and retired: frames for closed streams are ignored (section 3; a spurious retransmit must not
     * fail the connection). A locally initiated stream the application never opened is STREAM_STATE_ERROR.
     */
    private fun peerStream(
        id: Long,
        frameType: Long,
        receiving: Boolean,
    ): Entry? {
        val bidi = StreamIds.isBidi(id)
        val local = StreamIds.isLocal(id, role)
        // the missing half of a unidirectional stream, live, retired or not yet opened (RFC 9000 sections 19.4, 19.5, 19.8, 19.10,
        // 19.13): STREAM, RESET_STREAM and STREAM_DATA_BLOCKED on our send-only stream, MAX_STREAM_DATA and STOP_SENDING on our
        // receive-only one
        if (!bidi && receiving == local) {
            throw QuicWireException(
                TransportError.STREAM_STATE_ERROR,
                frameType,
                "frame 0x${frameType.toString(16)} on our ${if (local) "send" else "receive"}-only stream $id",
            )
        }
        streams[id]?.let { return it }
        val i = if (bidi) 0 else 1
        if (local) {
            if (StreamIds.index(id) < nextIndex[i]) return null
            throw QuicWireException(TransportError.STREAM_STATE_ERROR, frameType, "stream $id was not opened by us")
        }
        if (StreamIds.index(id) < nextPeerIndex[i]) return null
        limits.onPeerStream(id)
        // opening a stream opens every lower-numbered stream of the same kind (RFC 9000 section 3.2)
        var index = nextPeerIndex[i]
        while (index <=
            StreamIds.index(id)
        ) {
            val sid =
                StreamIds.of(
                    if (role ==
                        TlsRole.Client
                    ) {
                        TlsRole.Server
                    } else {
                        TlsRole.Client
                    },
                    bidi,
                    index,
                )
            ; if (!streams.containsKey(sid)) {
                newEntry(sid)
                events += ConnectionEvent.StreamOpened(sid)
            }
            index++
        }
        nextPeerIndex[i] = index
        return streams[id]!!
    }

    private val nextPeerIndex = longArrayOf(0, 0)

    fun onStream(
        id: Long,
        offset: Long,
        data: PacketBuffer,
        off: Int,
        len: Int,
        fin: Boolean,
    ) {
        val e = peerStream(id, 0x08, receiving = true) ?: return
        val r = e.recv ?: throw QuicWireException(TransportError.STREAM_STATE_ERROR, 0x08, "STREAM frame on our send-only stream $id")
        val before = r.readable
        connReceived += r.onData(offset, data, off, len, fin, connFlow, connReceived) // checks both windows before it changes anything
        if (r.stopped) {
            creditConnection(r.abandon())
            if (r.finished) maybeClose(id)
        } // nothing will read a stopped stream: its bytes go straight back to the connection window, and the FIN retires it
        else if (r.readable > before || (fin && r.readable == 0)) {
            events += e.readable
        }
    }

    fun onResetStream(
        id: Long,
        code: Long,
        finalSize: Long,
    ) {
        val e =
            peerStream(id, 0x04, receiving = true) ?: return
        val r =
            e.recv ?: throw QuicWireException(TransportError.STREAM_STATE_ERROR, 0x04, "RESET_STREAM on our send-only stream $id")
        connReceived += r.onReset(code, finalSize, connFlow, connReceived)
        creditConnection(r.abandon())
        events += ConnectionEvent.StreamReset(id, code)
        if (r.stopped) maybeClose(id) // a stopped half has no reader to surface the reset to
    }

    fun onStopSending(
        id: Long,
        code: Long,
    ) {
        val e =
            peerStream(id, 0x05, receiving = false) ?: return
        val s =
            e.send ?: throw QuicWireException(TransportError.STREAM_STATE_ERROR, 0x05, "STOP_SENDING on our receive-only stream $id")
        if (s.state == SendState.ResetSent || s.state == SendState.DataRecvd) return
        sendBufferedBytes -= s.reset()
        scheduler.remove(s)
        wakeRefusedWriters()
        queueControl(ControlKind.ResetStream, id, code, s.sentEnd)
        events += ConnectionEvent.StopSendingReceived(id, code)
        maybeClose(id)
    }

    /** False when the frame changed nothing (a glitch); true for a real update or a frame on a stream that is gone. */
    fun onMaxStreamData(
        id: Long,
        max: Long,
    ): Boolean {
        val e =
            peerStream(id, 0x11, receiving = false) ?: return true
        val s =
            e.send ?: throw QuicWireException(TransportError.STREAM_STATE_ERROR, 0x11, "MAX_STREAM_DATA on our receive-only stream $id")
        val grew = sendLimit[id]!!.onMaxUpdate(max)
        if (!grew) return false // like MAX_DATA: a frame that raises nothing costs no work (it spends no glitch token either)
        if (s.hasPending) scheduler.add(s)
        if (s.sentEnd < s.written) events += e.writable // data was waiting for this credit
        return true
    }

    /** Connection-level credit for bytes the application consumed or will never read. */
    private fun creditConnection(bytes: Long) {
        if (bytes >
            0
        ) {
            connFlow.onConsumed(bytes, now, smoothedRtt).let { if (it >= 0) queueOnce(ControlKind.MaxData, 0, it) }
        }
    }

    /** Streams that ran out of connection-level credit, rescheduled by the next MAX_DATA that raises it (and only by that). */
    private val connBlocked = ArrayList<SendStream>()

    fun onMaxData(max: Long): Boolean {
        val grew = connSend.onMaxUpdate(max)
        if (!grew) return false // RFC 9000 section 21.6: a frame that raises nothing must not cost a pass over the streams
        for (i in connBlocked.indices) {
            val s = connBlocked[i]
            s.connBlocked = false
            val e = streams[s.id] ?: continue
            if (e.send !== s) continue
            if (s.hasPending) scheduler.add(s)
            if (s.sentEnd < s.written) events += e.writable
        }
        connBlocked.clear()
        return true
    }

    private fun blockedOnConnection(s: SendStream) {
        if (s.connBlocked) return
        if (connBlocked.size >= 2 * streams.size + 16) { // drop streams closed while waiting, so the list stays bounded by the live ones
            connBlocked.removeAll { (streams[it.id]?.send !== it).also { gone -> if (gone) it.connBlocked = false } }
        }
        s.connBlocked = true
        connBlocked += s
    }

    fun onMaxStreams(
        bidi: Boolean,
        max: Long,
    ): Boolean {
        val grew = limits.onPeerMaxStreams(bidi, max)
        val i = if (bidi) 0 else 1
        if (grew && openBlocked[i]) {
            openBlocked[i] = false
            events += if (bidi) availableBidi else availableUni
        }
        return grew
    }

    private val availableBidi = ConnectionEvent.StreamsAvailable(true)
    private val availableUni = ConnectionEvent.StreamsAvailable(false)

    /** STREAMS_BLOCKED from the peer: below the limit we granted, our MAX_STREAMS was lost or is still in flight, so it goes out again. */
    fun onStreamsBlocked(
        bidi: Boolean,
        limit: Long,
    ) {
        if (limits.peerMaxStreamsGranted(bidi) > limit) queueMaxStreams(bidi)
    }

    /** When the peer's last DATA_BLOCKED arrived. */
    private var dataBlockedSeenAt = TimeMark.NEVER

    /**
     * DATA_BLOCKED from the peer (RFC 9000 sections 4.1 and 19.12). Below the limit we granted, our MAX_DATA was lost or is still in
     * flight: the current one goes out at once rather than after our PTO backoff. A repeat from less than an RTT ago is not
     * answered (the answer to the previous one is still in flight), so a flood buys at most one MAX_DATA per RTT. It is not a
     * glitch either: quiche reports DATA_BLOCKED on every `stream_send` that finds the window short, in almost every packet of a
     * download (interop run 20261015-005204).
     */
    fun onDataBlocked(
        limit: Long,
        now: TimeMark,
        smoothedRtt: Duration,
    ) {
        if (!blockedReportDue(dataBlockedSeenAt, now, smoothedRtt)) return
        dataBlockedSeenAt = now
        if (limit < connFlow.limit) queueOnce(ControlKind.MaxData, 0, connFlow.limit)
    }

    /** STREAM_DATA_BLOCKED from the peer (RFC 9000 sections 4.1 and 19.13), answered like [onDataBlocked] with the stream's MAX_STREAM_DATA. */
    fun onStreamDataBlocked(
        id: Long,
        limit: Long,
        now: TimeMark,
        smoothedRtt: Duration,
    ) {
        val e = peerStream(id, 0x15, receiving = true) ?: return
        val r =
            e.recv ?: throw QuicWireException(TransportError.STREAM_STATE_ERROR, 0x15, "STREAM_DATA_BLOCKED on our send-only stream $id")
        if (!blockedReportDue(r.blockedSeenAt, now, smoothedRtt)) return
        r.blockedSeenAt = now
        // once the final size is known no more credit is needed (RFC 9000 section 13.3)
        if (limit < r.flow.limit && r.finalSize < 0) queueOnce(ControlKind.MaxStreamData, id, r.flow.limit)
    }

    private fun blockedReportDue(
        last: TimeMark,
        now: TimeMark,
        smoothedRtt: Duration,
    ): Boolean = last == TimeMark.NEVER || now - last >= smoothedRtt

    private fun queueMaxStreams(bidi: Boolean) {
        val kind = if (bidi) ControlKind.MaxStreamsBidi else ControlKind.MaxStreamsUni
        for (i in 0 until control.size) {
            if (control[i].kind == kind) {
                control[i].a = limits.peerMaxStreamsGranted(bidi)
                return
            } // one queued frame carries the latest limit
        }
        queueControl(kind, 0, limits.peerMaxStreamsGranted(bidi))
    }

    fun write(
        id: Long,
        data: ByteArray,
        off: Int,
        len: Int,
        fin: Boolean,
    ): Int {
        val s = streams[id]?.send ?: throw IllegalStateException("stream $id is not writable")
        check(s.state != SendState.ResetSent) { "stream $id was reset" }
        val accepted = minOf(len.toLong(), config.maxSendBuffer - sendBufferedBytes).toInt()
        if (accepted <= 0 && !fin) return 0
        s.enqueue(data, off, accepted, fin && accepted == len)
        sendBufferedBytes += accepted
        if (s.hasPending) scheduler.add(s)
        if (accepted < len && !s.writeRefused) { // the send buffer is full: StreamWritable follows once acknowledgements free room
            s.writeRefused = true
            writeRefused += s
        }
        return accepted
    }

    fun read(
        id: Long,
        into: ByteArray,
        off: Int,
        len: Int,
    ): Int {
        val e = streams[id] ?: return 0 // not opened yet (peer-initiated) or already finished: nothing to read
        val r = e.recv ?: throw IllegalStateException("stream $id is not readable")
        val wasReset = r.state == RecvState.ResetRecvd || r.state == RecvState.ResetRead
        val n = r.read(into, off, len)
        lastReadResetCode = if (n < 0 && wasReset) r.resetCode else null
        if (n > 0) {
            r.connCredited += n
            creditConnection(n.toLong())
            r.flow.onConsumed(n.toLong(), now, smoothedRtt).let {
                if (it >=
                    0
                ) {
                    // RFC 9000 section 13.3: no more stream credit once the final size is known
                    if (r.finalSize < 0) queueOnce(ControlKind.MaxStreamData, id, it)
                    if (connFlow.ensureWindowAtLeast(r.flow.window * 3 / 2)) queueOnce(ControlKind.MaxData, 0, connFlow.limit)
                }
            } // connection window ≥ 1.5 × stream window
        }
        if (n < 0) maybeClose(id)
        return n
    }

    /** For stream limits a peer stream counts as closed when both halves are done and the application consumed it (RFC 9000 sections 3.3 and 4.6) — counting earlier would let a peer open unread streams without bound. */
    private fun countClosed(e: Entry) {
        if (e.countedClosed || StreamIds.isLocal(e.id, role)) return
        e.countedClosed = true
        limits.onPeerStreamClosed(StreamIds.isBidi(e.id)).let {
            if (it >=
                0
            ) {
                queueControl(if (StreamIds.isBidi(e.id)) ControlKind.MaxStreamsBidi else ControlKind.MaxStreamsUni, 0, it)
            }
        }
    }

    private fun maybeClose(id: Long) {
        val e = streams[id] ?: return
        val sendDone = e.send?.let { it.state == SendState.DataRecvd || it.state == SendState.ResetSent } ?: true
        val recvDone = e.recv?.finished ?: true
        if (sendDone &&
            recvDone
        ) {
            countClosed(e)
            streams.remove(id)
            sendLimit.remove(id)
            e.send?.let { scheduler.remove(it) }
            events +=
                ConnectionEvent.StreamFinished(id)
        }
    }

    fun reset(
        id: Long,
        code: Long,
    ) {
        val s =
            streams[id]?.send ?: return
        if (s.state ==
            SendState.ResetSent
        ) {
            return
        }
        sendBufferedBytes -= s.reset()
        scheduler.remove(s)
        wakeRefusedWriters()
        queueControl(ControlKind.ResetStream, id, code, s.sentEnd)
        maybeClose(id)
    }

    fun stopSending(
        id: Long,
        code: Long,
    ) {
        val r =
            streams[id]?.recv ?: return
        if (r.stopped) return
        r.stopped = true
        r.discardBuffered()
        creditConnection(r.abandon())
        if (r.wantsStopSending) queueControl(ControlKind.StopSending, id, code)
        if (r.finished) maybeClose(id)
    }

    fun setPriority(
        id: Long,
        p: StreamPriority,
    ) {
        val s = streams[id]?.send ?: return
        s.priority = p
        if (s.schedQueue >= 0) scheduler.reschedule(s)
    }

    /** Writes one STREAM frame for the next scheduled stream into [w]; records it in [frames]. False when nothing can be sent. */
    fun writeStreamFrame(
        w: WireWriter,
        frames: SentFrames,
    ): Boolean {
        while (true) {
            val s = scheduler.next() ?: return false
            val limit = sendLimit[s.id]!!
            val overhead = FrameEncoder.streamOverhead(s.id, s.nextOffset, w.remaining)
            val space = w.remaining - overhead
            if (space <= 0) return false
            // flow credit applies to new data only (offsets beyond what was ever sent)
            var allowed = space
            if (!s.hasRetransmit) allowed = minOf(allowed.toLong(), limit.available, connSend.available).toInt()
            if (!s.nextRange(maxOf(allowed, 0), range) || (range.length == 0 && !range.fin)) {
                if (!s.hasRetransmit &&
                    s.sentEnd < s.written
                ) {
                    limit.takeBlocked().let {
                        if (it >=
                            0
                        ) {
                            queueControl(ControlKind.StreamDataBlocked, s.id, it)
                            blockedEpoch++
                            if (!s.streamBlockedListed) {
                                s.streamBlockedListed = true
                                streamBlocked += s
                            }
                        }
                    }
                    if (connSend.available <= 0) blockedOnConnection(s)
                    connSend.takeBlocked().let {
                        if (it >=
                            0
                        ) {
                            queueControl(ControlKind.DataBlocked, 0, it)
                            blockedEpoch++
                        }
                    }
                }
                scheduler.remove(s)
                continue
            }
            val newBytes = maxOf(0L, range.offset + range.length - s.sentEnd)
            if (newBytes > 0) {
                limit.consume(newBytes)
                connSend.consume(newBytes)
            }
            FrameEncoder.streamHeader(w, s.id, range.offset, range.length, range.fin, withLength = true)
            val buf = if (range.length <= scratch.size) scratch else ByteArray(range.length)
            s.copy(range.offset, buf, 0, range.length)
            w.bytes(buf, 0, range.length)
            frames.addStream(s.id, range.offset, range.length, range.fin)
            s.markSent(range.offset, range.length, range.fin)
            if (!s.hasPending) {
                scheduler.remove(s)
            } else if (s.priority.incremental) {
                scheduler.rotate(s)
            }
            return true
        }
    }

    /** Bumped whenever a new DATA_BLOCKED / STREAM_DATA_BLOCKED limit is reported: the core restarts its repeat timer. */
    var blockedEpoch: Int = 0
        private set

    /** Streams that reported STREAM_DATA_BLOCKED; pruned by [flowBlocked] once they are no longer blocked. */
    private val streamBlocked = ArrayList<SendStream>()

    private fun stillStreamBlocked(s: SendStream): Boolean {
        val e = streams[s.id] ?: return false
        if (e.send !== s || s.sentEnd >= s.written) return false
        val limit = sendLimit[s.id] ?: return false
        return limit.stillBlockedAt(limit.maxLimit)
    }

    private fun stillConnBlocked(): Boolean = connBlocked.isNotEmpty() && connSend.stillBlockedAt(connSend.maxLimit)

    /** True while some data waits for credit the peer has not given: a reported DATA_BLOCKED or STREAM_DATA_BLOCKED still holds. */
    fun flowBlocked(): Boolean {
        var i = 0
        while (i < streamBlocked.size) {
            val s = streamBlocked[i]
            if (stillStreamBlocked(s)) {
                i++
            } else {
                s.streamBlockedListed = false
                streamBlocked[i] = streamBlocked[streamBlocked.size - 1]
                streamBlocked.removeAt(streamBlocked.size - 1)
            }
        }
        return streamBlocked.isNotEmpty() || stillConnBlocked()
    }

    /**
     * Queues every report that still holds again (RFC 9000 section 4.1): a sender with nothing in flight cannot learn that the
     * receiver's MAX_DATA / MAX_STREAM_DATA was lost, so it asks again rather than wait on the receiver's PTO backoff.
     */
    fun repeatBlockedReports() {
        if (flowBlocked()) {
            for (i in streamBlocked.indices) {
                val s = streamBlocked[i]
                queueOnce(ControlKind.StreamDataBlocked, s.id, sendLimit[s.id]!!.maxLimit)
            }
            if (stillConnBlocked()) queueOnce(ControlKind.DataBlocked, 0, connSend.maxLimit)
        }
    }

    /** Streams whose [write] took fewer bytes than offered; each gets StreamWritable once acknowledgements free buffer room. */
    private val writeRefused = ArrayList<SendStream>()

    fun onFramesAcked(f: SentFrames) {
        val bufferedBefore = sendBufferedBytes
        for (i in 0 until f.streamCount) {
            val s =
                streams[f.streamId[i]]?.send ?: continue
            if (s.state ==
                SendState.ResetSent
            ) {
                continue // reset() already released the buffer
            }
            sendBufferedBytes -=
                s.onAcked(f.streamOffset[i], f.streamLength[i], f.streamFin[i])
            if (s.state == SendState.DataRecvd) maybeClose(s.id)
        }
        if (sendBufferedBytes < bufferedBefore) wakeRefusedWriters()
    }

    /** The send buffer has room again: every stream whose write was cut short learns it (and live ones only). */
    private fun wakeRefusedWriters() {
        if (writeRefused.isEmpty()) return
        for (i in writeRefused.indices) {
            val s = writeRefused[i]
            s.writeRefused = false
            val e = streams[s.id] ?: continue
            if (e.send === s && s.state != SendState.ResetSent) events += e.writable
        }
        writeRefused.clear()
    }

    fun onFramesLost(f: SentFrames) {
        for (i in 0 until f.streamCount) {
            val s =
                streams[f.streamId[i]]?.send ?: continue
            s.onLost(f.streamOffset[i], f.streamLength[i], f.streamFin[i])
            if (s.hasPending) scheduler.reschedule(s)
        }
        for (i in 0 until f.idCount) {
            when (f.idKind[i]) {
                SentFrames.ID_MAX_STREAM_DATA -> {
                    streams[f.idValue[i]]?.recv?.let {
                        if (it.finalSize <
                            0
                        ) {
                            queueOnce(ControlKind.MaxStreamData, f.idValue[i], it.flow.limit)
                        }
                    }
                }

                SentFrames.ID_RESET_STREAM -> {
                    queueOnce(ControlKind.ResetStream, f.idValue[i], f.idExtra[i], f.idExtra2[i])
                }

                // final size travels with the frame: the stream may be retired by now
                SentFrames.ID_STOP_SENDING -> {
                    if (streams[f.idValue[i]]?.recv?.wantsStopSending == true) {
                        queueOnce(ControlKind.StopSending, f.idValue[i], f.idExtra[i])
                    }
                }

                // still blocked at the reported limit with data waiting: the report goes again (RFC 9000 section 13.3 lets it be
                // dropped, but a lost one leaves a sender with nothing in flight waiting on the receiver's PTO backoff)
                SentFrames.ID_STREAM_DATA_BLOCKED -> {
                    val s = streams[f.idValue[i]]?.send
                    if (s != null && s.sentEnd < s.written && sendLimit[f.idValue[i]]?.stillBlockedAt(f.idExtra[i]) == true) {
                        queueOnce(ControlKind.StreamDataBlocked, f.idValue[i], f.idExtra[i])
                    }
                }
            }
        }
        if (f.flags and SentFrames.DATA_BLOCKED != 0 && connBlocked.isNotEmpty() && connSend.stillBlockedAt(connSend.maxLimit)) {
            queueOnce(ControlKind.DataBlocked, 0, connSend.maxLimit)
        }
        if (f.flags and SentFrames.STREAMS_BLOCKED_BIDI != 0) {
            limits.stillStreamsBlocked(true).let { if (it >= 0) queueOnce(ControlKind.StreamsBlockedBidi, 0, it) }
        }
        if (f.flags and SentFrames.STREAMS_BLOCKED_UNI != 0) {
            limits.stillStreamsBlocked(false).let { if (it >= 0) queueOnce(ControlKind.StreamsBlockedUni, 0, it) }
        }
        if (f.flags and SentFrames.MAX_DATA != 0) queueOnce(ControlKind.MaxData, 0, connFlow.limit)
        if (f.flags and SentFrames.MAX_STREAMS_BIDI != 0) queueMaxStreams(true) // with the current limit, which may have grown since
        if (f.flags and SentFrames.MAX_STREAMS_UNI != 0) queueMaxStreams(false)
    }

    /** Varint size helper for the packet builder. */
    fun controlOverhead(c: ControlFrame): Int =
        1 + VarInt.size(c.id) + VarInt.size(c.a) + (if (c.kind == ControlKind.ResetStream) VarInt.size(c.b) else 0)
}
