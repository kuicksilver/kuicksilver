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

    val events: ArrayDeque<ConnectionEvent> = ArrayDeque()
    private val opened = ArrayList<Long>()
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

    fun takeOpenedStreams(): List<Long> {
        val l = opened.toList()
        opened.clear()
        return l
    }

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
    private fun peerStream(id: Long): Entry? {
        streams[id]?.let { return it }
        val bidi = StreamIds.isBidi(id)
        val i = if (bidi) 0 else 1
        if (StreamIds.isLocal(id, role)) {
            if (StreamIds.index(id) < nextIndex[i]) return null
            throw QuicWireException(TransportError.STREAM_STATE_ERROR, 0x08, "stream $id was not opened by us")
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
                opened +=
                    sid
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
        val e = peerStream(id) ?: return
        val r = e.recv ?: throw QuicWireException(TransportError.STREAM_STATE_ERROR, 0x08, "STREAM frame on our send-only stream $id")
        val before = r.readable
        val advanced = r.onData(offset, data, off, len, fin)
        if (advanced > 0) {
            connReceived += advanced
            connFlow.onData(connReceived)
        }
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
            peerStream(id) ?: return
        val r =
            e.recv ?: throw QuicWireException(TransportError.STREAM_STATE_ERROR, 0x04, "RESET_STREAM on our send-only stream $id")
        val advanced = r.onReset(code, finalSize)
        if (advanced > 0) {
            connReceived += advanced
            connFlow.onData(connReceived)
        }
        creditConnection(r.abandon())
        events += ConnectionEvent.StreamReset(id, code)
        if (r.stopped) maybeClose(id) // a stopped half has no reader to surface the reset to
    }

    fun onStopSending(
        id: Long,
        code: Long,
    ) {
        val e =
            peerStream(id) ?: return
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
            peerStream(id) ?: return true
        val s =
            e.send ?: throw QuicWireException(TransportError.STREAM_STATE_ERROR, 0x11, "MAX_STREAM_DATA on our receive-only stream $id")
        val grew = sendLimit[id]!!.onMaxUpdate(max)
        if (s.hasPending) scheduler.add(s)
        if (grew && s.sentEnd < s.written) events += e.writable // data was waiting for this credit
        return grew
    }

    /** Connection-level credit for bytes the application consumed or will never read. */
    private fun creditConnection(bytes: Long) {
        if (bytes >
            0
        ) {
            connFlow.onConsumed(bytes, now, smoothedRtt).let { if (it >= 0) queueControl(ControlKind.MaxData, 0, it) }
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
        val n = r.read(into, off, len)
        if (n > 0) {
            r.connCredited += n
            creditConnection(n.toLong())
            r.flow.onConsumed(n.toLong(), now, smoothedRtt).let {
                if (it >=
                    0
                ) {
                    queueControl(ControlKind.MaxStreamData, id, it)
                    if (connFlow.ensureWindowAtLeast(r.flow.window * 3 / 2)) queueControl(ControlKind.MaxData, 0, connFlow.limit)
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
        queueControl(ControlKind.StopSending, id, code)
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
                        }
                    }
                    if (connSend.available <= 0) blockedOnConnection(s)
                    connSend.takeBlocked().let {
                        if (it >=
                            0
                        ) {
                            queueControl(ControlKind.DataBlocked, 0, it)
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
                    streams[f.idValue[i]]?.recv?.let { queueControl(ControlKind.MaxStreamData, f.idValue[i], it.flow.limit) }
                }

                SentFrames.ID_RESET_STREAM -> {
                    queueControl(ControlKind.ResetStream, f.idValue[i], f.idExtra[i], f.idExtra2[i])
                }

                // final size travels with the frame: the stream may be retired by now
                SentFrames.ID_STOP_SENDING -> {
                    queueControl(ControlKind.StopSending, f.idValue[i], f.idExtra[i])
                }

                SentFrames.ID_STREAM_DATA_BLOCKED -> {}
            }
        }
        if (f.flags and SentFrames.MAX_DATA != 0) queueControl(ControlKind.MaxData, 0, connFlow.limit)
        if (f.flags and SentFrames.MAX_STREAMS_BIDI != 0) queueMaxStreams(true) // with the current limit, which may have grown since
        if (f.flags and SentFrames.MAX_STREAMS_UNI != 0) queueMaxStreams(false)
    }

    /** Varint size helper for the packet builder. */
    fun controlOverhead(c: ControlFrame): Int =
        1 + VarInt.size(c.id) + VarInt.size(c.a) + (if (c.kind == ControlKind.ResetStream) VarInt.size(c.b) else 0)
}
