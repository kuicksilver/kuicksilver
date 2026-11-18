// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    io.kuicksilver.annotations.InternalKuicksilverApi::class,
    kotlin.concurrent.atomics.ExperimentalAtomicApi::class,
    kotlinx.coroutines.ExperimentalCoroutinesApi::class,
)

package io.kuicksilver.http3.runtime

import io.ktor.utils.io.readAvailable
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3PeerSettings
import io.kuicksilver.http3.frame.ControlFrames
import io.kuicksilver.http3.frame.FrameAction
import io.kuicksilver.http3.frame.FrameRules
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.H3ProtocolError
import io.kuicksilver.http3.frame.SettingsCodec
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.message.PriorityField
import io.kuicksilver.http3.qpack.entrySize
import io.kuicksilver.http3.runtime.H3Session.Companion.beforeControlFrameForTest
import io.kuicksilver.http3.runtime.H3Session.Companion.transportCause
import io.kuicksilver.http3.webtransport.WtSettings
import io.kuicksilver.http3.webtransport.WtVersion
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.rememberWithTickets
import io.kuicksilver.quic.runtime.QuicStreamLimits
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetch

// The peer's unidirectional streams: control, QPACK encoder and decoder streams, and what arrives on them (RFC 9114 sections 6.2 and 7.2, RFC 9204 section 4.2).

/**
 * One of the peer's unidirectional streams. A stream that ends or is reset before its type is dropped: RFC 9114 section
 * 6.2 says "A receiver MUST tolerate unidirectional streams being closed or reset prior to the reception of the
 * unidirectional stream header" (quic-go's `handleUnidirectionalStream` returns the same way). Each such stream spends
 * a glitch token, so a peer that only opens and abandons streams still meets H3_EXCESSIVE_LOAD (section 10.5).
 */
internal suspend fun H3Session.readUni(st: QuicStream) {
    // the stream's header (its type; a WebTransport stream's Session ID too) must arrive within maxHeaderBlockTime of its
    // first byte, as a request head must: a stream that never sends it would hold its reader and stream slot as long as the
    // peer keeps the connection alive (RFC 9000 section 21.6). Its type unknown, it is an unknown type to RFC 9114 section
    // 6.2: reading is aborted with H3_STREAM_CREATION_ERROR, never a connection error. A critical stream must not be
    // stopped that way (section 6.2.1: "the receiver MUST NOT request that the sender close the control stream"), and a
    // critical type value fits one byte but may be sent longer: a stalled stream is spared only while what arrived of its
    // type can still decode to a critical type not seen yet, and only as many such streams as types are missing, oldest
    // first ([sparedAsCritical]); every other one is stopped at its deadline.
    val reader = currentCoroutineContext()[Job]!!
    val header = UniHeader()
    uniTypesPending[st.id] = header
    uniProgress()
    // a var the reader drops once the header is read: a critical stream's reader runs as long as the connection, and its
    // frame must not keep the cancelled deadline (its job and cancellation cause) for all that time
    var deadline: Job? =
        scope.launch {
            delay(settings.maxHeaderBlockTime)
            while (true) {
                if (header.settled) return@launch
                val seen = uniTypeProgress.value
                if (!sparedAsCritical(header)) break
                uniTypeProgress.first { it != seen } // a byte, a stream identified or gone: decide again
            }
            header.settled = true
            uniDeadlinesPassedForTest++
            reader.cancel()
            runCatching { st.stopSending(header.rejectCode) }
            if (!header.known) {
                discardedUniStreams.value++
                guarded { glitch("unidirectional stream without its type in time") }
            }
        }
    uniDeadlinesArmed.incrementAndFetch()
    deadline?.invokeOnCompletion { uniDeadlinesArmed.decrementAndFetch() }

    fun headerRead() {
        header.settled = true
        deadline?.cancel()
        deadline = null
    }
    try {
        readUniArmed(st, header, ::headerRead)
    } finally {
        deadline?.cancel()
        uniTypesPending.remove(st.id)
        uniProgress()
    }
}

/** The peer's critical stream types (RFC 9114 section 6.2, RFC 9204 section 4.2). */
private val CRITICAL_TYPES = listOf(StreamType.CONTROL, StreamType.QPACK_ENCODER, StreamType.QPACK_DECODER)

/**
 * Whether [header]'s stalled stream is spared at its deadline as possibly one of the peer's critical streams: what arrived
 * of its type can still decode to a critical type not seen yet ([UniHeader.couldBeCritical]: every critical value is
 * below 256, so only a varint's length prefix with zero value bits, then zeros, leaves one possible), and it is among the
 * oldest such streams, at most one per critical type still missing. Session dispatcher only.
 */
private fun H3Session.sparedAsCritical(header: UniHeader): Boolean {
    if (!header.couldBeCritical()) return false
    val missing = CRITICAL_TYPES.count { it !in peerUni }
    if (missing == 0) return false
    val rank =
        uniTypesPending.values
            .asSequence()
            .filter { it.couldBeCritical() }
            .indexOf(header)
    return rank in 0 until missing
}

/** Where a peer's unidirectional stream is in its header, and the code its deadline stops it with. */
internal class UniHeader {
    /** The header was read (or given up): the deadline stands down. */
    var settled = false

    /** The type was read: the stream is no critical stream that could still be identified. */
    var known = false

    /** The bytes of the type's varint read so far (at most 8). */
    val prefix = ArrayList<Byte>(8)

    /**
     * What arrived of the type can still be a critical type (0x00, 0x02 or 0x03): nothing yet, or the first byte of a
     * longer varint whose value bits are all zero (0x40, 0x80, 0xc0) followed by zeros only; its last byte, which would
     * complete it, has not come.
     */
    fun couldBeCritical(): Boolean {
        if (known) return false
        if (prefix.isEmpty()) return true
        val first = prefix[0].toInt() and 0xff
        return (first == 0x40 || first == 0x80 || first == 0xc0) && prefix.drop(1).all { it.toInt() == 0 }
    }

    /**
     * H3_STREAM_CREATION_ERROR for a type that never arrived (RFC 9114 section 6.2: "If reading is aborted, the recipient
     * SHOULD use the H3_STREAM_CREATION_ERROR error code"); WT_BUFFERED_STREAM_REJECTED for a WebTransport stream whose
     * Session ID never came (it reached no session, draft-ietf-webtrans-http3-16 section 4.6).
     */
    var rejectCode = Http3ErrorCode.STREAM_CREATION_ERROR
}

/**
 * The type of a peer's unidirectional stream, read byte by byte into [header] (what [sparedAsCritical] decides on), with
 * the length it took; null at a clean end before its first byte, IncompleteFrame at an end inside it.
 */
private suspend fun H3Session.readUniType(
    st: QuicStream,
    header: UniHeader,
): Pair<Long, Int>? {
    val one = ByteArray(1)
    if (st.input.readAvailable(one, 0, 1) <= 0) {
        st.input.closedCause?.let { throw it }
        return null
    }
    header.prefix += one[0]
    uniProgress()
    val n = VarInt.encodedLength(one[0])
    val b = ByteArray(n)
    b[0] = one[0]
    var i = 1
    while (i < n) {
        val r = st.input.readAvailable(one, 0, 1)
        if (r < 0) throw st.input.closedCause ?: IncompleteFrame()
        if (r == 0) continue
        b[i++] = one[0]
        header.prefix += one[0]
        uniProgress()
    }
    return VarInt.read(b, 0, n) to n
}

private suspend fun H3Session.readUniArmed(
    st: QuicStream,
    header: UniHeader,
    headerRead: () -> Unit,
) {
    val (type, typeLength) =
        try {
            readUniType(st, header)
        } catch (_: IncompleteFrame) {
            null
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            if (transportCause(e) !is QuicException.StreamError) throw e
            null
        } ?: run {
            discardedUniStreams.value++
            glitch("unidirectional stream ended or reset before its type")
            return
        }
    header.known = true
    uniTypesPending.remove(st.id)
    uniProgress()
    if (type != StreamType.WT_UNI || !settings.webTransport) {
        headerRead()
        qlog { it.streamTypeSet("remote", st.id, type) } // a WebTransport stream is logged with its Session ID ([WtStreamRouter])
    }
    when (type) {
        StreamType.CONTROL, StreamType.QPACK_ENCODER, StreamType.QPACK_DECODER -> {
            if (!peerUni.add(type)) throw H3ProtocolError(Http3ErrorCode.STREAM_CREATION_ERROR, "second stream of type $type")
            criticalStreamsSeen.value++
            uniProgress()
            try {
                when (type) {
                    StreamType.CONTROL -> {
                        readControl(st)
                    }

                    StreamType.QPACK_ENCODER -> {
                        peerEncoderReading = true
                        try {
                            readQpack(st) { b, n -> qpack.onPeerEncoderStream(b, n) }
                        } finally {
                            peerEncoderReading = false
                        }
                    }

                    else -> {
                        readQpack(st) { b, n -> qpack.onPeerDecoderStream(b, n) }
                    }
                }
            } catch (
                e: IncompleteFrame,
            ) {
                throw H3ProtocolError(Http3ErrorCode.CLOSED_CRITICAL_STREAM, "critical stream $type closed")
            } catch (
                e: QuicException.StreamError,
            ) {
                throw H3ProtocolError(Http3ErrorCode.CLOSED_CRITICAL_STREAM, "critical stream $type reset")
            }
            throw H3ProtocolError(Http3ErrorCode.CLOSED_CRITICAL_STREAM, "critical stream $type closed")
        }

        StreamType.WT_UNI -> {
            if (settings.webTransport) {
                header.rejectCode = Http3ErrorCode.WT_BUFFERED_STREAM_REJECTED
                wt.onUni(st, typeLength, headerRead)
            } else {
                st.stopSending(Http3ErrorCode.STREAM_CREATION_ERROR)
                discardedUniStreams.value++
            }
        }

        // no push: a client never sent MAX_PUSH_ID (so any push ID is too large); a server never receives push streams
        StreamType.PUSH -> {
            throw H3ProtocolError(if (isServer) Http3ErrorCode.STREAM_CREATION_ERROR else Http3ErrorCode.ID_ERROR, "push stream")
        }

        else -> {
            st.stopSending(Http3ErrorCode.STREAM_CREATION_ERROR)
            discardedUniStreams.value++
        } // unknown or reserved type: not a connection error (RFC 9114 section 6.2)
    }
}

private suspend fun H3Session.readQpack(
    st: QuicStream,
    sink: suspend (ByteArray, Int) -> Unit,
) {
    val buf = ByteArray(4096)
    while (true) {
        val n = st.input.readAvailable(buf, 0, buf.size)
        if (n <
            0
        ) {
            st.input.closedCause?.let { throw it }
            return
        }
        if (n > 0) sink(buf, n)
    }
}

private suspend fun H3Session.readControl(st: QuicStream) {
    var first = true
    // reserved (GREASE) types are there to be ignored (sections 7.2.8, 9): a few are free, as on request streams, and a
    // flood of them spends glitch tokens as unknown types do (section 10.5)
    var freeGrease = RequestFrames.FREE_USELESS_FRAMES
    while (true) {
        val type = st.input.readVarIntOrNull() ?: return
        val len = st.input.readVarInt()
        val action =
            try {
                FrameRules.checkControl(type, first, isServer, settings.webTransport)
            } catch (e: H3ProtocolError) {
                // a frame the control stream must not carry: what was parsed of it (its header) is in the trace
                qlog { it.frameParsed(st.id, type, len, it.controlFrame(type, null)) }
                throw e
            }
        when (action) {
            FrameAction.Skip -> {
                when {
                    !FrameType.isGrease(type) -> glitch("unknown frame on the control stream")
                    freeGrease > 0 -> freeGrease--
                    else -> glitch("reserved frames on the control stream")
                }
                qlog { it.frameParsed(st.id, type, len, it.other(type, len)) }
                st.input.skipExact(len)
            }

            FrameAction.Process -> {
                try {
                    FrameRules.checkControlLength(type, len)
                } catch (e: H3ProtocolError) {
                    qlog { it.frameParsed(st.id, type, len, it.controlFrame(type, null)) }
                    throw e
                }
                beforeControlFrameForTest?.invoke(this, type)
                val payload = st.input.readExact(len.toInt())
                qlog { it.frameParsed(st.id, type, len, it.controlFrame(type, payload)) }
                onControlFrame(type, payload)
            }
        }
        first = false
    }
}

private suspend fun H3Session.onControlFrame(
    type: Long,
    payload: ByteArray,
) {
    when (type) {
        FrameType.SETTINGS -> {
            applyPeerSettings(SettingsCodec.decode(payload))
        }

        FrameType.GOAWAY -> {
            onGoAway(ControlFrames.parseGoAway(payload))
        }

        FrameType.PRIORITY_UPDATE_REQUEST -> {
            onPriorityUpdate(payload)
        }

        // server only (a client gets H3_FRAME_UNEXPECTED from FrameRules); RFC 9114 section 7.2.7
        FrameType.MAX_PUSH_ID -> {
            val id = ControlFrames.parseMaxPushId(payload)
            if (id < peerMaxPushId) throw H3ProtocolError(Http3ErrorCode.ID_ERROR, "MAX_PUSH_ID fell from $peerMaxPushId to $id")
            // we never push: after the first, a MAX_PUSH_ID does no useful work and spends a glitch token (section 10.5)
            if (peerMaxPushId >= 0) glitch("MAX_PUSH_ID after the first")
            peerMaxPushId = id
        }

        FrameType.PRIORITY_UPDATE_PUSH -> {
            throw H3ProtocolError(Http3ErrorCode.ID_ERROR, "PRIORITY_UPDATE for a push without server push")
        }

        else -> {}
    }
}

/**
 * Throws [Http3Exception.FieldSectionTooLarge] when [fields] (pseudo-headers included) exceed the peer's
 * `SETTINGS_MAX_FIELD_SECTION_SIZE`, counted as name + value + 32 per field (RFC 9114 section 4.2.2): the peer would
 * refuse it anyway. No limit is known before the peer's SETTINGS arrive.
 */
internal fun H3Session.checkPeerFieldLimit(
    streamId: Long,
    fields: List<Pair<String, String>>,
) {
    // until the server's SETTINGS arrive, the ones stored for 0-RTT bind us (RFC 9114 section 7.2.4.2)
    val ps = peerSettings.value
    val limit = (if (ps != null) ps.maxFieldSectionSize else storedPeerSettings?.get(SettingsId.MAX_FIELD_SECTION_SIZE)) ?: return
    var size = 0L
    for ((n, v) in fields) {
        size += entrySize(n, v)
        if (size > limit) throw Http3Exception.FieldSectionTooLarge(streamId, limit)
    }
}

private suspend fun H3Session.applyPeerSettings(m: Map<Long, Long>) {
    val known =
        setOf(
            SettingsId.QPACK_MAX_TABLE_CAPACITY,
            SettingsId.QPACK_BLOCKED_STREAMS,
            SettingsId.MAX_FIELD_SECTION_SIZE,
            SettingsId.ENABLE_CONNECT_PROTOCOL,
            SettingsId.H3_DATAGRAM,
        ) + WtSettings.ALL
    val ps =
        Http3PeerSettings(
            m[SettingsId.QPACK_MAX_TABLE_CAPACITY] ?: 0,
            m[SettingsId.QPACK_BLOCKED_STREAMS] ?: 0,
            m[SettingsId.MAX_FIELD_SECTION_SIZE],
            m[SettingsId.ENABLE_CONNECT_PROTOCOL] == 1L,
            m[SettingsId.H3_DATAGRAM] == 1L,
            m.filterKeys { it !in known },
            webTransport = WtVersion.of(m) != null,
        )
    // H3_DATAGRAM=1 without the transport's max_datagram_frame_size is no error: RFC 9297 section 2.1.1 makes only a
    // value other than 0 or 1 one (checked by the codec). HTTP/3 Datagrams are QUIC DATAGRAM frames (section 2.1), which
    // RFC 9221 section 3 forbids sending to such a peer, so none is sent ([DatagramDemux.unsupported])
    // draft-ietf-webtrans-http3-02 section 3.1: "an endpoint that receives a value other than "0" or "1" MUST close the
    // connection with the H3_SETTINGS_ERROR error code" (SETTINGS_WT_ENABLED is checked by the codec for every draft)
    if (settings.webTransport && (m[SettingsId.ENABLE_WEBTRANSPORT_DRAFT02] ?: 0L) > 1L) {
        throw H3ProtocolError(Http3ErrorCode.SETTINGS_ERROR, "SETTINGS_ENABLE_WEBTRANSPORT (draft-02) must be 0 or 1")
    }
    if (!isServer) {
        // RFC 9114 section 7.2.4.2: after an accepted 0-RTT, SETTINGS that lower or omit what the client relied on are
        // H3_SETTINGS_ERROR, a changed QPACK table capacity QPACK_DECODER_STREAM_ERROR (RFC 9204 section 3.2.3) (whether 0-RTT was accepted is known once the handshake is: SETTINGS are 1-RTT data)
        storedPeerSettings?.let { stored ->
            if (quic.earlyDataAccepted == null) quic.awaitHandshake()
            if (quic.earlyDataAccepted == true) {
                StoredSettings.incompatibility(stored, m)?.let { throw H3ProtocolError(it.code, it.reason) }
            }
        }
        // kept with this connection's tickets for the next 0-RTT ("Clients SHOULD store the settings")
        quic.rememberWithTickets(SettingsCodec.encode(StoredSettings.kept(m)))
    }
    qpack.onPeerSettings(ps.qpackMaxTableCapacity, ps.qpackBlockedStreams)
    wtCommonVersions = WtVersion.common(m, isServer)
    wtPeerSettings = m.filterKeys { it in WtSettings.ALL }.ifEmpty { emptyMap() } // no map held when the peer has none
    qlog { it.parametersSet("remote", m) }
    peerSettings.value = ps
    peerSettingsArrived.complete(ps)
}

internal fun H3Session.onGoAway(id: Long) {
    val prev = goAwayReceived.value
    if (prev != null && id > prev) throw H3ProtocolError(Http3ErrorCode.ID_ERROR, "GOAWAY id grew from $prev to $id")
    if (!isServer &&
        id % 4 != 0L
    ) {
        throw H3ProtocolError(Http3ErrorCode.ID_ERROR, "GOAWAY $id is not a client-initiated bidirectional stream")
    }
    goAwayReceived.value = id
    goAwaySeen.complete(Unit)
    if (!isServer) {
        for ((sid, st) in clientStreams.toList()) {
            if (sid >= id) { // never processed: fail them as retry-safe (section 5.2)
                rejectedByGoAway += sid
                runCatching { st.stopSending(Http3ErrorCode.REQUEST_CANCELLED) }
                runCatching { st.reset(Http3ErrorCode.REQUEST_CANCELLED) }
            }
        }
        closeIfIdleAfterGoAway()
    }
}

/**
 * RFC 9218 section 7 on a server: the client's new signal for a request stream. An open request takes it at once; a
 * stream whose request is not open yet (not opened, or its HEADERS still on the way) keeps it (at most
 * `maxEarlyPriorityUpdates`) and applies it when it opens; a stream beyond the limit we granted is H3_ID_ERROR
 * (section 7.2); every frame spends a glitch token, and early ones beyond the buffer one more. A frame of any length the
 * control stream accepts ([io.kuicksilver.http3.frame.FrameRules.MAX_CONTROL_PAYLOAD]) is checked and applied: a cap
 * below it would skip the H3_ID_ERROR checks and drop the most recent signal section 7 asks servers to apply.
 */
internal fun H3Session.onPriorityUpdate(payload: ByteArray) {
    priorityUpdatesForTest++
    glitch("PRIORITY_UPDATE")
    val (id, value) = ControlFrames.parsePriorityUpdate(payload)
    if (id % 4 != 0L) throw H3ProtocolError(Http3ErrorCode.ID_ERROR, "PRIORITY_UPDATE for stream $id, not a request stream")
    // a value that fails to parse carries no parameter (RFC 8941 section 4.2: "treated as if the field were not present"),
    // and the frame is "a complete set of all priority parameters" in which an omitted one means its default (RFC 9218
    // section 7): the defaults; the connection error section 7 allows (MAY) is not used
    val p = PriorityField.parse(value)
    activeServerRequests[id]?.let {
        it.onPriorityUpdate(p)
        return
    }
    // the transport hands streams out in id order: one taken whose handler ended is over
    if (id <= acceptedBidiUpTo && id !in handledBidi) return
    QuicStreamLimits.peerBidiStreamsGranted(quic)?.let {
        if (id / 4 >=
            it
        ) {
            throw H3ProtocolError(Http3ErrorCode.ID_ERROR, "PRIORITY_UPDATE for stream $id beyond the limit of $it streams")
        }
    }
    if (id in earlyPriority ||
        earlyPriority.size < settings.maxEarlyPriorityUpdates
    ) {
        earlyPriority[id] = p
    } else {
        glitch("early PRIORITY_UPDATE beyond the buffer")
    }
}
