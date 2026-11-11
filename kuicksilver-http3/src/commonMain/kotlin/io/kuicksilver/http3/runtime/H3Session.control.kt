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
import io.kuicksilver.http3.message.PriorityField
import io.kuicksilver.http3.qpack.entrySize
import io.kuicksilver.http3.runtime.H3Session.Companion.MAX_PRIORITY_UPDATE
import io.kuicksilver.http3.runtime.H3Session.Companion.beforeControlFrameForTest
import io.kuicksilver.http3.runtime.H3Session.Companion.transportCause
import io.kuicksilver.http3.webtransport.WtSettings
import io.kuicksilver.http3.webtransport.WtVersion
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.runtime.QuicStreamLimits
import kotlinx.coroutines.CancellationException

// The peer's unidirectional streams: control, QPACK encoder and decoder streams, and what arrives on them (RFC 9114 sections 6.2 and 7.2, RFC 9204 section 4.2).

/**
 * One of the peer's unidirectional streams. A stream that ends or is reset before its type is dropped: RFC 9114 section
 * 6.2 says "A receiver MUST tolerate unidirectional streams being closed or reset prior to the reception of the
 * unidirectional stream header" (quic-go's `handleUnidirectionalStream` returns the same way). Each such stream spends
 * a glitch token, so a peer that only opens and abandons streams still meets H3_EXCESSIVE_LOAD (section 10.5).
 */
internal suspend fun H3Session.readUni(st: QuicStream) {
    val type =
        try {
            st.input.readVarIntOrNull()
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
    when (type) {
        StreamType.CONTROL, StreamType.QPACK_ENCODER, StreamType.QPACK_DECODER -> {
            if (!peerUni.add(type)) throw H3ProtocolError(Http3ErrorCode.STREAM_CREATION_ERROR, "second stream of type $type")
            criticalStreamsSeen.value++
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
                wt.onUni(st)
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
    while (true) {
        val type = st.input.readVarIntOrNull() ?: return
        val len = st.input.readVarInt()
        when (FrameRules.checkControl(type, first, isServer, settings.webTransport)) {
            FrameAction.Skip -> {
                // reserved (GREASE) types are there to be ignored (sections 7.2.8, 9) and cost nothing, as on request streams
                if (!FrameType.isGrease(type)) glitch("unknown frame on the control stream")
                st.input.skipExact(len)
            }

            FrameAction.Process -> {
                FrameRules.checkControlLength(type, len)
                beforeControlFrameForTest?.invoke(this, type)
                onControlFrame(type, st.input.readExact(len.toInt()))
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
    val limit = peerSettings.value?.maxFieldSectionSize ?: return
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
    // H3_DATAGRAM=1 needs the transport's max_datagram_frame_size (RFC 9297 section 2.1: HTTP/3 Datagrams are QUIC DATAGRAM
    // frames), as quic-go and quiche check: any value above 0 is support (RFC 9221 section 3), however small
    if (ps.h3Datagram &&
        !quic.peerSupportsDatagrams
    ) {
        throw H3ProtocolError(Http3ErrorCode.SETTINGS_ERROR, "H3_DATAGRAM without QUIC datagram support")
    }
    qpack.onPeerSettings(ps.qpackMaxTableCapacity, ps.qpackBlockedStreams)
    peerWtVersion = WtVersion.of(m)
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
 * (section 7.2); frames above 256 bytes and the excess are ignored and spend glitch tokens.
 */
internal fun H3Session.onPriorityUpdate(payload: ByteArray) {
    priorityUpdatesForTest++
    glitch("PRIORITY_UPDATE")
    if (payload.size > MAX_PRIORITY_UPDATE) {
        glitch("oversized PRIORITY_UPDATE")
        return
    }
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
