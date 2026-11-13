// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.http2.core

import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.H2
import io.kuicksilver.http2.frame.H2ConnectionError
import io.kuicksilver.http2.frame.SettingId
import io.kuicksilver.http2.hpack.HpackError
import io.kuicksilver.http2.hpack.entrySize

// The frames a peer sends, one handler per type (RFC 9113 section 6); the checks of section 5.1 and 4.3 live in the handlers.

internal fun H2ConnectionCore.onData(
    f: Frame.Data,
    now: Long,
) {
    val id = f.streamId
    if (f.data.isEmpty() && !f.endStream) {
        if (++emptyDataInARow > settings.maxEmptyFrames) calm("more than ${settings.maxEmptyFrames} empty DATA frames in a row")
        glitch(now, "empty DATA")
    } else {
        emptyDataInARow = 0
    }
    // section 6.9: every DATA counts toward the connection window, whatever its stream's state
    if (!connRecv.onData(f.flowLength)) throw H2ConnectionError(Http2ErrorCode.FLOW_CONTROL_ERROR, "DATA beyond the connection window")
    val s = streams[id]
    if (s == null || s.state == StreamState.CLOSED || s.state == StreamState.HALF_CLOSED_REMOTE) {
        creditConnection(f.flowLength.toLong(), now)
        if (s == null && isIdle(id)) throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "DATA on idle stream $id")
        // half-closed (remote) or closed: STREAM_CLOSED (sections 5.1, 6.1), except on a stream we reset or discarded,
        // which gets minimal processing (section 5.1, "closed")
        if (s?.state == StreamState.HALF_CLOSED_REMOTE || recentlyClosed[id] != true) {
            streamError(id, Http2ErrorCode.STREAM_CLOSED, "DATA on a closed stream", now)
        }
        return
    }
    if (!s.finalHeadersReceived) {
        creditConnection(f.flowLength.toLong(), now)
        return streamError(id, Http2ErrorCode.PROTOCOL_ERROR, "DATA before the final field section (section 8.1)", now)
    }
    if (!s.recv.onData(f.flowLength)) {
        creditConnection(f.flowLength.toLong(), now)
        return streamError(id, Http2ErrorCode.FLOW_CONTROL_ERROR, "DATA beyond the stream window", now)
    }
    val padding = f.flowLength - f.data.size
    if (padding > 0) credit(s, padding.toLong(), now) // padding is never read by the application
    s.unconsumed += f.data.size
    emit(H2Event.Data(id, f.data, f.endStream))
    if (f.endStream) remoteEnded(s)
}

internal fun H2ConnectionCore.startBlock(
    id: Int,
    promised: Int,
    endStream: Boolean,
    dependency: Int,
    fragment: ByteArray,
    endHeaders: Boolean,
    now: Long,
) {
    block.reset()
    if (!block.add(fragment, continuation = false)) calm("field block above ${2 * settings.maxHeaderListSize} bytes")
    blockStream = id
    blockPromised = promised
    blockEndStream = endStream
    blockDependency = dependency
    blockStartedAt = now
    inBlock = true
    if (endHeaders) endBlock(now)
}

internal fun H2ConnectionCore.onContinuation(
    f: Frame.Continuation,
    now: Long,
) {
    if (!inBlock) throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "CONTINUATION without a field block")
    if (!block.add(f.fragment, continuation = true)) {
        calm("field block above ${2 * settings.maxHeaderListSize} bytes or ${settings.maxContinuationFrames} CONTINUATION frames")
    }
    if (f.endHeaders) endBlock(now)
}

private fun H2ConnectionCore.endBlock(now: Long) {
    inBlock = false
    val fields = ArrayList<Pair<String, String>>()
    // a compressed block above the list limit (but within twice it) fails its stream only: it is still decoded for HPACK
    val compressedFits = block.size <= settings.maxHeaderListSize
    val fits =
        try {
            hpackIn.decode(block.block()) { n, v -> if (compressedFits) fields += n to v }
        } catch (e: HpackError) {
            throw H2ConnectionError(Http2ErrorCode.COMPRESSION_ERROR, e.message ?: "HPACK decoding error") // section 4.3
        }
    block.reset()
    if (blockPromised !=
        0
    ) {
        onPushPromiseBlock(blockPromised, now)
    } else {
        onHeaders(
            blockStream,
            if (compressedFits) fields else emptyList(),
            fits && compressedFits,
            now,
        )
    }
}

internal fun H2ConnectionCore.onHeaders(
    id: Int,
    fields: List<Pair<String, String>>,
    fits: Boolean,
    now: Long,
) {
    val endStream = blockEndStream
    val s = streams[id]
    if (s == null) {
        if (!peerInitiated(id) || client) {
            // a client never accepts a stream from the server (no push); a stream of ours we never opened is idle
            if (isIdle(id)) throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "HEADERS on idle stream $id")
            if (recentlyClosed[id] == false) headersOnClosed(id)
            return
        }
        if (id <= lastPeerStreamId) {
            // section 5.1.1: identifiers only grow; a closed stream we remember answers STREAM_CLOSED
            when (recentlyClosed[id]) {
                false -> headersOnClosed(id)

                true -> Unit

                null -> throw H2ConnectionError(
                    Http2ErrorCode.PROTOCOL_ERROR,
                    "stream $id is not above the last stream $lastPeerStreamId",
                )
            }
            return
        }
        lastPeerStreamId = id
        if (goAwaySentLastId in 0 until id) {
            rememberClosed(id, weReset = true) // after our GOAWAY: discarded, its frames too; the block fed HPACK (section 6.8)
            return
        }
        // RFC 7540 section 5.3.1: a stream cannot depend on itself; RFC 9113 has no such rule, kept for h2spec (http2/5.3.1)
        if (blockDependency == id) return streamError(id, Http2ErrorCode.PROTOCOL_ERROR, "stream depends on itself", now)
        if (peerStreams >= settings.maxConcurrentStreams) {
            // section 5.1.2: REFUSED_STREAM; a peer that keeps opening past the limit is flooding (golang/go#63417: Go's
            // server.go scheduleHandler allows 4 x the limit of unstarted handlers)
            if (++refusedInARow > 4 * maxOf(settings.maxConcurrentStreams, 1)) {
                calm("more than ${4 * settings.maxConcurrentStreams} refused streams in a row")
            }
            return resetStream(id, Http2ErrorCode.REFUSED_STREAM, now, causedByPeer = false)
        }
        val ns =
            H2Stream(
                id,
                local = false,
                state = if (endStream) StreamState.HALF_CLOSED_REMOTE else StreamState.OPEN,
                sendWindow = peerInitialWindow,
                recv = RecvWindow(recvInitialWindow, settings.maxStreamWindow.toLong()),
            )
        ns.finalHeadersReceived = true
        streams[id] = ns
        peerStreams++
        emit(H2Event.HeadersReceived(id, fields, endStream, !fits, opening = true))
        return
    }
    if (s.state == StreamState.CLOSED) {
        if (recentlyClosed[id] != true) headersOnClosed(id)
        return
    }
    if (blockDependency ==
        id
    ) {
        return streamError(id, Http2ErrorCode.PROTOCOL_ERROR, "stream depends on itself (RFC 7540 section 5.3.1)", now)
    }
    if (s.state == StreamState.HALF_CLOSED_REMOTE) return streamError(id, Http2ErrorCode.STREAM_CLOSED, "HEADERS after END_STREAM", now)
    if (s.finalHeadersReceived) {
        // trailers (section 8.1): they end the stream
        if (!endStream) return streamError(id, Http2ErrorCode.PROTOCOL_ERROR, "a second field section without END_STREAM", now)
    } else if (client) {
        val status = fields.firstOrNull()?.takeIf { it.first == ":status" }?.second
        // section 8.6: HTTP/2 does not support 101 (Switching Protocols); a response carrying it is malformed
        if (status == "101") return streamError(id, Http2ErrorCode.PROTOCOL_ERROR, "status 101 over HTTP/2 (section 8.6)", now)
        val informational = status != null && status.length == 3 && status[0] == '1'
        // section 8.1: an interim response with END_STREAM is malformed
        if (informational &&
            endStream
        ) {
            return streamError(id, Http2ErrorCode.PROTOCOL_ERROR, "an interim response with END_STREAM", now)
        }
        if (informational) {
            // any number of interim responses (RFC 9110 section 15.2), but not unbounded: all of them together within
            // our field section limit, as kuicksilver-http3 does; past it the response is discarded (section 8.2)
            s.interimBytes += fields.sumOf { entrySize(it.first, it.second).toLong() }
            if (s.interimBytes > settings.maxHeaderListSize) return resetStream(id, Http2ErrorCode.CANCEL, now, causedByPeer = false)
        } else {
            s.finalHeadersReceived = true
        }
    }
    emit(H2Event.HeadersReceived(id, fields, endStream, !fits))
    if (endStream) remoteEnded(s)
}

/**
 * HEADERS on a stream that closed without a reset of ours (both END_STREAM flags, or the peer's RST_STREAM): RFC 9113
 * section 5.1, "closed", lets an endpoint treat it as a connection error of type STREAM_CLOSED, and RFC 7540 section 5.1
 * required that after END_STREAM; a peer that sends it has lost track of its streams (h2spec http2/5.1/12). Frames the
 * peer may still send after our END_STREAM or reset (WINDOW_UPDATE, RST_STREAM; anything on a stream we reset) are not
 * this.
 */
private fun H2ConnectionCore.headersOnClosed(id: Int): Nothing =
    throw H2ConnectionError(Http2ErrorCode.STREAM_CLOSED, "HEADERS on closed stream $id")

internal fun H2ConnectionCore.onPushPromise(
    f: Frame.PushPromise,
    now: Long,
) {
    // a client cannot push (section 8.4); our SETTINGS_ENABLE_PUSH = 0, once acknowledged, forbids it (section 6.6)
    if (!client) throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "PUSH_PROMISE from a client")
    if (settingsUnacked ==
        0
    ) {
        throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "PUSH_PROMISE after SETTINGS_ENABLE_PUSH = 0 was acknowledged")
    }
    val p = f.promisedStreamId
    if (p == 0 || p and 1 == 1 ||
        p <= lastPeerStreamId
    ) {
        throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "invalid promised stream $p")
    }
    val s = streams[f.streamId]
    val valid = s != null && (s.state == StreamState.OPEN || s.state == StreamState.HALF_CLOSED_LOCAL)
    // section 6.6: on a stream neither open nor half-closed (local) it is a connection error, unless we reset that stream
    if (!valid &&
        recentlyClosed[f.streamId] != true
    ) {
        throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "PUSH_PROMISE on stream ${f.streamId}")
    }
    lastPeerStreamId = p
    startBlock(f.streamId, p, false, -1, f.fragment, f.endHeaders, now)
}

private fun H2ConnectionCore.onPushPromiseBlock(
    promised: Int,
    now: Long,
) {
    // the push our SETTINGS had not yet forbidden: the block was decoded for HPACK, the stream is cancelled
    resetStream(promised, Http2ErrorCode.CANCEL, now, causedByPeer = false)
}

internal fun H2ConnectionCore.onPriority(
    f: Frame.Priority,
    now: Long,
) {
    glitch(now, "PRIORITY") // deprecated (section 5.3.2): no state, but not for free (nghttp2 does the same)
    // RFC 7540 section 5.3.1: a stream cannot depend on itself; RFC 9113 has no such rule, kept for h2spec (http2/5.3.1)
    if (f.dependency == f.streamId) streamError(f.streamId, Http2ErrorCode.PROTOCOL_ERROR, "stream depends on itself", now)
}

internal fun H2ConnectionCore.onRstStream(
    f: Frame.RstStream,
    now: Long,
) {
    val id = f.streamId
    if (isIdle(id) && streams[id] == null) throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "RST_STREAM on idle stream $id")
    // Rapid Reset: a server counts every RST_STREAM of the client (nghttp2_session.c session_update_stream_reset_ratelim);
    // a client does not (a server may answer early and reset with NO_ERROR, section 8.1)
    if (!client && !resets.take(now)) calm("stream resets above ${settings.resetsPerSecond}/s (burst ${settings.resetBurst})")
    val s = streams[id] ?: return
    if (s.state == StreamState.CLOSED) {
        // closed on our side by an END_STREAM still in the queue: nothing more goes out on a reset stream (section 6.4)
        dropQueued(s)
        rememberClosed(id, weReset = false)
        if (s.released) removeStream(s)
        return
    }
    val code = Http2ErrorCode.of(f.errorCode)
    closeStream(s, weReset = false)
    emit(H2Event.StreamReset(id, code, byPeer = true, notProcessed = code == Http2ErrorCode.REFUSED_STREAM))
}

internal fun H2ConnectionCore.onSettings(
    f: Frame.Settings,
    now: Long,
) {
    if (f.ack) {
        if (settingsUnacked == 0) return
        settingsUnacked--
        if (settingsSentAt >= 0) rttNanos = maxOf(1, now - settingsSentAt)
        ourSettingsAcknowledged()
        return
    }
    glitch(now, "SETTINGS")
    var windowShrank = false
    for (i in f.ids.indices) {
        val v = f.values[i]
        when (f.ids[i]) {
            SettingId.HEADER_TABLE_SIZE -> {
                hpackOut.setPeerMaxTableSize(v)
            }

            // applied to the next block written, after our ACK
            SettingId.ENABLE_PUSH -> {
                if (v > 1) throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "SETTINGS_ENABLE_PUSH = $v")
                // section 6.5.2: a server never sends 1
                if (client && v != 0L) throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "SETTINGS_ENABLE_PUSH = 1 from a server")
            }

            SettingId.MAX_CONCURRENT_STREAMS -> {
                peerMaxConcurrent = v
            }

            SettingId.INITIAL_WINDOW_SIZE -> {
                if (v > H2.MAX_WINDOW) throw H2ConnectionError(Http2ErrorCode.FLOW_CONTROL_ERROR, "SETTINGS_INITIAL_WINDOW_SIZE = $v")
                val delta = v - peerInitialWindow
                peerInitialWindow = v
                if (delta < 0) windowShrank = true
                // section 6.9.2: the windows of streams we can still send on (open, half-closed (remote)) move by the
                // difference, possibly below zero
                for (s in streams.values) {
                    if (!canSend(s)) continue
                    s.sendWindow += delta
                    if (s.sendWindow >
                        H2.MAX_WINDOW
                    ) {
                        throw H2ConnectionError(Http2ErrorCode.FLOW_CONTROL_ERROR, "stream ${s.id} window above 2^31 - 1")
                    }
                }
                if (delta > 0) for (s in writers.toList()) tryWake(s)
            }

            SettingId.MAX_FRAME_SIZE -> {
                if (v < H2.MIN_MAX_FRAME_SIZE ||
                    v > H2.MAX_MAX_FRAME_SIZE
                ) {
                    throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "SETTINGS_MAX_FRAME_SIZE = $v")
                }
                peerMaxFrameSize = v.toInt()
            }

            SettingId.MAX_HEADER_LIST_SIZE -> {
                peerMaxHeaderListSize = v
            }

            SettingId.ENABLE_CONNECT_PROTOCOL -> {
                if (v > 1) throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "SETTINGS_ENABLE_CONNECT_PROTOCOL = $v")
                peerEnableConnectProtocol = v == 1L
            }

            SettingId.NO_RFC7540_PRIORITIES -> {
                if (v > 1) throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "SETTINGS_NO_RFC7540_PRIORITIES = $v")
            }

            else -> {} // section 6.5.2: unknown settings are ignored
        }
    }
    queueSettingsAck(windowShrank) // section 6.5.3: immediately, behind DATA already taken from a larger window
    emit(H2Event.SettingsChanged)
}

/** Section 6.5.3: our values hold once acknowledged; a smaller value than the protocol's initial one tightens only now. */
private fun H2ConnectionCore.ourSettingsAcknowledged() {
    hpackIn.setMaxTableSize(settings.headerTableSize) // section 4.3.1
    val ours = settings.initialStreamWindow.toLong()
    if (ours != recvInitialWindow) {
        val delta = ours - recvInitialWindow
        recvInitialWindow = ours
        for (s in streams.values) s.recv.adjust(delta, ours)
    }
}

internal fun H2ConnectionCore.onPing(
    f: Frame.Ping,
    now: Long,
) {
    if (!f.ack) {
        // a PING after DATA or HEADERS of ours is free (a gRPC client's bandwidth probe follows our DATA; grpc-go's server
        // resets its ping strikes when it writes them, http2_server.go:279-281, :906-910); PINGs with nothing of ours
        // in between are glitches
        if (!wroteSincePing) glitch(now, "PING")
        wroteSincePing = false
        // section 6.7: the same payload back, ahead of any other frame, the answers in the order of their PINGs
        if (controlQueued >= settings.maxControlFramesQueued) {
            calm("more than ${settings.maxControlFramesQueued} control frames queued")
        }
        pingAnswers.addLast(FrameEncoder.ping(true, f.payload))
        return
    }
    val sent = pingsOut.remove(f.payload) ?: return
    rttNanos = maxOf(1, now - sent)
    emit(H2Event.PingAck(f.payload, now - sent))
    if (f.payload == gracefulPing) finishGracefulGoAway()
}

internal fun H2ConnectionCore.onGoAway(f: Frame.GoAway) {
    goAwayReceived = true
    // section 6.8: the last stream ID never grows; streams above it were not processed and may be retried
    peerLastStreamId = minOf(peerLastStreamId, f.lastStreamId)
    val code = Http2ErrorCode.of(f.errorCode)
    emit(H2Event.GoAway(peerLastStreamId, code, f.debug.copyOf(minOf(f.debug.size, 1_024))))
    // and "Receivers of a GOAWAY frame MUST NOT open additional streams": a stream whose HEADERS are still queued was never
    // opened for the peer, whatever its ID; it goes the same way (never written, retry-safe)
    val refused = streams.values.filter { it.local && (it.id > peerLastStreamId || !it.headersSent) && it.state != StreamState.CLOSED }
    for (s in refused) {
        closeStream(s, weReset = false)
        emit(H2Event.StreamReset(s.id, Http2ErrorCode.REFUSED_STREAM, byPeer = true, notProcessed = true))
    }
    maybeFinished()
}

internal fun H2ConnectionCore.onWindowUpdate(
    f: Frame.WindowUpdate,
    now: Long,
) {
    val id = f.streamId
    if (id == 0) {
        if (f.increment == 0) throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "WINDOW_UPDATE of 0 on the connection")
        connSendWindow += f.increment
        sendCredited += f.increment
        if (connSendWindow >
            H2.MAX_WINDOW
        ) {
            throw H2ConnectionError(Http2ErrorCode.FLOW_CONTROL_ERROR, "connection window above 2^31 - 1")
        }
        for (s in blockedOnConnection.toList()) tryWake(s)
        return
    }
    val s = streams[id]
    if (s == null) {
        if (isIdle(id)) throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "WINDOW_UPDATE on idle stream $id")
        // allowed (section 5.1) and common: Go's client credits every 4 KiB it reads, also while it still reads a body whose stream is already closed on our side
        // (transport.go:2261-2265); not a glitch (nghttp2 does not count it either)
        return
    }
    if (f.increment == 0) return streamError(id, Http2ErrorCode.PROTOCOL_ERROR, "WINDOW_UPDATE of 0", now) // section 6.9
    if (s.state == StreamState.CLOSED) return
    s.sendWindow += f.increment
    if (s.sendWindow > H2.MAX_WINDOW) return streamError(id, Http2ErrorCode.FLOW_CONTROL_ERROR, "stream window above 2^31 - 1", now)
    tryWake(s)
}
