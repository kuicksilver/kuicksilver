// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.http2.core

import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.H2
import io.kuicksilver.http2.frame.H2ConnectionError

// How streams and the connection end: stream state changes, RST_STREAM, GOAWAY and connection errors (RFC 9113 sections 5.1, 5.4 and 6.8).

internal fun H2ConnectionCore.remoteEnded(s: H2Stream) {
    s.state = if (s.state == StreamState.HALF_CLOSED_LOCAL) StreamState.CLOSED else StreamState.HALF_CLOSED_REMOTE
    s.pendingCredit = 0
    if (s.state == StreamState.CLOSED) closeStream(s, weReset = false, flush = true)
}

internal fun H2ConnectionCore.localEnded(s: H2Stream) {
    s.state = if (s.state == StreamState.HALF_CLOSED_REMOTE) StreamState.CLOSED else StreamState.HALF_CLOSED_LOCAL
    if (s.state == StreamState.CLOSED) closeStream(s, weReset = false, flush = true)
}

/**
 * Closes [s]. A normal end ([flush]) still writes what is queued; otherwise queued field lists (never encoded) and DATA
 * are dropped, and so is pending stream credit (section 6.4: nothing more on a reset stream).
 */
internal fun H2ConnectionCore.closeStream(
    s: H2Stream,
    weReset: Boolean,
    flush: Boolean = false,
) {
    // a normal end comes here with the state already CLOSED; a reset or GOAWAY with the stream still open
    if (s.local && (flush || s.state != StreamState.CLOSED)) localOpen--
    s.state = StreamState.CLOSED
    s.pendingCredit = 0
    if (!flush) {
        dropQueued(s)
        dropUnconsumed(s) // a reset stream's content will not be read
    }
    s.wantsWindow = false
    writers.remove(s)
    blockedOnConnection.remove(s)
    rememberClosed(s.id, weReset)
    if (s.out.isEmpty() && s.released) removeStream(s)
    maybeFinished()
}

internal fun H2ConnectionCore.removeStream(s: H2Stream) {
    if (streams.remove(s.id) == null) return
    if (!s.local) peerStreams--
    dropUnconsumed(s)
    maybeFinished()
}

internal fun H2ConnectionCore.rememberClosed(
    id: Int,
    weReset: Boolean,
) {
    recentlyClosed.remove(id)
    recentlyClosed[id] = weReset
    if (recentlyClosed.size > recentlyClosedMax) recentlyClosed.remove(recentlyClosed.keys.first())
}

/** Our RST_STREAM for [id]; [causedByPeer] (an error of the peer) also takes from the glitch budget (MadeYouReset, CVE-2025-8671). */
internal fun H2ConnectionCore.resetStream(
    id: Int,
    code: Http2ErrorCode,
    now: Long,
    causedByPeer: Boolean,
) {
    val s = streams[id]
    val active = s != null && s.state != StreamState.CLOSED
    if (!active && recentlyClosed[id] == true) return // reset by us already: one RST_STREAM per stream
    if (causedByPeer) glitch(now, "stream error ${code.name}")
    // later frames on this stream are discarded (section 5.1), so a peer cannot make us answer them again
    if (active) closeStream(s, weReset = true) else rememberClosed(id, weReset = true)
    queueControl(FrameEncoder.rstStream(id, code.code))
    if (active) emit(H2Event.StreamReset(id, code, byPeer = false, notProcessed = code == Http2ErrorCode.REFUSED_STREAM))
}

/** A stream error (section 5.4.2); on an idle stream (no RST_STREAM allowed there, section 6.4) a connection error. */
internal fun H2ConnectionCore.streamError(
    id: Int,
    code: Http2ErrorCode,
    message: String,
    now: Long,
) {
    if (isIdle(id) && streams[id] == null) throw H2ConnectionError(code, "$message on idle stream $id")
    resetStream(id, code, now, causedByPeer = true)
}

internal fun H2ConnectionCore.calm(message: String): Nothing = throw H2ConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM, message)

internal fun H2ConnectionCore.sendGoAway(
    lastId: Int,
    code: Http2ErrorCode,
    debug: ByteArray,
) {
    // section 6.8: the last stream identifier never grows from one GOAWAY to the next
    val last = if (goAwaySentLastId >= 0) minOf(lastId, goAwaySentLastId) else lastId
    goAwaySentLastId = last
    control.addLast(FrameEncoder.goAway(last, code.code, debug))
}

internal fun H2ConnectionCore.finishGracefulGoAway() {
    pingsOut.remove(gracefulPing)
    gracefulPing = -1
    sendGoAway(lastPeerStreamId, Http2ErrorCode.NO_ERROR, ByteArray(0)) // the second phase
    maybeFinished()
}

/** A connection error (section 5.4.1): only our GOAWAY goes out after it, then the transport closes. */
internal fun H2ConnectionCore.connectionError(
    code: Http2ErrorCode,
    message: String,
) {
    if (closed) return
    // a frame already partly written is finished first (the peer must still parse the stream), then only the GOAWAY
    control.clear()
    pingAnswers.clear()
    creditReady.clear()
    headerReady.clear()
    dataReady.clear()
    val debug = message.encodeToByteArray()
    sendGoAway(lastPeerStreamId, code, debug.copyOf(minOf(debug.size, 256)))
    closed = true
    for (s in streams.values) {
        if (s.state !=
            StreamState.CLOSED
        ) {
            emit(H2Event.StreamReset(s.id, code, byPeer = false, notProcessed = s.local && !s.headersSent))
        }
    }
    streams.clear()
    report(code, byPeer = false, message)
}

/** After a GOAWAY either way, the connection is over once no stream is left. */
internal fun H2ConnectionCore.maybeFinished() {
    if (closed || streams.isNotEmpty()) return
    val drainingOut = goAwaySentLastId >= 0 && goAwaySentLastId != H2.MAX_STREAM_ID
    if (goAwayReceived || drainingOut) {
        closed = true
        report(Http2ErrorCode.NO_ERROR, byPeer = goAwayReceived && !drainingOut, "GOAWAY and no streams left")
    }
}
