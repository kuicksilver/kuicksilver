// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.frame.H3ProtocolError
import io.kuicksilver.http3.runtime.H3Session
import io.kuicksilver.http3.runtime.IncompleteFrame
import io.kuicksilver.http3.runtime.readVarIntOrNull
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.runtime.QuicStreamLimits
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** Where the router hands a WebTransport stream once its session exists; called on the session's dispatcher. */
internal fun interface WtSessionSink {
    /** [stream] is positioned after its header (signal or type, then Session ID); [bidi] tells which kind it is. */
    fun onStream(
        stream: QuicStream,
        bidi: Boolean,
    )
}

/**
 * Routes WebTransport streams to their sessions (draft-ietf-webtrans-http3-16 sections 4.2, 4.3, 4.6). A unidirectional
 * stream of type `0x54` and a bidirectional stream that starts with the `WT_STREAM` signal `0x41` both carry the Session ID
 * next: the stream id of the session's Extended CONNECT, so always a client-initiated bidirectional stream (anything
 * else is H3_ID_ERROR).
 *
 * A stream may arrive before its session is established (its CONNECT still in flight, or not yet accepted). Such
 * streams wait here, bounded twice: at most [MAX_BUFFERED_STREAMS] per connection, and at most [BUFFER_TIMEOUT] each. A
 * stream over either bound, and one for a session that is closed or was refused, is rejected with
 * WT_BUFFERED_STREAM_REJECTED: `STOP_SENDING`, and `RESET_STREAM` too when it is bidirectional (section 4.6;
 * webtransport-go rejects streams of recently closed sessions the same way). The peer's QUIC stream limits bound how
 * many streams are open at all; this bound keeps the ones nobody claims from holding memory and stream credit.
 *
 * Every member runs on the session's single-threaded dispatcher.
 */
internal class WtStreamRouter(
    private val session: H3Session,
) {
    private class Buffered(
        val sessionId: Long,
        val stream: QuicStream,
        val bidi: Boolean,
    ) {
        var timer: Job? = null
    }

    private val sinks = HashMap<Long, WtSessionSink>()
    private val buffered = ArrayList<Buffered>()
    private val closedSessions = ArrayDeque<Long>()

    /** How a buffered stream waits out [BUFFER_TIMEOUT]; a test replaces it to end the wait without real time passing. */
    var bufferTimer: suspend (Duration) -> Unit = { delay(it) }

    /** Streams waiting for their session (a test hook). */
    val bufferedCount = MutableStateFlow(0)

    /** A peer's unidirectional stream whose type `0x54` was read. */
    suspend fun onUni(st: QuicStream) = route(st, bidi = false)

    /** A bidirectional stream whose `WT_STREAM` signal `0x41` was read. */
    suspend fun onBidi(st: QuicStream) = route(st, bidi = true)

    private suspend fun route(
        st: QuicStream,
        bidi: Boolean,
    ) {
        val sessionId =
            try {
                st.input.readVarIntOrNull()
            } catch (_: IncompleteFrame) {
                null
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                if (H3Session.transportCause(e) !is QuicException.StreamError) throw e
                null
            } ?: run {
                // ended or reset before its Session ID: nothing to route, but a peer doing only this spends glitch tokens
                session.glitch("WebTransport stream ended before its Session ID")
                return
            }
        if (sessionId % 4 != 0L) {
            throw H3ProtocolError(
                Http3ErrorCode.ID_ERROR,
                "WebTransport stream ${st.id} names session $sessionId, not a client-initiated bidirectional stream",
            )
        }
        // server: a stream the client could never open under the limit we granted (RFC 9218 section 7.2 does the same)
        if (session.isServer) {
            QuicStreamLimits.peerBidiStreamsGranted(session.quic)?.let {
                if (sessionId / 4 >= it) {
                    throw H3ProtocolError(Http3ErrorCode.ID_ERROR, "WebTransport session $sessionId beyond the limit of $it streams")
                }
            }
        }
        sinks[sessionId]?.let {
            it.onStream(st, bidi)
            return
        }
        if (isGone(sessionId) || buffered.size >= MAX_BUFFERED_STREAMS) {
            reject(st, bidi)
            return
        }
        val b = Buffered(sessionId, st, bidi)
        buffered += b
        bufferedCount.value = buffered.size
        b.timer =
            session.scope.launch {
                bufferTimer(BUFFER_TIMEOUT)
                if (buffered.remove(b)) {
                    bufferedCount.value = buffered.size
                    reject(b.stream, b.bidi)
                }
            }
    }

    /** A session that will never be established here: closed or refused, or (server) a CONNECT at or above our GOAWAY id. */
    private fun isGone(sessionId: Long): Boolean =
        sessionId in closedSessions || (session.isServer && session.goAwaySentId?.let { sessionId >= it } == true)

    /** [sessionId] is established: its buffered streams go to [sink] in arrival order, later ones at once. */
    fun register(
        sessionId: Long,
        sink: WtSessionSink,
    ) {
        sinks[sessionId] = sink
        val mine = buffered.filter { it.sessionId == sessionId }
        buffered.removeAll(mine)
        bufferedCount.value = buffered.size
        for (b in mine) {
            b.timer?.cancel()
            sink.onStream(b.stream, b.bidi)
        }
    }

    /** [sessionId] ended, or its CONNECT was refused: streams still waiting for it, and later ones, are rejected. */
    fun unregister(sessionId: Long) {
        sinks.remove(sessionId)
        if (sessionId !in closedSessions) {
            closedSessions.addLast(sessionId)
            if (closedSessions.size > MAX_CLOSED_REMEMBERED) closedSessions.removeFirst()
        }
        val mine = buffered.filter { it.sessionId == sessionId }
        buffered.removeAll(mine)
        bufferedCount.value = buffered.size
        for (b in mine) {
            b.timer?.cancel()
            reject(b.stream, b.bidi)
        }
    }

    private fun reject(
        st: QuicStream,
        bidi: Boolean,
    ) {
        runCatching { st.stopSending(Http3ErrorCode.WT_BUFFERED_STREAM_REJECTED) }
        if (bidi) runCatching { st.reset(Http3ErrorCode.WT_BUFFERED_STREAM_REJECTED) }
    }

    companion object {
        /** WebTransport streams per connection that may wait for their session (section 4.6 leaves the number to us). */
        const val MAX_BUFFERED_STREAMS = 16

        /** How long one of them may wait. */
        val BUFFER_TIMEOUT: Duration = 5.seconds

        /** Closed or refused sessions remembered, so their late streams are rejected at once instead of buffered. */
        const val MAX_CLOSED_REMEMBERED = 16
    }
}
