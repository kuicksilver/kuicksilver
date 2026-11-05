// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameDecoder
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.H2
import io.kuicksilver.http2.frame.H2ConnectionError
import io.kuicksilver.http2.frame.H2StreamError
import io.kuicksilver.http2.frame.SettingId
import io.kuicksilver.http2.hpack.HpackDecoder
import io.kuicksilver.http2.hpack.HpackEncoder
import io.kuicksilver.http2.hpack.HpackError
import io.kuicksilver.http2.hpack.entrySize

/** Which end of the connection this core is. */
internal enum class Role { CLIENT, SERVER }

/**
 * The sans-IO state of one HTTP/2 connection (RFC 9113; ADR-0004, ADR-0017): bytes from the transport go in through
 * [receive], bytes for it come out of [poll], what happened comes out of [nextEvent], and time (nanoseconds, any origin)
 * is a parameter. No coroutines, sockets or clocks.
 *
 * - Preface and SETTINGS (sections 3.4, 6.5): queued at construction; the peer's first frame must be SETTINGS; ours must
 *   be acknowledged within [Http2Settings.settingsAckTimeout] of being written or the connection ends with
 *   SETTINGS_TIMEOUT.
 * - Streams (section 5.1): the client opens odd streams with [openStream], the server answers with [sendHeaders]. Server
 *   push is never used: a client sends SETTINGS_ENABLE_PUSH = 0 and refuses PUSH_PROMISE.
 * - Field compression (section 4.3.1): a field list is HPACK-encoded when [poll] writes it, never when it is queued, so
 *   the encoder's state always follows the order on the wire; a list never written is dropped without touching it.
 * - Flow control (sections 5.2, 6.9): WINDOW_UPDATE goes out only when the driver reports with [consumed] that the
 *   application read the data, so memory per connection stays within the connection window; [sendData] takes at most
 *   one frame's worth within both windows and never buffers beyond it.
 * - Floods (section 10.5, threat model 3.23): field blocks are bounded in bytes, CONTINUATION frames and time before
 *   decoding; queued control frames, empty DATA frames, glitches and (on a server) the client's stream resets are bounded
 *   per connection; a stream the peer reset still counts toward our SETTINGS_MAX_CONCURRENT_STREAMS until [release].
 * - Order of output: control frames (PING answers first), stream credit, then field blocks, then DATA round-robin between
 *   streams. RFC 7540 priorities are parsed and ignored (section 5.3.2).
 *
 * The driver's contract: drain [nextEvent] after every call; call [consumed] as the application reads; call [release]
 * for every stream once the application is done with it (both roles; unread content of a dropped stream is credited to
 * the connection then, or at once when the stream is reset); a server answers a [H2Event.HeadersReceived] with
 * `tooLarge` with 431 and a client fails that request; call [onTimeout] at [nextTimeout].
 */
internal class H2ConnectionCore(
    val role: Role,
    val settings: Http2Settings,
    now: Long,
) {
    private val client = role == Role.CLIENT
    private val decoder = FrameDecoder(settings.maxFrameSize)

    // section 4.3.1: both tables start at 4096; our own value holds once the peer acknowledged it
    private val hpackIn =
        HpackDecoder(
            H2.DEFAULT_HEADER_TABLE_SIZE,
            settings.maxHeaderListSize,
            maxStringLength =
                2 * settings.maxHeaderListSize,
        )
    private val hpackOut = HpackEncoder(maxTableSize = H2.DEFAULT_HEADER_TABLE_SIZE)
    private val block = HeaderBlockCollector(2 * settings.maxHeaderListSize, settings.maxContinuationFrames)
    private val resets = TokenBucket(settings.resetBurst, settings.resetsPerSecond, now)
    private val glitches = TokenBucket(settings.glitchBurst, settings.glitchesPerSecond, now)

    // insertion order is the order each side opened its streams in: the resets a GOAWAY or a close reports (and the
    // engine retries) come out in that order on every platform, not in a hash table's
    private val streams = LinkedHashMap<Int, H2Stream>()
    private var peerStreams = 0 // peer-initiated streams in [streams]: their handlers count toward our limit
    private var localOpen = 0 // our streams not closed: they count toward the peer's limit

    /** Recently closed streams: true when we reset or discarded them (late frames are ignored), false otherwise (STREAM_CLOSED). */
    private val recentlyClosed = LinkedHashMap<Int, Boolean>()
    private val recentlyClosedMax = maxOf(256, minOf(settings.maxConcurrentStreams, 4_096) * 2)

    /** The preface and our first SETTINGS: they go out before anything, even before the GOAWAY of an early error. */
    private val initial = ArrayDeque<ByteArray>()
    private var ourSettingsFrame: ByteArray? = null
    private val pingAnswers = ArrayDeque<ByteArray>() // section 6.7: ahead of every other control frame
    private val control = ArrayDeque<ByteArray>()
    private var wroteSincePing = true
    private val creditReady = ArrayDeque<H2Stream>()
    private val headerReady = ArrayDeque<H2Stream>()
    private val dataReady = ArrayDeque<H2Stream>()
    private val writers = LinkedHashSet<H2Stream>() // streams waiting for window
    private val blockedOnConnection = LinkedHashSet<H2Stream>() // ... of which only the connection window holds back
    private var partial: ByteArray? = null
    private var partialPos = 0
    private val events = ArrayDeque<H2Event>()

    // the peer's settings (section 6.5.2 initial values)
    private var peerMaxConcurrent = Long.MAX_VALUE
    private var peerInitialWindow = H2.DEFAULT_WINDOW.toLong()
    private var peerMaxFrameSize = H2.MIN_MAX_FRAME_SIZE
    private var peerMaxHeaderListSize = Long.MAX_VALUE

    /** The peer allows Extended CONNECT (RFC 8441 section 3). */
    var peerEnableConnectProtocol: Boolean = false
        private set

    /** The peer's SETTINGS_MAX_CONCURRENT_STREAMS, for the driver's pool. */
    val peerMaxConcurrentStreams: Long get() = peerMaxConcurrent

    private var connSendWindow = H2.DEFAULT_WINDOW.toLong()
    private var sendCredited = H2.DEFAULT_WINDOW.toLong() // the protocol's initial window plus the peer's connection credit
    private var queuedDataBytes = 0L // DATA payload taken by sendData, not yet written
    private var dataWritten = 0L
    private val connRecv = RecvWindow(settings.initialConnectionWindow.toLong(), settings.maxConnectionWindow.toLong())

    /** The receive window streams start with: the protocol's 65 535 until our SETTINGS are acknowledged, if ours is smaller. */
    private var recvInitialWindow = maxOf(H2.DEFAULT_WINDOW, settings.initialStreamWindow).toLong()

    private var prefaceLeft = if (client) 0 else H2.PREFACE.size
    private var peerSettingsSeen = false
    private var settingsSentAt = -1L // when [poll] wrote our SETTINGS; -1 before
    private var settingsUnacked = 1
    private var rttNanos = 100_000_000L // until the SETTINGS acknowledgement measures it
    private var nextLocalId = if (client) 1 else 2
    private var lastPeerStreamId = 0
    private var refusedInARow = 0
    private var emptyDataInARow = 0
    private var lastNow = now // the latest time a caller gave, for work that a call without a time triggers

    // the field block being collected: its stream, kind and flags
    private var blockStream = 0
    private var blockPromised = 0
    private var blockEndStream = false
    private var blockDependency = -1
    private var blockStartedAt = 0L
    private var inBlock = false

    private var pingCounter = 0L
    private val pingsOut = LinkedHashMap<Long, Long>()
    private var gracefulPing = -1L
    private var gracefulDeadline = -1L

    private var goAwayReceived = false
    private var peerLastStreamId = H2.MAX_STREAM_ID

    /** The last stream ID of the GOAWAY we sent (MAX_STREAM_ID for the first phase of a graceful one), or -1. */
    private var goAwaySentLastId = -1
    private var closed = false
    private var closedReported = false

    /** True once the connection ended (an error, a finished GOAWAY): nothing more is read, [poll] drains what is left. */
    val isClosed: Boolean get() = closed

    /** A stream we open can still get an identifier (section 5.1.1: identifiers cannot be reused). */
    val streamIdsLeft: Boolean get() = nextLocalId in 1..H2.MAX_STREAM_ID

    /** Moves the next identifier of our streams to [id] (a test hook: exhausting 2^30 identifiers takes too long). */
    internal fun nextStreamIdForTest(id: Int) {
        nextLocalId = id
    }

    /** Streams the core still holds (closed ones the driver has not released yet included). */
    val activeStreams: Int get() = streams.size

    init {
        if (client) initial.addLast(H2.PREFACE)
        val ids = mutableListOf<Int>()
        val values = mutableListOf<Long>()

        fun put(
            id: Int,
            v: Long,
        ) {
            ids += id
            values += v
        }
        if (settings.headerTableSize != H2.DEFAULT_HEADER_TABLE_SIZE) put(SettingId.HEADER_TABLE_SIZE, settings.headerTableSize.toLong())
        if (client) put(SettingId.ENABLE_PUSH, 0)
        put(SettingId.MAX_CONCURRENT_STREAMS, settings.maxConcurrentStreams.toLong())
        put(SettingId.INITIAL_WINDOW_SIZE, settings.initialStreamWindow.toLong())
        if (settings.maxFrameSize != H2.MIN_MAX_FRAME_SIZE) put(SettingId.MAX_FRAME_SIZE, settings.maxFrameSize.toLong())
        put(SettingId.MAX_HEADER_LIST_SIZE, settings.maxHeaderListSize.toLong())
        put(SettingId.NO_RFC7540_PRIORITIES, 1)
        val frame = FrameEncoder.settings(ids.toIntArray(), values.toLongArray())
        ourSettingsFrame = frame
        initial.addLast(frame)
        val raise = settings.initialConnectionWindow - H2.DEFAULT_WINDOW
        if (raise > 0) initial.addLast(FrameEncoder.windowUpdate(0, raise))
    }

    // ---------------------------------------------------------------------------------------------------------------
    // input

    /** Feeds bytes from the transport. Errors end the connection (a GOAWAY is queued and [H2Event.Closed] reported). */
    fun receive(
        buf: ByteArray,
        off: Int,
        len: Int,
        now: Long,
    ) {
        lastNow = now
        var p = off
        val end = off + len
        try {
            while (p < end && !closed) {
                if (prefaceLeft > 0) {
                    val at = H2.PREFACE.size - prefaceLeft
                    val n = minOf(prefaceLeft, end - p)
                    for (i in 0 until n) {
                        if (buf[p + i] !=
                            H2.PREFACE[at + i]
                        ) {
                            throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "invalid connection preface")
                        }
                    }
                    prefaceLeft -= n
                    p += n
                    continue
                }
                p += decoder.feed(buf, p, end - p)
                val f =
                    try {
                        decoder.next()
                    } catch (e: H2StreamError) {
                        // a frame of another kind inside a field block (sections 6.2, 6.10) or before the peer's SETTINGS (section
                        // 3.4) is a connection error whatever is wrong with it
                        if (inBlock ||
                            !peerSettingsSeen
                        ) {
                            throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "invalid frame: ${e.message}")
                        }
                        streamError(e.streamId, e.code, e.message ?: "", now)
                        null
                    } ?: continue
                onFrame(f, now)
            }
        } catch (e: H2ConnectionError) {
            connectionError(e.code, e.message ?: "")
        }
    }

    private fun onFrame(
        f: Frame,
        now: Long,
    ) {
        if (!peerSettingsSeen) {
            // section 3.4: the peer's preface ends with a SETTINGS frame, its first frame
            if (f !is Frame.Settings || f.ack) throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "the first frame is not SETTINGS")
            peerSettingsSeen = true
        }
        if (inBlock && (f !is Frame.Continuation || f.streamId != blockStream)) {
            // section 6.10: nothing may interleave a field block
            throw H2ConnectionError(
                Http2ErrorCode.PROTOCOL_ERROR,
                "frame type ${f::class.simpleName} inside the field block of stream $blockStream",
            )
        }
        when (f) {
            is Frame.Data -> onData(f, now)
            is Frame.Headers -> startBlock(f.streamId, 0, f.endStream, f.dependency, f.fragment, f.endHeaders, now)
            is Frame.PushPromise -> onPushPromise(f, now)
            is Frame.Continuation -> onContinuation(f, now)
            is Frame.Priority -> onPriority(f, now)
            is Frame.RstStream -> onRstStream(f, now)
            is Frame.Settings -> onSettings(f, now)
            is Frame.Ping -> onPing(f, now)
            is Frame.GoAway -> onGoAway(f)
            is Frame.WindowUpdate -> onWindowUpdate(f, now)
            is Frame.Unknown -> glitch(now, "unknown frame type ${f.type}") // section 5.5: ignored, but not for free
        }
    }

    private fun peerInitiated(id: Int): Boolean = (id and 1 == 1) == !client

    /** Idle (section 5.1): never used by its initiator yet. */
    private fun isIdle(id: Int): Boolean = if (peerInitiated(id)) id > lastPeerStreamId else id >= nextLocalId

    /** Section 10.5: legal but suspicious when frequent; an empty glitch budget ends the connection (nghttp2's glitch limit). */
    private fun glitch(
        now: Long,
        what: String,
    ) {
        if (!glitches.take(
                now,
            )
        ) {
            calm("too many glitches (last: $what): above ${settings.glitchesPerSecond}/s, burst ${settings.glitchBurst}")
        }
    }

    private fun onData(
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

    private fun startBlock(
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

    private fun onContinuation(
        f: Frame.Continuation,
        now: Long,
    ) {
        if (!inBlock) throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "CONTINUATION without a field block")
        if (!block.add(f.fragment, continuation = true)) {
            calm("field block above ${2 * settings.maxHeaderListSize} bytes or ${settings.maxContinuationFrames} CONTINUATION frames")
        }
        if (f.endHeaders) endBlock(now)
    }

    private fun endBlock(now: Long) {
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

    private fun onHeaders(
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
            // RFC 7540 section 5.3.1: a stream cannot depend on itself (kept for interoperability; RFC 9113 section 5.3.2)
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
            emit(H2Event.HeadersReceived(id, fields, endStream, !fits))
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
    private fun headersOnClosed(id: Int): Nothing = throw H2ConnectionError(Http2ErrorCode.STREAM_CLOSED, "HEADERS on closed stream $id")

    private fun onPushPromise(
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

    private fun onPushPromiseBlock(
        promised: Int,
        now: Long,
    ) {
        // the push our SETTINGS had not yet forbidden: the block was decoded for HPACK, the stream is cancelled
        resetStream(promised, Http2ErrorCode.CANCEL, now, causedByPeer = false)
    }

    private fun onPriority(
        f: Frame.Priority,
        now: Long,
    ) {
        glitch(now, "PRIORITY") // deprecated (section 5.3.2): no state, but not for free (nghttp2 does the same)
        // RFC 7540 section 5.3.1: a stream cannot depend on itself (kept for interoperability)
        if (f.dependency == f.streamId) streamError(f.streamId, Http2ErrorCode.PROTOCOL_ERROR, "stream depends on itself", now)
    }

    private fun onRstStream(
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

    private fun onSettings(
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

                else -> {
                    Unit
                } // section 6.5.2: unknown settings are ignored
            }
        }
        queueControl(FrameEncoder.settingsAck()) // section 6.5.3: immediately
        emit(H2Event.SettingsChanged)
    }

    /** Section 6.5.3: our values hold once acknowledged; a smaller value than the protocol's initial one tightens only now. */
    private fun ourSettingsAcknowledged() {
        hpackIn.setMaxTableSize(settings.headerTableSize) // section 4.3.1
        val ours = settings.initialStreamWindow.toLong()
        if (ours != recvInitialWindow) {
            val delta = ours - recvInitialWindow
            recvInitialWindow = ours
            for (s in streams.values) s.recv.adjust(delta, ours)
        }
    }

    private fun onPing(
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
            if (control.size + pingAnswers.size >= settings.maxControlFramesQueued) {
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

    private fun onGoAway(f: Frame.GoAway) {
        goAwayReceived = true
        // section 6.8: the last stream ID never grows; streams above it were not processed and may be retried
        peerLastStreamId = minOf(peerLastStreamId, f.lastStreamId)
        val code = Http2ErrorCode.of(f.errorCode)
        emit(H2Event.GoAway(peerLastStreamId, code, f.debug.copyOf(minOf(f.debug.size, 1_024))))
        for (s in streams.values.filter { it.local && it.id > peerLastStreamId && it.state != StreamState.CLOSED }) {
            closeStream(s, weReset = false)
            emit(H2Event.StreamReset(s.id, Http2ErrorCode.REFUSED_STREAM, byPeer = true, notProcessed = true))
        }
        maybeFinished()
    }

    private fun onWindowUpdate(
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

    // ---------------------------------------------------------------------------------------------------------------
    // the driver's actions

    /**
     * Opens a client stream with [fields] (section 8.3.1 pseudo-header fields first, already validated by the caller) and
     * returns its identifier. Throws [H2StreamLimit] at the peer's SETTINGS_MAX_CONCURRENT_STREAMS, [H2ConnectionUnusable]
     * after a GOAWAY or the last identifier, [H2HeaderListTooLarge] above the peer's SETTINGS_MAX_HEADER_LIST_SIZE.
     */
    fun openStream(
        fields: List<Pair<String, String>>,
        endStream: Boolean,
    ): Int {
        check(client) { "only a client opens streams" }
        if (closed || goAwayReceived || goAwaySentLastId >= 0) throw H2ConnectionUnusable("the connection is going away")
        if (nextLocalId > H2.MAX_STREAM_ID || nextLocalId < 0) throw H2ConnectionUnusable("stream identifiers exhausted (section 5.1.1)")
        if (localOpen >= peerMaxConcurrent) throw H2StreamLimit("the peer allows $peerMaxConcurrent concurrent streams")
        checkListSize(fields)
        val id = nextLocalId
        nextLocalId += 2
        val s =
            H2Stream(
                id,
                local = true,
                state = if (endStream) StreamState.HALF_CLOSED_LOCAL else StreamState.OPEN,
                sendWindow = peerInitialWindow,
                recv = RecvWindow(recvInitialWindow, settings.maxStreamWindow.toLong()),
            )
        streams[id] = s
        localOpen++
        enqueue(s, OutItem.Fields(fields, endStream))
        return id
    }

    /** Sends a field section on [streamId]: a response, an interim response or trailers ([endStream] true for trailers). */
    fun sendHeaders(
        streamId: Int,
        fields: List<Pair<String, String>>,
        endStream: Boolean,
    ) {
        val s = streams[streamId] ?: throw IllegalStateException("stream $streamId is closed")
        check(canSend(s)) { "stream $streamId cannot send" }
        checkListSize(fields)
        enqueue(s, OutItem.Fields(fields, endStream))
        if (endStream) localEnded(s)
    }

    /**
     * Sends up to [len] bytes of [buf] as DATA on [streamId] and returns how many were taken: at most one frame, within the
     * connection and stream windows (sections 5.2, 6.9.1); 0 while a DATA frame of this stream waits for [poll] or no
     * window is left ([H2Event.WindowAvailable] follows). [endStream] applies only when all [len] bytes were taken.
     */
    fun sendData(
        streamId: Int,
        buf: ByteArray,
        off: Int,
        len: Int,
        endStream: Boolean,
    ): Int {
        val s = streams[streamId] ?: throw IllegalStateException("stream $streamId is closed")
        check(canSend(s)) { "stream $streamId cannot send" }
        if (s.dataQueued) {
            want(s)
            return 0
        }
        val n = minOf(len.toLong(), connSendWindow, s.sendWindow, H2.MIN_MAX_FRAME_SIZE.toLong()).toInt().coerceAtLeast(0)
        if (n == 0 && len > 0) {
            want(s)
            tryWake(s) // file it as blocked on its own or on the connection window
            return 0
        }
        val end = endStream && n == len
        connSendWindow -= n
        s.sendWindow -= n
        queuedDataBytes += n
        enqueue(s, OutItem.Data(FrameEncoder.data(streamId, buf, off, n, end), n))
        s.dataQueued = true
        if (n < len) want(s)
        if (end) localEnded(s)
        return n
    }

    /**
     * Ends our side of [streamId] with an empty DATA frame carrying END_STREAM, for a body whose end is known only after its
     * last bytes went out; an empty frame needs no window (section 6.9.1), so a body that used the window up exactly still
     * ends. Returns false while a DATA frame of the stream waits for [poll] (one at a time): call again once [poll] wrote it.
     */
    fun endStream(streamId: Int): Boolean {
        val s = streams[streamId] ?: throw IllegalStateException("stream $streamId is closed")
        check(canSend(s)) { "stream $streamId cannot send" }
        if (s.dataQueued) return false
        enqueue(s, OutItem.Data(FrameEncoder.data(streamId, EMPTY, 0, 0, true), 0))
        s.dataQueued = true
        localEnded(s)
        return true
    }

    /** The application read [n] bytes of [streamId]: credit goes back to the peer (WINDOW_UPDATE) when due. */
    fun consumed(
        streamId: Int,
        n: Long,
        now: Long,
    ) {
        lastNow = now
        if (n <= 0 || closed) return
        val s = streams[streamId] ?: return // a dropped stream's content was credited when it was dropped
        val k = minOf(n, s.unconsumed)
        if (k <= 0) return
        s.unconsumed -= k
        credit(s, k, now)
    }

    /**
     * Resets [streamId] with [code] (the application cancelled it). A stream whose field section was never written is idle
     * to the peer: it is dropped without a RST_STREAM (section 6.4; a later stream closes it, section 5.1.1) and reported
     * as not processed. A stream already closed (the peer reset it, or it ended both ways) gets nothing (sections 5.1, 5.4.2).
     */
    fun reset(
        streamId: Int,
        code: Http2ErrorCode,
        now: Long,
    ) {
        if (closed) return
        val s = streams[streamId]
        if (s != null && s.local && !s.headersSent) {
            if (s.state == StreamState.CLOSED) return
            closeStream(s, weReset = true)
            emit(H2Event.StreamReset(streamId, code, byPeer = false, notProcessed = true))
            return
        }
        if (isIdle(streamId) && s == null) return // section 6.4: never on an idle stream
        // section 5.1: nothing but PRIORITY on a closed stream, and section 5.4.2: no RST_STREAM in answer to the peer's
        if (s?.state == StreamState.CLOSED || (s == null && streamId in recentlyClosed)) return
        resetStream(streamId, code, now, causedByPeer = false)
    }

    /**
     * The driver is done with [streamId] (a server's handler returned; a client read or abandoned the response): it stops
     * counting toward our concurrency limit, and content the application never read is credited to the connection. A
     * request still open after its complete response is stopped with RST_STREAM NO_ERROR once that response is written
     * (section 8.1).
     */
    fun release(streamId: Int) {
        val s = streams[streamId] ?: return
        s.released = true
        if (!s.local) refusedInARow = 0
        dropUnconsumed(s)
        if (!s.local && s.state == StreamState.HALF_CLOSED_LOCAL) {
            // section 8.1: the response is complete and nobody reads the rest of the request: the server asks the client to
            // stop with RST_STREAM NO_ERROR once the response's frames are out (Go's server.go wroteFrame does the same)
            if (s.out.isEmpty()) resetStream(s.id, Http2ErrorCode.NO_ERROR, lastNow, causedByPeer = false) else s.stopPeerAfterFlush = true
            return
        }
        if (s.state == StreamState.CLOSED && s.out.isEmpty()) removeStream(s) // else once its last frame is written
    }

    /** Sends a PING (section 6.7) and returns its payload; [H2Event.PingAck] reports the answer. */
    fun ping(now: Long): Long {
        val payload = ++pingCounter
        if (pingsOut.size >= MAX_PINGS_OUT) {
            // the oldest unanswered PING is forgotten, never the one of a graceful GOAWAY
            pingsOut.keys.firstOrNull { it != gracefulPing }?.let { pingsOut.remove(it) }
        }
        pingsOut[payload] = now
        queueControl(FrameEncoder.ping(false, payload))
        return payload
    }

    /**
     * Sends GOAWAY (section 6.8). [graceful]: first with the largest stream identifier and a PING, then, when the PING is
     * answered (a round trip later, so streams the peer opened meanwhile are counted) or after
     * [Http2Settings.settingsAckTimeout] at the latest, with the last stream we accepted. Otherwise at once with the last
     * stream we accepted; an error [code] also closes the connection.
     */
    fun goAway(
        code: Http2ErrorCode,
        debug: ByteArray,
        graceful: Boolean,
        now: Long,
    ) {
        if (closed) return
        if (code != Http2ErrorCode.NO_ERROR) return connectionError(code, debug.decodeToString())
        // a graceful GOAWAY after one of ours changes nothing: a two-step one in progress keeps its second step for when
        // its PING returns (a second call must not collapse it and cut the streams that crossed the first GOAWAY)
        if (graceful && goAwaySentLastId >= 0) return
        if (graceful) {
            sendGoAway(H2.MAX_STREAM_ID, code, debug)
            gracefulPing = ping(now)
            gracefulDeadline = now + settings.settingsAckTimeout.inWholeNanoseconds
        } else {
            sendGoAway(lastPeerStreamId, code, debug)
            maybeFinished()
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // output, time, events

    /** Writes pending bytes into [out] from [off] at [now]; returns how many. A field block is never interleaved with other frames. */
    fun poll(
        out: ByteArray,
        off: Int,
        now: Long,
    ): Int {
        lastNow = now
        var p = off
        while (p < out.size) {
            val cur = partial ?: nextFrame(now) ?: break
            val n = minOf(cur.size - partialPos, out.size - p)
            cur.copyInto(out, p, partialPos, partialPos + n)
            p += n
            partialPos += n
            if (partialPos == cur.size) {
                partial = null
                partialPos = 0
            } else {
                partial = cur
            }
        }
        return p - off
    }

    /** True when [poll] has something to write. */
    val wantsWrite: Boolean
        get() =
            partial != null || initial.isNotEmpty() || pingAnswers.isNotEmpty() || control.isNotEmpty() || creditReady.isNotEmpty() ||
                headerReady.isNotEmpty() ||
                dataReady.isNotEmpty()

    /** The next deadline (nanoseconds) for [onTimeout], or null. */
    fun nextTimeout(): Long? {
        if (closed) return null
        var t: Long? = null

        fun at(v: Long) {
            t = t?.let { minOf(it, v) } ?: v
        }
        if (settingsUnacked > 0 && settingsSentAt >= 0) at(settingsSentAt + settings.settingsAckTimeout.inWholeNanoseconds)
        if (inBlock) at(blockStartedAt + settings.maxHeaderBlockTime.inWholeNanoseconds)
        if (gracefulPing >= 0) at(gracefulDeadline)
        return t
    }

    fun onTimeout(now: Long) {
        lastNow = now
        if (closed) return
        if (settingsUnacked > 0 && settingsSentAt >= 0 && now - settingsSentAt >= settings.settingsAckTimeout.inWholeNanoseconds) {
            return connectionError(Http2ErrorCode.SETTINGS_TIMEOUT, "SETTINGS not acknowledged within ${settings.settingsAckTimeout}")
        }
        if (inBlock && now - blockStartedAt >= settings.maxHeaderBlockTime.inWholeNanoseconds) {
            return connectionError(Http2ErrorCode.ENHANCE_YOUR_CALM, "field block not finished within ${settings.maxHeaderBlockTime}")
        }
        if (gracefulPing >= 0 && now >= gracefulDeadline) finishGracefulGoAway()
    }

    fun nextEvent(): H2Event? = events.removeFirstOrNull()

    /** Bytes of the field block being collected (a test hook for the CONTINUATION limits). */
    internal val blockBufferCapacity: Int get() = block.capacity

    /** The connection send window plus the DATA queued but not written (a test hook: dropped DATA must give its window back). */
    internal val connectionSendWindowAccounted: Long get() = connSendWindow + queuedDataBytes

    /** Send-window conservation (a fuzz invariant): credit granted = window left + DATA queued + DATA written. */
    internal val sendWindowConserved: Boolean get() = sendCredited == connSendWindow + queuedDataBytes + dataWritten

    /** Control frames waiting for [poll] (a test hook for the queue limit). */
    internal val controlQueued: Int get() = control.size + pingAnswers.size

    // ---------------------------------------------------------------------------------------------------------------
    // internals

    private fun emit(e: H2Event) {
        if (!closedReported) events.addLast(e) // nothing after Closed
    }

    private fun canSend(s: H2Stream): Boolean = s.state == StreamState.OPEN || s.state == StreamState.HALF_CLOSED_REMOTE

    private fun checkListSize(fields: List<Pair<String, String>>) {
        var size = 0L
        for ((n, v) in fields) size += entrySize(n, v)
        if (size > peerMaxHeaderListSize) throw H2HeaderListTooLarge("field section of $size bytes above the peer's $peerMaxHeaderListSize")
    }

    private fun enqueue(
        s: H2Stream,
        item: OutItem,
    ) {
        s.out.addLast(item)
        schedule(s)
    }

    private fun schedule(s: H2Stream) {
        if (s.scheduled || s.out.isEmpty()) return
        s.scheduled = true
        (if (s.out.first() is OutItem.Fields) headerReady else dataReady).addLast(s)
    }

    /** The next whole frame (or field block) to write; field lists are HPACK-encoded here, in wire order (section 4.3.1). */
    private fun nextFrame(now: Long): ByteArray? {
        initial.removeFirstOrNull()?.let {
            if (it === ourSettingsFrame) settingsSentAt = now // the acknowledgement deadline and the RTT count from here
            return it
        }
        pingAnswers.removeFirstOrNull()?.let { return it }
        control.removeFirstOrNull()?.let { return it }
        if (closed) return null
        while (true) {
            val s = creditReady.removeFirstOrNull() ?: break
            val inc = s.pendingCredit
            s.pendingCredit = 0
            if (inc > 0 && s.state != StreamState.CLOSED &&
                s.state != StreamState.HALF_CLOSED_REMOTE
            ) {
                return FrameEncoder.windowUpdate(s.id, inc.toInt())
            }
        }
        var s: H2Stream
        while (true) {
            s = headerReady.removeFirstOrNull() ?: dataReady.removeFirstOrNull() ?: return null
            s.scheduled = false
            if (s.out.isNotEmpty()) break // a stream whose queue was dropped (a reset) leaves its slot empty
        }
        val frame =
            when (val item = s.out.removeFirst()) {
                is OutItem.Fields -> {
                    encodeBlock(s.id, item)
                }

                is OutItem.Data -> {
                    queuedDataBytes -= item.length
                    dataWritten += item.length
                    item.frame
                }
            }
        if (frame[3].toInt() == 0x1) s.headersSent = true // HEADERS: the stream left the idle state for the peer
        if (frame[3].toInt() <= 0x1) wroteSincePing = true // DATA or HEADERS
        if (frame[3].toInt() == 0x0) {
            s.dataQueued = false
            tryWake(s)
        }
        schedule(s)
        if (s.stopPeerAfterFlush && s.out.isEmpty()) {
            s.stopPeerAfterFlush = false
            // the client ended its side meanwhile, or the reset of [release] (section 8.1) goes out now, after the response
            if (s.state == StreamState.HALF_CLOSED_LOCAL) resetStream(s.id, Http2ErrorCode.NO_ERROR, now, causedByPeer = false)
        }
        if (s.state == StreamState.CLOSED && s.out.isEmpty() && s.released) removeStream(s)
        return frame
    }

    /** HEADERS and CONTINUATION frames of one field block in one array, so they are written back to back (section 4.3). */
    private fun encodeBlock(
        id: Int,
        item: OutItem.Fields,
    ): ByteArray {
        val encoded = hpackOut.encode(item.fields)
        val max = minOf(peerMaxFrameSize, H2.MIN_MAX_FRAME_SIZE)
        var out = FrameEncoder.headers(id, encoded.copyOfRange(0, minOf(max, encoded.size)), item.endStream, encoded.size <= max)
        var at = max
        while (at < encoded.size) {
            val end = minOf(at + max, encoded.size)
            out += FrameEncoder.continuation(id, encoded.copyOfRange(at, end), end == encoded.size)
            at = end
        }
        return out
    }

    private fun queueControl(frame: ByteArray) {
        if (closed) return
        // CVE-2019-9512/9515: a peer that makes us answer without reading our answers must not grow this queue; called from the
        // driver's actions too, so this ends the connection instead of throwing
        if (control.size + pingAnswers.size >= settings.maxControlFramesQueued) {
            return connectionError(Http2ErrorCode.ENHANCE_YOUR_CALM, "more than ${settings.maxControlFramesQueued} control frames queued")
        }
        control.addLast(frame)
    }

    /** Credit [n] bytes of [s] back to the peer: the connection at once when due, the stream as one coalesced WINDOW_UPDATE. */
    private fun credit(
        s: H2Stream,
        n: Long,
        now: Long,
    ) {
        creditConnection(n, now)
        if (s.state == StreamState.HALF_CLOSED_REMOTE || s.state == StreamState.CLOSED) return // no more data will come
        val inc = s.recv.onConsumed(n, now, rttNanos)
        if (inc <= 0) return
        s.pendingCredit += inc
        if (s.pendingCredit == inc.toLong()) creditReady.addLast(s)
    }

    private fun creditConnection(
        n: Long,
        now: Long,
    ) {
        val inc = connRecv.onConsumed(n, now, rttNanos)
        if (inc > 0) queueControl(FrameEncoder.windowUpdate(0, inc))
    }

    /** Content of [s] that will never be read goes back to the connection window. */
    private fun dropUnconsumed(s: H2Stream) {
        val n = s.unconsumed
        s.unconsumed = 0
        if (n > 0 && !closed) creditConnection(n, lastNow)
    }

    /** Drops what [s] still had to send; DATA that was never written gives its window back to the connection. */
    private fun dropQueued(s: H2Stream) {
        var refund = 0L
        for (item in s.out) if (item is OutItem.Data) refund += item.length
        s.out.clear()
        s.dataQueued = false
        if (refund == 0L) return
        queuedDataBytes -= refund
        connSendWindow += refund
        for (w in blockedOnConnection.toList()) tryWake(w)
    }

    private fun want(s: H2Stream) {
        s.wantsWindow = true
        writers.add(s)
    }

    /** Reports [H2Event.WindowAvailable] for [s] if it waits for window and has some now; otherwise files where it waits. */
    private fun tryWake(s: H2Stream) {
        if (!s.wantsWindow) return
        if (!canSend(s)) {
            s.wantsWindow = false
            writers.remove(s)
            blockedOnConnection.remove(s)
            return
        }
        if (s.dataQueued || s.sendWindow <= 0) {
            blockedOnConnection.remove(s)
            return
        }
        if (connSendWindow <= 0) {
            blockedOnConnection.add(s)
            return
        }
        s.wantsWindow = false
        writers.remove(s)
        blockedOnConnection.remove(s)
        emit(H2Event.WindowAvailable(s.id))
    }

    private fun remoteEnded(s: H2Stream) {
        s.state = if (s.state == StreamState.HALF_CLOSED_LOCAL) StreamState.CLOSED else StreamState.HALF_CLOSED_REMOTE
        s.pendingCredit = 0
        if (s.state == StreamState.CLOSED) closeStream(s, weReset = false, flush = true)
    }

    private fun localEnded(s: H2Stream) {
        s.state = if (s.state == StreamState.HALF_CLOSED_REMOTE) StreamState.CLOSED else StreamState.HALF_CLOSED_LOCAL
        if (s.state == StreamState.CLOSED) closeStream(s, weReset = false, flush = true)
    }

    /**
     * Closes [s]. A normal end ([flush]) still writes what is queued; otherwise queued field lists (never encoded) and DATA
     * are dropped, and so is pending stream credit (section 6.4: nothing more on a reset stream).
     */
    private fun closeStream(
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

    private fun removeStream(s: H2Stream) {
        if (streams.remove(s.id) == null) return
        if (!s.local) peerStreams--
        dropUnconsumed(s)
        maybeFinished()
    }

    private fun rememberClosed(
        id: Int,
        weReset: Boolean,
    ) {
        recentlyClosed.remove(id)
        recentlyClosed[id] = weReset
        if (recentlyClosed.size > recentlyClosedMax) recentlyClosed.remove(recentlyClosed.keys.first())
    }

    /** Our RST_STREAM for [id]; [causedByPeer] (an error of the peer) also takes from the glitch budget (MadeYouReset, CVE-2025-8671). */
    private fun resetStream(
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
    private fun streamError(
        id: Int,
        code: Http2ErrorCode,
        message: String,
        now: Long,
    ) {
        if (isIdle(id) && streams[id] == null) throw H2ConnectionError(code, "$message on idle stream $id")
        resetStream(id, code, now, causedByPeer = true)
    }

    private fun calm(message: String): Nothing = throw H2ConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM, message)

    private fun sendGoAway(
        lastId: Int,
        code: Http2ErrorCode,
        debug: ByteArray,
    ) {
        // section 6.8: the last stream identifier never grows from one GOAWAY to the next
        val last = if (goAwaySentLastId >= 0) minOf(lastId, goAwaySentLastId) else lastId
        goAwaySentLastId = last
        control.addLast(FrameEncoder.goAway(last, code.code, debug))
    }

    private fun finishGracefulGoAway() {
        pingsOut.remove(gracefulPing)
        gracefulPing = -1
        sendGoAway(lastPeerStreamId, Http2ErrorCode.NO_ERROR, ByteArray(0)) // the second phase
        maybeFinished()
    }

    /** A connection error (section 5.4.1): only our GOAWAY goes out after it, then the transport closes. */
    private fun connectionError(
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
    private fun maybeFinished() {
        if (closed || streams.isNotEmpty()) return
        val drainingOut = goAwaySentLastId >= 0 && goAwaySentLastId != H2.MAX_STREAM_ID
        if (goAwayReceived || drainingOut) {
            closed = true
            report(Http2ErrorCode.NO_ERROR, byPeer = goAwayReceived && !drainingOut, "GOAWAY and no streams left")
        }
    }

    private fun report(
        code: Http2ErrorCode,
        byPeer: Boolean,
        reason: String,
    ) {
        if (closedReported) return
        events.addLast(H2Event.Closed(code, byPeer, reason))
        closedReported = true
    }

    private companion object {
        const val MAX_PINGS_OUT = 16
        val EMPTY = ByteArray(0)
    }
}
