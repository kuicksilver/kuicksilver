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
 *   be acknowledged within [Http2Settings.settingsAckTimeout] or the connection ends with SETTINGS_TIMEOUT.
 * - Streams (section 5.1): the client opens odd streams with [openStream], the server answers with [sendHeaders]. Server
 *   push is never used: a client sends SETTINGS_ENABLE_PUSH = 0 and refuses PUSH_PROMISE.
 * - Flow control (sections 5.2, 6.9): WINDOW_UPDATE goes out only when the driver reports with [consumed] that the
 *   application read the data, so memory per connection stays within the connection window; [sendData] takes at most
 *   one frame's worth within both windows and never buffers beyond it.
 * - Floods (threat model 3.23): field blocks are bounded in bytes, CONTINUATION frames and time before decoding; queued
 *   control frames, empty DATA frames and stream resets (the peer's and the ones its errors cause) are bounded per
 *   connection; a stream the peer reset still counts toward our SETTINGS_MAX_CONCURRENT_STREAMS until [release].
 * - Order of output: control frames first, then field blocks, then DATA round-robin between streams. RFC 7540
 *   priorities are parsed and ignored (section 5.3.2).
 */
internal class H2ConnectionCore(
    val role: Role,
    val settings: Http2Settings,
    now: Long,
) {
    private val client = role == Role.CLIENT
    private val decoder = FrameDecoder(settings.maxFrameSize)
    private val hpackIn = HpackDecoder(maxOf(H2.DEFAULT_HEADER_TABLE_SIZE, settings.headerTableSize), settings.maxHeaderListSize)
    private val hpackOut = HpackEncoder(maxTableSize = H2.DEFAULT_HEADER_TABLE_SIZE)
    private val block = HeaderBlockCollector(settings.maxHeaderListSize, settings.maxContinuationFrames)
    private val resets = TokenBucket(settings.resetBurst, settings.resetsPerSecond, now)

    private val streams = HashMap<Int, H2Stream>()

    /** Recently closed streams: true when we reset them (late frames are then ignored), false otherwise (STREAM_CLOSED). */
    private val recentlyClosed = LinkedHashMap<Int, Boolean>()
    private val recentlyClosedMax = maxOf(256, minOf(settings.maxConcurrentStreams, 4_096) * 2)

    /** The preface and our first SETTINGS: they go out before anything, even before the GOAWAY of an early error. */
    private val initial = ArrayDeque<ByteArray>()
    private val control = ArrayDeque<ByteArray>()
    private val headerReady = ArrayDeque<H2Stream>()
    private val dataReady = ArrayDeque<H2Stream>()
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
    private val connRecv = RecvWindow(settings.initialConnectionWindow.toLong(), settings.maxConnectionWindow.toLong())

    /** The receive window streams start with: the protocol's 65 535 until our SETTINGS are acknowledged, if ours is smaller. */
    private var recvInitialWindow = maxOf(H2.DEFAULT_WINDOW, settings.initialStreamWindow).toLong()

    private var prefaceLeft = if (client) 0 else H2.PREFACE.size
    private var peerSettingsSeen = false
    private var settingsSentAt = now
    private var settingsUnacked = 1
    private var rttNanos = 100_000_000L // until the SETTINGS acknowledgement measures it
    private var nextLocalId = if (client) 1 else 2
    private var lastPeerStreamId = 0
    private var refusedInARow = 0
    private var emptyDataInARow = 0

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

    private var goAwayReceived = false
    private var peerLastStreamId = H2.MAX_STREAM_ID

    /** The last stream ID of the GOAWAY we sent (MAX_STREAM_ID for the first phase of a graceful one), or -1. */
    private var goAwaySentLastId = -1
    private var closed = false
    private var closedReported = false

    /** True once the connection ended (an error, a finished GOAWAY): nothing more is read, [poll] drains what is left. */
    val isClosed: Boolean get() = closed

    /** Streams open in either direction (closed ones the driver has not released yet included). */
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
        initial.addLast(FrameEncoder.settings(ids.toIntArray(), values.toLongArray()))
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
            is Frame.GoAway -> onGoAway(f, now)
            is Frame.WindowUpdate -> onWindowUpdate(f, now)
            is Frame.Unknown -> Unit // section 5.5
        }
    }

    private fun peerInitiated(id: Int): Boolean = (id and 1 == 1) == !client

    /** Idle (section 5.1): never used by its initiator yet. */
    private fun isIdle(id: Int): Boolean = if (peerInitiated(id)) id > lastPeerStreamId else id >= nextLocalId

    private fun onData(
        f: Frame.Data,
        now: Long,
    ) {
        val id = f.streamId
        if (f.data.isEmpty() && !f.endStream) {
            if (++emptyDataInARow > settings.maxEmptyFrames) calm("more than ${settings.maxEmptyFrames} empty DATA frames in a row")
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
        if (padding > 0) consumed(id, padding.toLong(), now) // padding is never read by the application
        events.addLast(H2Event.Data(id, f.data, f.endStream))
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
        if (!block.add(fragment, continuation = false)) calm("field block above ${settings.maxHeaderListSize} bytes")
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
            calm("field block above ${settings.maxHeaderListSize} bytes or ${settings.maxContinuationFrames} CONTINUATION frames")
        }
        if (f.endHeaders) endBlock(now)
    }

    private fun endBlock(now: Long) {
        inBlock = false
        val fields = ArrayList<Pair<String, String>>()
        val fits =
            try {
                hpackIn.decode(block.block()) { n, v -> fields += n to v }
            } catch (e: HpackError) {
                throw H2ConnectionError(Http2ErrorCode.COMPRESSION_ERROR, e.message ?: "HPACK decoding error") // section 4.3
            }
        block.reset()
        if (blockPromised != 0) onPushPromiseBlock(blockStream, blockPromised, now) else onHeaders(blockStream, fields, fits, now)
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
                if (recentlyClosed[id] == false) streamError(id, Http2ErrorCode.STREAM_CLOSED, "HEADERS on a closed stream", now)
                return
            }
            if (id <= lastPeerStreamId) {
                // section 5.1.1: identifiers only grow; a closed stream we remember answers STREAM_CLOSED
                when (recentlyClosed[id]) {
                    false -> streamError(id, Http2ErrorCode.STREAM_CLOSED, "HEADERS on a closed stream", now)

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
            if (blockDependency ==
                id
            ) {
                return streamError(id, Http2ErrorCode.PROTOCOL_ERROR, "stream depends on itself (section 5.3.1)", now)
            }
            val running = streams.values.count { !it.local }
            if (running >= settings.maxConcurrentStreams) {
                // section 5.1.2: REFUSED_STREAM; a peer that keeps opening past the limit is flooding (golang/go#63417)
                if (++refusedInARow >
                    4 * maxOf(settings.maxConcurrentStreams, 1)
                ) {
                    calm("more than ${4 * settings.maxConcurrentStreams} refused streams in a row")
                }
                return streamError(id, Http2ErrorCode.REFUSED_STREAM, "SETTINGS_MAX_CONCURRENT_STREAMS reached", now)
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
            events.addLast(H2Event.HeadersReceived(id, fields, endStream, !fits))
            return
        }
        if (s.state == StreamState.CLOSED) {
            if (recentlyClosed[id] != true) streamError(id, Http2ErrorCode.STREAM_CLOSED, "HEADERS on a closed stream", now)
            return
        }
        if (blockDependency == id) return streamError(id, Http2ErrorCode.PROTOCOL_ERROR, "stream depends on itself (section 5.3.1)", now)
        if (s.state == StreamState.HALF_CLOSED_REMOTE) return streamError(id, Http2ErrorCode.STREAM_CLOSED, "HEADERS after END_STREAM", now)
        if (s.finalHeadersReceived) {
            // trailers (section 8.1): they end the stream
            if (!endStream) return streamError(id, Http2ErrorCode.PROTOCOL_ERROR, "a second field section without END_STREAM", now)
        } else {
            val status = fields.firstOrNull()?.takeIf { it.first == ":status" }?.second
            val informational = client && status != null && status.length == 3 && status[0] == '1'
            if (informational &&
                endStream
            ) {
                return streamError(id, Http2ErrorCode.PROTOCOL_ERROR, "an interim response with END_STREAM", now)
            }
            if (!informational) s.finalHeadersReceived = true
        }
        events.addLast(H2Event.HeadersReceived(id, fields, endStream, !fits))
        if (endStream) remoteEnded(s)
    }

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
        if (!valid &&
            recentlyClosed[f.streamId] != true
        ) {
            throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "PUSH_PROMISE on stream ${f.streamId}")
        }
        lastPeerStreamId = p
        startBlock(f.streamId, p, false, -1, f.fragment, f.endHeaders, now)
    }

    private fun onPushPromiseBlock(
        id: Int,
        promised: Int,
        now: Long,
    ) {
        // the push our SETTINGS had not yet forbidden: the block was decoded for HPACK, the stream is cancelled
        resetStream(promised, Http2ErrorCode.CANCEL, now, causedByPeer = true)
    }

    private fun onPriority(
        f: Frame.Priority,
        now: Long,
    ) {
        // deprecated signal (section 5.3.2): no state; a stream may not depend on itself (section 5.3.1)
        if (f.dependency == f.streamId) streamError(f.streamId, Http2ErrorCode.PROTOCOL_ERROR, "stream depends on itself", now)
    }

    private fun onRstStream(
        f: Frame.RstStream,
        now: Long,
    ) {
        val id = f.streamId
        if (isIdle(id) && streams[id] == null) throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "RST_STREAM on idle stream $id")
        if (!resets.take(now)) calm("stream resets above ${settings.resetsPerSecond}/s (burst ${settings.resetBurst})")
        val s = streams[id] ?: return
        if (s.state == StreamState.CLOSED) return
        val code = Http2ErrorCode.of(f.errorCode)
        closeStream(s, weReset = false)
        events.addLast(H2Event.StreamReset(id, code, byPeer = true, notProcessed = code == Http2ErrorCode.REFUSED_STREAM))
    }

    private fun onSettings(
        f: Frame.Settings,
        now: Long,
    ) {
        if (f.ack) {
            if (settingsUnacked == 0) return
            settingsUnacked--
            rttNanos = maxOf(1, now - settingsSentAt)
            ourSettingsAcknowledged()
            return
        }
        for (i in f.ids.indices) {
            val v = f.values[i]
            when (f.ids[i]) {
                SettingId.HEADER_TABLE_SIZE -> {
                    hpackOut.setPeerMaxTableSize(v)
                }

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
                    // section 6.9.2: every stream window moves by the difference, possibly below zero
                    for (s in streams.values) {
                        s.sendWindow += delta
                        if (s.sendWindow >
                            H2.MAX_WINDOW
                        ) {
                            throw H2ConnectionError(Http2ErrorCode.FLOW_CONTROL_ERROR, "stream ${s.id} window above 2^31 - 1")
                        }
                    }
                }

                SettingId.MAX_FRAME_SIZE -> {
                    if (v < H2.MIN_MAX_FRAME_SIZE || v > H2.MAX_MAX_FRAME_SIZE) {
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
        events.addLast(H2Event.SettingsChanged)
        wakeWriters()
    }

    /** Section 6.5.3: our values hold once acknowledged; a smaller value than the protocol's initial one tightens only now. */
    private fun ourSettingsAcknowledged() {
        hpackIn.setMaxTableSize(settings.headerTableSize)
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
        if (!f.ack) return queueControl(FrameEncoder.ping(true, f.payload)) // section 6.7, ahead of other frames
        val sent = pingsOut.remove(f.payload) ?: return
        rttNanos = maxOf(1, now - sent)
        events.addLast(H2Event.PingAck(f.payload, now - sent))
        if (f.payload == gracefulPing) {
            gracefulPing = -1
            sendGoAway(lastPeerStreamId, Http2ErrorCode.NO_ERROR, ByteArray(0)) // the second phase of a graceful GOAWAY
            maybeFinished()
        }
    }

    private fun onGoAway(
        f: Frame.GoAway,
        now: Long,
    ) {
        goAwayReceived = true
        // section 6.8: the last stream ID never grows; streams above it were not processed and may be retried
        peerLastStreamId = minOf(peerLastStreamId, f.lastStreamId)
        val code = Http2ErrorCode.of(f.errorCode)
        events.addLast(H2Event.GoAway(peerLastStreamId, code, f.debug.copyOf(minOf(f.debug.size, 1_024))))
        for (s in streams.values.filter { it.local && it.id > peerLastStreamId && it.state != StreamState.CLOSED }) {
            closeStream(s, weReset = false)
            events.addLast(H2Event.StreamReset(s.id, Http2ErrorCode.REFUSED_STREAM, byPeer = true, notProcessed = true))
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
            if (connSendWindow >
                H2.MAX_WINDOW
            ) {
                throw H2ConnectionError(Http2ErrorCode.FLOW_CONTROL_ERROR, "connection window above 2^31 - 1")
            }
            return wakeWriters()
        }
        val s = streams[id]
        if (s == null) {
            if (isIdle(id)) throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "WINDOW_UPDATE on idle stream $id")
            return // a closed stream: allowed (section 5.1)
        }
        if (f.increment == 0) return streamError(id, Http2ErrorCode.PROTOCOL_ERROR, "WINDOW_UPDATE of 0", now) // section 6.9
        if (s.state == StreamState.CLOSED) return
        s.sendWindow += f.increment
        if (s.sendWindow > H2.MAX_WINDOW) return streamError(id, Http2ErrorCode.FLOW_CONTROL_ERROR, "stream window above 2^31 - 1", now)
        wakeWriters()
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
        val open = streams.values.count { it.local && it.state != StreamState.CLOSED }
        if (open >= peerMaxConcurrent) throw H2StreamLimit("the peer allows $peerMaxConcurrent concurrent streams")
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
        queueBlock(s, fields, endStream)
        return id
    }

    /** Sends a field section on [streamId]: a response, an interim response or trailers ([endStream] true for trailers). */
    fun sendHeaders(
        streamId: Int,
        fields: List<Pair<String, String>>,
        endStream: Boolean,
    ) {
        val s = streams[streamId] ?: throw IllegalStateException("stream $streamId is closed")
        check(s.state == StreamState.OPEN || s.state == StreamState.HALF_CLOSED_REMOTE) { "stream $streamId cannot send" }
        checkListSize(fields)
        queueBlock(s, fields, endStream)
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
        check(s.state == StreamState.OPEN || s.state == StreamState.HALF_CLOSED_REMOTE) { "stream $streamId cannot send" }
        if (s.dataQueued) {
            s.wantsWindow = true
            return 0
        }
        val n =
            minOf(
                len.toLong(),
                connSendWindow,
                s.sendWindow,
                minOf(peerMaxFrameSize, H2.MIN_MAX_FRAME_SIZE).toLong(),
            ).toInt().coerceAtLeast(0)
        if (n == 0 && len > 0) {
            s.wantsWindow = true
            return 0
        }
        val end = endStream && n == len
        connSendWindow -= n
        s.sendWindow -= n
        enqueue(s, FrameEncoder.data(streamId, buf, off, n, end), headers = false)
        s.dataQueued = true
        if (n < len) s.wantsWindow = true
        if (end) localEnded(s)
        return n
    }

    /** The application read [n] bytes of [streamId]: credit goes back to the peer (WINDOW_UPDATE) when due. */
    fun consumed(
        streamId: Int,
        n: Long,
        now: Long,
    ) {
        if (n <= 0 || closed) return
        creditConnection(n, now)
        val s = streams[streamId] ?: return
        if (s.state == StreamState.HALF_CLOSED_REMOTE || s.state == StreamState.CLOSED) return // no more data will come
        val inc = s.recv.onConsumed(n, now, rttNanos)
        if (inc > 0) queueControl(FrameEncoder.windowUpdate(streamId, inc))
    }

    /** Resets [streamId] with [code] (the application cancelled it); not counted against the peer's reset budget. */
    fun reset(
        streamId: Int,
        code: Http2ErrorCode,
        now: Long,
    ) {
        if (closed) return
        resetStream(streamId, code, now, causedByPeer = false)
    }

    /** The driver finished with [streamId] (its handler returned): it stops counting toward our concurrency limit. */
    fun release(streamId: Int) {
        val s = streams[streamId] ?: return
        s.released = true
        refusedInARow = 0
        if (s.state == StreamState.CLOSED && s.out.isEmpty()) streams.remove(streamId) // else once its last frame is written
        maybeFinished()
    }

    /** Sends a PING (section 6.7) and returns its payload; [H2Event.PingAck] reports the answer. */
    fun ping(now: Long): Long {
        val payload = ++pingCounter
        if (pingsOut.size >= MAX_PINGS_OUT) pingsOut.remove(pingsOut.keys.first())
        pingsOut[payload] = now
        queueControl(FrameEncoder.ping(false, payload))
        return payload
    }

    /**
     * Sends GOAWAY (section 6.8). [graceful]: first with the largest stream identifier and a PING, then, when the PING is
     * answered (a round trip later, so streams the peer opened meanwhile are counted), with the last stream we accepted.
     * Otherwise at once with the last stream we accepted; an error [code] also closes the connection.
     */
    fun goAway(
        code: Http2ErrorCode,
        debug: ByteArray,
        graceful: Boolean,
        now: Long,
    ) {
        if (closed) return
        if (code != Http2ErrorCode.NO_ERROR) return connectionError(code, debug.decodeToString())
        if (graceful && goAwaySentLastId < 0) {
            sendGoAway(H2.MAX_STREAM_ID, code, debug)
            gracefulPing = ping(now)
        } else {
            sendGoAway(lastPeerStreamId, code, debug)
            maybeFinished()
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // output, time, events

    /** Writes pending bytes into [out] from [off]; returns how many. Field blocks are never interleaved with other frames. */
    fun poll(
        out: ByteArray,
        off: Int = 0,
        now: Long = 0,
    ): Int {
        var p = off
        while (p < out.size) {
            val cur = partial ?: nextFrame() ?: break
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
        if (!closed) wakeWriters()
        return p - off
    }

    /** True when [poll] has something to write. */
    val wantsWrite: Boolean get() =
        partial != null || initial.isNotEmpty() || control.isNotEmpty() || headerReady.isNotEmpty() ||
            dataReady.isNotEmpty()

    /** The next deadline (nanoseconds) for [onTimeout], or null. */
    fun nextTimeout(): Long? {
        if (closed) return null
        var t: Long? = null
        if (settingsUnacked > 0) t = settingsSentAt + settings.settingsAckTimeout.inWholeNanoseconds
        if (inBlock) {
            val b = blockStartedAt + settings.maxHeaderBlockTime.inWholeNanoseconds
            t = if (t == null) b else minOf(t, b)
        }
        return t
    }

    fun onTimeout(now: Long) {
        if (closed) return
        if (settingsUnacked > 0 && now - settingsSentAt >= settings.settingsAckTimeout.inWholeNanoseconds) {
            return connectionError(Http2ErrorCode.SETTINGS_TIMEOUT, "SETTINGS not acknowledged within ${settings.settingsAckTimeout}")
        }
        if (inBlock && now - blockStartedAt >= settings.maxHeaderBlockTime.inWholeNanoseconds) {
            connectionError(Http2ErrorCode.ENHANCE_YOUR_CALM, "field block not finished within ${settings.maxHeaderBlockTime}")
        }
    }

    fun nextEvent(): H2Event? = events.removeFirstOrNull()

    /** Bytes of the field block being collected (a test hook for the CONTINUATION limits). */
    internal val blockBufferCapacity: Int get() = block.capacity

    /** Control frames waiting for [poll] (a test hook for the queue limit). */
    internal val controlQueued: Int get() = control.size

    // ---------------------------------------------------------------------------------------------------------------
    // internals

    private fun checkListSize(fields: List<Pair<String, String>>) {
        var size = 0L
        for ((n, v) in fields) size += entrySize(n, v)
        if (size > peerMaxHeaderListSize) throw H2HeaderListTooLarge("field section of $size bytes above the peer's $peerMaxHeaderListSize")
    }

    private fun queueBlock(
        s: H2Stream,
        fields: List<Pair<String, String>>,
        endStream: Boolean,
    ) {
        val encoded = hpackOut.encode(fields)
        val max = minOf(peerMaxFrameSize, H2.MIN_MAX_FRAME_SIZE)
        // one array for the whole block, so poll writes HEADERS and its CONTINUATION frames back to back (section 4.3)
        var out = FrameEncoder.headers(s.id, encoded.copyOfRange(0, minOf(max, encoded.size)), endStream, encoded.size <= max)
        var at = max
        while (at < encoded.size) {
            val end = minOf(at + max, encoded.size)
            out += FrameEncoder.continuation(s.id, encoded.copyOfRange(at, end), end == encoded.size)
            at = end
        }
        s.headersSent = true
        enqueue(s, out, headers = true)
    }

    private fun enqueue(
        s: H2Stream,
        frame: ByteArray,
        headers: Boolean,
    ) {
        val wasEmpty = s.out.isEmpty()
        s.out.addLast(frame)
        s.outHeads.addLast(headers)
        if (wasEmpty) (if (headers) headerReady else dataReady).addLast(s)
    }

    private fun nextFrame(): ByteArray? {
        initial.removeFirstOrNull()?.let { return it }
        control.removeFirstOrNull()?.let { return it }
        if (closed) return null
        val s = headerReady.removeFirstOrNull() ?: dataReady.removeFirstOrNull() ?: return null
        val frame = s.out.removeFirst()
        val wasHeaders = s.outHeads.removeFirst()
        if (!wasHeaders) s.dataQueued = false
        if (s.out.isNotEmpty()) (if (s.outHeads.first()) headerReady else dataReady).addLast(s)
        if (s.state == StreamState.CLOSED && s.out.isEmpty() && (s.local || s.released)) {
            streams.remove(s.id)
            maybeFinished()
        }
        return frame
    }

    private fun queueControl(frame: ByteArray) {
        if (closed) return
        // CVE-2019-9512/9515: a peer that makes us answer without reading our answers must not grow this queue; called from the
        // driver's actions too, so this ends the connection instead of throwing
        if (control.size >= settings.maxControlFramesQueued) {
            return connectionError(Http2ErrorCode.ENHANCE_YOUR_CALM, "more than ${settings.maxControlFramesQueued} control frames queued")
        }
        control.addLast(frame)
    }

    private fun creditConnection(
        n: Long,
        now: Long,
    ) {
        val inc = connRecv.onConsumed(n, now, rttNanos)
        if (inc > 0) queueControl(FrameEncoder.windowUpdate(0, inc))
    }

    private fun wakeWriters() {
        if (connSendWindow <= 0) return
        for (s in streams.values) {
            if (s.wantsWindow && !s.dataQueued && s.sendWindow > 0 &&
                (s.state == StreamState.OPEN || s.state == StreamState.HALF_CLOSED_REMOTE)
            ) {
                s.wantsWindow = false
                events.addLast(H2Event.WindowAvailable(s.id))
            }
        }
    }

    private fun remoteEnded(s: H2Stream) {
        s.state = if (s.state == StreamState.HALF_CLOSED_LOCAL) StreamState.CLOSED else StreamState.HALF_CLOSED_REMOTE
        if (s.state == StreamState.CLOSED) closeStream(s, weReset = false, flush = true)
    }

    private fun localEnded(s: H2Stream) {
        s.state = if (s.state == StreamState.HALF_CLOSED_REMOTE) StreamState.CLOSED else StreamState.HALF_CLOSED_LOCAL
        if (s.state == StreamState.CLOSED) closeStream(s, weReset = false, flush = true)
    }

    /** Closes [s]; queued frames are dropped unless [flush] (a normal end: they still go out). */
    private fun closeStream(
        s: H2Stream,
        weReset: Boolean,
        flush: Boolean = false,
    ) {
        s.state = StreamState.CLOSED
        if (!flush) {
            s.out.clear()
            s.outHeads.clear()
            s.dataQueued = false
            headerReady.remove(s)
            dataReady.remove(s)
        }
        s.wantsWindow = false
        rememberClosed(s.id, weReset)
        if (s.out.isEmpty() && (s.local || s.released)) streams.remove(s.id)
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

    /** Our RST_STREAM for [id]; [causedByPeer] resets take from the reset budget (MadeYouReset, CVE-2025-8671). */
    private fun resetStream(
        id: Int,
        code: Http2ErrorCode,
        now: Long,
        causedByPeer: Boolean,
    ) {
        val s = streams[id]
        val active = s != null && s.state != StreamState.CLOSED
        if (!active && recentlyClosed[id] == true) return // reset by us already: one RST_STREAM per stream
        if (causedByPeer && !resets.take(now)) calm("stream errors above ${settings.resetsPerSecond}/s (burst ${settings.resetBurst})")
        // later frames on this stream are discarded (section 5.1), so a peer cannot make us answer them again
        if (active) closeStream(s, weReset = true) else rememberClosed(id, weReset = true)
        queueControl(FrameEncoder.rstStream(id, code.code))
        if (active) events.addLast(H2Event.StreamReset(id, code, byPeer = false, notProcessed = code == Http2ErrorCode.REFUSED_STREAM))
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

    /** A connection error (section 5.4.1): only our GOAWAY goes out after it, then the transport closes. */
    private fun connectionError(
        code: Http2ErrorCode,
        message: String,
    ) {
        if (closed) return
        // a frame already partly written is finished first (the peer must still parse the stream), then only the GOAWAY
        control.clear()
        headerReady.clear()
        dataReady.clear()
        sendGoAway(lastPeerStreamId, code, message.encodeToByteArray().copyOf(minOf(message.length, 256)))
        closed = true
        for (s in streams.values) {
            if (s.state !=
                StreamState.CLOSED
            ) {
                events.addLast(H2Event.StreamReset(s.id, code, byPeer = false, notProcessed = s.local && !s.headersSent))
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
        closedReported = true
        events.addLast(H2Event.Closed(code, byPeer, reason))
    }

    private companion object {
        const val MAX_PINGS_OUT = 16
    }
}
