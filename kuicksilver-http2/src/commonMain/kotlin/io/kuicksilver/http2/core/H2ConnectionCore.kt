// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameDecoder
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.FrameType
import io.kuicksilver.http2.frame.H2
import io.kuicksilver.http2.frame.H2ConnectionError
import io.kuicksilver.http2.frame.H2StreamError
import io.kuicksilver.http2.frame.SettingId
import io.kuicksilver.http2.hpack.HpackDecoder
import io.kuicksilver.http2.hpack.HpackEncoder
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
 *   SETTINGS_TIMEOUT. A client opens streams at once, under the section 6.5.2 initial values of the server's settings
 *   (section 3.4); a server preface that has not arrived by [expectPeerPrefaceBy]'s deadline ends the connection with
 *   SETTINGS_TIMEOUT too (our SETTINGS cannot be acknowledged before it).
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
    internal val client = role == Role.CLIENT
    private val decoder = FrameDecoder(settings.maxFrameSize).also { it.altSvcFrames = client }

    // section 4.3.1: both tables start at 4096; our own value holds once the peer acknowledged it
    internal val hpackIn =
        HpackDecoder(
            H2.DEFAULT_HEADER_TABLE_SIZE,
            settings.maxHeaderListSize,
            maxStringLength =
                2 * settings.maxHeaderListSize,
        )
    internal val hpackOut = HpackEncoder(maxTableSize = H2.DEFAULT_HEADER_TABLE_SIZE)
    internal val block = HeaderBlockCollector(2 * settings.maxHeaderListSize, settings.maxContinuationFrames)
    internal val resets = TokenBucket(settings.resetBurst, settings.resetsPerSecond, now)
    private val glitches = TokenBucket(settings.glitchBurst, settings.glitchesPerSecond, now)

    // insertion order is the order each side opened its streams in: the resets a GOAWAY or a close reports (and the
    // engine retries) come out in that order on every platform, not in a hash table's
    internal val streams = LinkedHashMap<Int, H2Stream>()
    internal var peerStreams = 0 // peer-initiated streams in [streams]: their handlers count toward our limit
    internal var localOpen = 0 // our streams not closed: they count toward the peer's limit

    /** Recently closed streams: true when we reset or discarded them (late frames are ignored), false otherwise (STREAM_CLOSED). */
    internal val recentlyClosed = LinkedHashMap<Int, Boolean>()
    internal val recentlyClosedMax = maxOf(256, minOf(settings.maxConcurrentStreams, 4_096) * 2)

    /** The preface and our first SETTINGS: they go out before anything, even before the GOAWAY of an early error. */
    private val initial = ArrayDeque<ByteArray>()
    private var ourSettingsFrame: ByteArray? = null
    internal val pingAnswers = ArrayDeque<ByteArray>() // section 6.7: ahead of every other control frame
    internal val control = ArrayDeque<ByteArray>()

    /**
     * Our SETTINGS acknowledgements held back, oldest first (see [queueSettingsAck]): each entry waits for the DATA of its
     * streams to be written and carries the later acknowledgements that wait only for it. [heldAcks] counts them all.
     */
    private val heldSettingsAcks = ArrayDeque<HeldAck>()
    private var heldAcks = 0

    private class HeldAck(
        val behind: MutableSet<H2Stream>,
    ) {
        var followers = 0
    }

    internal var wroteSincePing = true
    internal val creditReady = ArrayDeque<H2Stream>()
    internal val headerReady = ArrayDeque<H2Stream>()
    internal val dataReady = ArrayDeque<H2Stream>()
    internal val writers = LinkedHashSet<H2Stream>() // streams waiting for window
    internal val blockedOnConnection = LinkedHashSet<H2Stream>() // ... of which only the connection window holds back
    private var partial: ByteArray? = null
    private var partialPos = 0
    private val events = ArrayDeque<H2Event>()

    // the peer's settings (section 6.5.2 initial values)
    internal var peerMaxConcurrent = Long.MAX_VALUE
    internal var peerInitialWindow = H2.DEFAULT_WINDOW.toLong()
    internal var peerMaxFrameSize = H2.MIN_MAX_FRAME_SIZE
    internal var peerMaxHeaderListSize = Long.MAX_VALUE

    /** The peer allows Extended CONNECT (RFC 8441 section 3). */
    var peerEnableConnectProtocol: Boolean = false
        internal set

    /** The peer's SETTINGS_MAX_CONCURRENT_STREAMS, for the driver's pool. */
    val peerMaxConcurrentStreams: Long get() = peerMaxConcurrent

    internal var connSendWindow = H2.DEFAULT_WINDOW.toLong()
    internal var sendCredited = H2.DEFAULT_WINDOW.toLong() // the protocol's initial window plus the peer's connection credit
    private var queuedDataBytes = 0L // DATA payload taken by sendData, not yet written
    private var dataWritten = 0L
    internal val connRecv = RecvWindow(settings.initialConnectionWindow.toLong(), settings.maxConnectionWindow.toLong())

    /** The receive window streams start with: the protocol's 65 535 until our SETTINGS are acknowledged, if ours is smaller. */
    internal var recvInitialWindow = maxOf(H2.DEFAULT_WINDOW, settings.initialStreamWindow).toLong()

    private var prefaceLeft = if (client) 0 else H2.PREFACE.size
    private var peerSettingsSeen = false
    private var peerPrefaceDeadline = -1L
    private var peerPrefaceAt = -1L // when the peer's preface arrived

    /** The peer's connection preface (its first SETTINGS) arrived. */
    val peerPrefaceReceived: Boolean get() = peerSettingsSeen

    /** The connection ended because the peer's preface had not arrived by the [expectPeerPrefaceBy] deadline. */
    var peerPrefaceMissed: Boolean = false
        private set
    internal var settingsSentAt = -1L // when [poll] wrote our SETTINGS; -1 before
    internal var settingsUnacked = 1
    internal var rttNanos = 100_000_000L // until the SETTINGS acknowledgement measures it
    private var nextLocalId = if (client) 1 else 2
    internal var lastPeerStreamId = 0
    internal var refusedInARow = 0
    internal var emptyDataInARow = 0
    private var lastNow = now // the latest time a caller gave, for work that a call without a time triggers

    // the field block being collected: its stream, kind and flags
    internal var blockStream = 0
    internal var blockPromised = 0
    internal var blockEndStream = false
    internal var blockDependency = -1
    internal var blockStartedAt = 0L
    internal var inBlock = false

    private var pingCounter = 0L
    internal val pingsOut = LinkedHashMap<Long, Long>()
    internal var gracefulPing = -1L
    private var gracefulDeadline = -1L

    internal var goAwayReceived = false
    internal var peerLastStreamId = H2.MAX_STREAM_ID

    /** The last stream ID of the GOAWAY we sent (MAX_STREAM_ID for the first phase of a graceful one), or -1. */
    internal var goAwaySentLastId = -1
    internal var closed = false
    private var closedReported = false

    /**
     * The connection ended with ENHANCE_YOUR_CALM because a field block took longer than `maxHeaderBlockTime`: a slow
     * peer, not a flood (the engine does not count it against the peer's address).
     */
    var slowFieldBlock: Boolean = false
        private set

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
                p +=
                    try {
                        decoder.feed(buf, p, end - p)
                    } catch (e: H2ConnectionError) {
                        // section 3.4: before the peer's SETTINGS anything but a malformed SETTINGS frame (section 6.5) is an
                        // invalid preface, a PROTOCOL_ERROR whatever else is wrong with the frame (an HTTP/1.1 "HTT" reads
                        // as a length above SETTINGS_MAX_FRAME_SIZE)
                        if (peerSettingsSeen || decoder.lastFrameType == FrameType.SETTINGS) throw e
                        throw H2ConnectionError(Http2ErrorCode.PROTOCOL_ERROR, "invalid connection preface: ${e.message}")
                    }
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
            peerPrefaceAt = now
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
            is Frame.AltSvc -> onAltSvc(f, now)
            is Frame.Unknown -> glitch(now, "unknown frame type ${f.type}") // section 5.5: ignored, but not for free
        }
    }

    internal fun peerInitiated(id: Int): Boolean = (id and 1 == 1) == !client

    /** Idle (section 5.1): never used by its initiator yet. */
    internal fun isIdle(id: Int): Boolean = if (peerInitiated(id)) id > lastPeerStreamId else id >= nextLocalId

    /** Section 10.5: legal but suspicious when frequent; an empty glitch budget ends the connection (nghttp2's glitch limit). */
    internal fun glitch(
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
     * A server's ALTSVC frame (RFC 7838 section 4) on [streamId], a request stream it can still send on: [value] (an
     * `Alt-Svc` field value of ASCII characters) applies to the origin of that stream, so the Origin field is empty. Section
     * 3: "When using HTTP/2 ([RFC7540]), servers SHOULD instead send an ALTSVC frame". It is queued with the control frames,
     * ahead of the stream's next field block. Throws IllegalStateException on a client or a stream that cannot send, and
     * IllegalArgumentException for a value that is not ASCII or does not fit one frame of the peer's size.
     */
    fun sendAltSvc(
        streamId: Int,
        value: String,
    ) {
        check(!client) { "ALTSVC is sent by servers only (RFC 7838 section 4)" }
        val s = streams[streamId] ?: throw IllegalStateException("stream $streamId is closed")
        check(canSend(s)) { "stream $streamId cannot send" }
        require(value.all { it.code in 0x20..0x7e }) { "an Alt-Svc value is visible ASCII" }
        require(2 + value.length <= peerMaxFrameSize) { "an ALTSVC frame of ${2 + value.length} bytes exceeds the peer's frame size" }
        queueControl(FrameEncoder.altSvc(streamId, "", value))
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

    /**
     * Ends the connection with SETTINGS_TIMEOUT (RFC 9113 section 6.5.3) when the peer's preface (section 3.4: its SETTINGS,
     * the first frame it sends) has not arrived by [deadline] (nanoseconds, the clock of [onTimeout]). A client sends its
     * requests without waiting for the server's preface (section 3.4: "clients are permitted to send additional frames to
     * the server immediately after sending the client connection preface"), so this bounds how long they wait for a server
     * that never answers. Our SETTINGS are not acknowledged before the peer's preface either.
     */
    fun expectPeerPrefaceBy(deadline: Long) {
        if (!peerSettingsSeen) peerPrefaceDeadline = deadline
    }

    /**
     * When our SETTINGS must have been acknowledged (section 6.5.3), or null. With a deadline for the peer's preface
     * ([expectPeerPrefaceBy]) the acknowledgement is not awaited before that preface (the peer acknowledges only after
     * it, section 3.4) and its time counts from the preface on: a peer that never answers is the preface deadline's, not
     * this one's.
     */
    private fun settingsAckDeadline(): Long? {
        if (settingsUnacked <= 0 || settingsSentAt < 0) return null
        val timeout = settings.settingsAckTimeout.inWholeNanoseconds
        if (peerPrefaceDeadline < 0) return settingsSentAt + timeout
        if (!peerSettingsSeen) return null
        return maxOf(settingsSentAt, peerPrefaceAt) + timeout
    }

    /** The next deadline (nanoseconds) for [onTimeout], or null. */
    fun nextTimeout(): Long? {
        if (closed) return null
        var t: Long? = null

        fun at(v: Long) {
            t = t?.let { minOf(it, v) } ?: v
        }
        settingsAckDeadline()?.let { at(it) }
        if (!peerSettingsSeen && peerPrefaceDeadline >= 0) at(peerPrefaceDeadline)
        if (inBlock) at(blockStartedAt + settings.maxHeaderBlockTime.inWholeNanoseconds)
        if (gracefulPing >= 0) at(gracefulDeadline)
        return t
    }

    fun onTimeout(now: Long) {
        lastNow = now
        if (closed) return
        if (!peerSettingsSeen && peerPrefaceDeadline >= 0 && now >= peerPrefaceDeadline) {
            peerPrefaceMissed = true
            return connectionError(Http2ErrorCode.SETTINGS_TIMEOUT, "no connection preface (SETTINGS) from the peer in time")
        }
        if (settingsAckDeadline()?.let { now >= it } == true) {
            return connectionError(Http2ErrorCode.SETTINGS_TIMEOUT, "SETTINGS not acknowledged within ${settings.settingsAckTimeout}")
        }
        if (inBlock && now - blockStartedAt >= settings.maxHeaderBlockTime.inWholeNanoseconds) {
            slowFieldBlock = true
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

    /** Control frames waiting for [poll], held SETTINGS acknowledgements included (bounded by `maxControlFramesQueued`). */
    internal val controlQueued: Int get() = control.size + pingAnswers.size + heldAcks

    // ---------------------------------------------------------------------------------------------------------------
    // internals

    internal fun emit(e: H2Event) {
        if (!closedReported) events.addLast(e) // nothing after Closed
    }

    internal fun canSend(s: H2Stream): Boolean = s.state == StreamState.OPEN || s.state == StreamState.HALF_CLOSED_REMOTE

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
            dataLeft(s)
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

    internal fun queueControl(frame: ByteArray) {
        if (closed) return
        // CVE-2019-9512/9515: a peer that makes us answer without reading our answers must not grow this queue; called from the
        // driver's actions too, so this ends the connection instead of throwing
        if (controlQueued >= settings.maxControlFramesQueued) {
            return connectionError(Http2ErrorCode.ENHANCE_YOUR_CALM, "more than ${settings.maxControlFramesQueued} control frames queued")
        }
        control.addLast(frame)
    }

    /**
     * Acknowledges the peer's SETTINGS (section 6.5.3): the acknowledgement is queued at once, in order with the earlier
     * ones. When the SETTINGS shrank SETTINGS_INITIAL_WINDOW_SIZE ([windowShrank]), it is queued after the DATA frames
     * [sendData] already took from the larger window (each at most 16 KiB, at most one per stream, needing no window to be
     * written): the peer counts what arrives after the acknowledgement against the smaller window (sections 6.5.3, 6.9.2),
     * and such a frame written after it would overrun that window (FLOW_CONTROL_ERROR). Nothing waits for the peer. Held
     * acknowledgements count toward `maxControlFramesQueued` (CVE-2019-9515), so a peer that stops reading cannot pile
     * them up.
     */
    internal fun queueSettingsAck(windowShrank: Boolean) {
        if (closed) return
        val behind = LinkedHashSet<H2Stream>()
        if (windowShrank) {
            for (s in streams.values) if (s.out.any { it is OutItem.Data && it.length > 0 }) behind += s
        }
        if (behind.isEmpty() && heldSettingsAcks.isEmpty()) return queueControl(FrameEncoder.settingsAck())
        if (controlQueued >= settings.maxControlFramesQueued) {
            return connectionError(Http2ErrorCode.ENHANCE_YOUR_CALM, "more than ${settings.maxControlFramesQueued} control frames queued")
        }
        heldAcks++
        if (behind.isEmpty()) heldSettingsAcks.last().followers++ else heldSettingsAcks.addLast(HeldAck(behind))
    }

    /** The connection ended with an error: only its GOAWAY goes out, no acknowledgement. */
    internal fun dropHeldSettingsAcks() {
        heldSettingsAcks.clear()
        heldAcks = 0
    }

    /** The queued DATA of [s] was written or dropped: acknowledgements held behind it may go. */
    private fun dataLeft(s: H2Stream) {
        if (heldSettingsAcks.isEmpty()) return
        for (h in heldSettingsAcks) h.behind.remove(s)
        while (heldSettingsAcks.firstOrNull()?.behind?.isEmpty() == true) {
            val h = heldSettingsAcks.removeFirst()
            repeat(1 + h.followers) {
                heldAcks-- // first, so moving it into the control queue keeps the count within the bound
                queueControl(FrameEncoder.settingsAck())
            }
        }
    }

    /** Credit [n] bytes of [s] back to the peer: the connection at once when due, the stream as one coalesced WINDOW_UPDATE. */
    internal fun credit(
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

    internal fun creditConnection(
        n: Long,
        now: Long,
    ) {
        val inc = connRecv.onConsumed(n, now, rttNanos)
        if (inc > 0) queueControl(FrameEncoder.windowUpdate(0, inc))
    }

    /** Content of [s] that will never be read goes back to the connection window. */
    internal fun dropUnconsumed(s: H2Stream) {
        val n = s.unconsumed
        s.unconsumed = 0
        if (n > 0 && !closed) creditConnection(n, lastNow)
    }

    /** Drops what [s] still had to send; DATA that was never written gives its window back to the connection. */
    internal fun dropQueued(s: H2Stream) {
        var refund = 0L
        for (item in s.out) if (item is OutItem.Data) refund += item.length
        s.out.clear()
        s.dataQueued = false
        dataLeft(s)
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
    internal fun tryWake(s: H2Stream) {
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

    internal fun report(
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
