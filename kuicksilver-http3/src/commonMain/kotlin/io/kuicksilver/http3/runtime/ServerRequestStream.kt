// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    io.kuicksilver.annotations.InternalKuicksilverApi::class,
    io.kuicksilver.annotations.ExperimentalKuicksilverApi::class,
    kotlin.concurrent.atomics.ExperimentalAtomicApi::class,
)

package io.kuicksilver.http3.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readAvailable
import io.kuicksilver.http3.Http3EarlyDataPolicy
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3ResponseWriter
import io.kuicksilver.http3.Http3ServerRequest
import io.kuicksilver.http3.Http3Stream
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.H3ProtocolError
import io.kuicksilver.http3.message.CapsuleRules
import io.kuicksilver.http3.message.FieldValidator
import io.kuicksilver.http3.message.MalformedMessage
import io.kuicksilver.http3.message.PriorityField
import io.kuicksilver.http3.message.PseudoHeaders
import io.kuicksilver.http3.message.priorityFieldValue
import io.kuicksilver.http3.webtransport.WtFlow
import io.kuicksilver.http3.webtransport.WtProtocols
import io.kuicksilver.http3.webtransport.WtSessionImpl
import io.kuicksilver.http3.webtransport.WtTokens
import io.kuicksilver.http3.webtransport.wtServerVersion
import io.kuicksilver.native.LeakRegistry
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.activePath
import io.kuicksilver.quic.awaitSendStopped
import io.kuicksilver.quic.markTunnel
import io.kuicksilver.quic.ownAddresses
import io.kuicksilver.quic.readAhead
import io.kuicksilver.quic.releaseStreamCredit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetch

/**
 * A request stream accepted by a server: HEADERS first, then the body pump (RFC 9114 section 4.1). The stream keeps its
 * MAX_STREAMS credit while it is a request the application holds (see [ServerRequestImpl.applicationDone]); one that
 * never reached the application (refused, aborted, reset before its HEADERS, a WebTransport stream) gives it back here.
 */
internal suspend fun handleRequestStream(
    session: H3Session,
    st: QuicStream,
) {
    var delivered = false
    try {
        readRequestStream(session, st) { delivered = true }
    } finally {
        if (!delivered) st.releaseStreamCredit()
    }
}

private suspend fun readRequestStream(
    session: H3Session,
    st: QuicStream,
    onDelivered: () -> Unit,
) = with(session) {
    // WebTransport: a bidirectional stream that starts with WT_STREAM is no request (draft-ietf-webtrans-http3-16 section
    // 4.3). Read before anything a request does: such a stream does not count as one, and our GOAWAY does not refuse it
    // nothing of the request head is taken from the stream's flow-control window before the connection's header budget
    // granted it (RFC 9114 section 10.5); RFC 9204 section 2.2.1: with blocked sections possible, nor before it may decode
    st.readAhead = RequestFrames.FRAME_HEADER_AHEAD
    // the stream's head (a request's HEADERS, decoded; a WebTransport stream's signal and Session ID) must be read within
    // maxHeaderBlockTime of its first byte, or the stream is rejected: a stream that never completes it would otherwise hold
    // its reader, its budget and its stream slot as long as the client keeps the connection alive (RFC 9000 section 21.6,
    // Slowloris; RFC 9114 section 10.5). Armed before the first read, which with WebTransport is the frame type itself.
    val reader = currentCoroutineContext()[Job]!!
    val head = HeadState()
    val headDeadline =
        scope.launch {
            delay(settings.maxHeaderBlockTime)
            if (!head.settled) {
                head.settled = true
                headDeadlinesPassedForTest++
                rejectUnfinishedHead(st, reader, head.rejectCode)
            }
        }
    headDeadlinesArmedForTest.incrementAndFetch()
    headDeadline.invokeOnCompletion { headDeadlinesArmedForTest.decrementAndFetch() }

    /** The head was read in time: the deadline stands down (on the dispatcher, so it cannot fire in between). */
    fun headSettled() {
        head.settled = true
        headDeadline.cancel()
    }
    try {
        handleArmedRequestStream(st, reader, head, ::headSettled, onDelivered)
    } finally {
        headDeadline.cancel()
    }
}

/** Whether a server stream's head was read (or given up), and the code its deadline rejects it with. */
private class HeadState {
    var settled = false

    /**
     * H3_REQUEST_REJECTED while the stream may be a request (RFC 9114 section 4.1.1); once it is a WebTransport stream,
     * WT_BUFFERED_STREAM_REJECTED: it reached no session (draft-ietf-webtrans-http3-16 section 4.6).
     */
    var rejectCode = Http3ErrorCode.REQUEST_REJECTED
}

private suspend fun H3Session.handleArmedRequestStream(
    st: QuicStream,
    reader: Job,
    head: HeadState,
    headSettled: () -> Unit,
    onDelivered: () -> Unit,
) {
    val firstSized =
        if (settings.webTransport) {
            try {
                st.input.readVarIntSizedOrNull()
            } catch (_: IncompleteFrame) {
                headSettled()
                truncated(st, null, null)
                return
            } catch (e: CancellationException) {
                throw e
            } catch (_: Throwable) {
                null // a reset or a lost connection: the request path below meets it again and handles it as before
            }
        } else {
            null
        }
    val firstType = firstSized?.first
    if (firstType == FrameType.WT_STREAM) {
        bidiSettled(st.id) // a WebTransport stream, not a request: never a session
        head.rejectCode = Http3ErrorCode.WT_BUFFERED_STREAM_REJECTED
        st.readAhead = Long.MAX_VALUE // its data carries no field section: read ahead as any stream
        wt.onBidi(st, firstSized.second, headSettled)
        return
    }
    if (st.id > maxRequestId) maxRequestId = st.id
    goAwaySentId?.let {
        if (st.id >= it || headerDeadlinePassed) {
            headSettled()
            abort(st, Http3ErrorCode.REQUEST_REJECTED)
            return
        }
    }
    // in flight from its first frame type (its first byte; with WebTransport, once that type was read above), not from
    // the parsed HEADERS: a request below the GOAWAY id whose HEADERS are still arriving must keep the idle close away
    // (RFC 9114 section 5.2), until the header deadline after GOAWAY
    requestStarted()
    pendingHeaders[st.id] = st to reader
    var handedOff = false
    try {
        val frames =
            RequestFrames(
                st.input,
                isServerSide = true,
                maxHeadersFrame = maxHeadersFrame,
                onUseless = { glitch(it) },
                onBuffered = { bufferedHeaderBytes += it },
                firstType = firstType,
                webTransport = settings.webTransport,
                // RFC 9204 section 2.2.1: a blocked section stays unread, in the stream's flow-control window
                beforeFieldSection = { ric -> qpack.awaitInserts(st.id, ric) { insertsWatch(st) } },
                limitReadAhead = { st.readAhead = it },
                budget = headerBudget,
                budgetWatch = { budgetWatch(st) },
                streamId = st.id,
                qlog = qlog,
            )
        beforeRequestHeadersForTest?.invoke(st)
        val first =
            try {
                frames.next()
            } catch (
                e: IncompleteFrame,
            ) {
                truncated(st, null, null)
                return
            } catch (e: QuicException.StreamError) {
                // reset before its HEADERS were read: no request, but the peer's encoder may count a section that was lost
                // or dropped with the reset (RFC 9204 section 4.4.2)
                runCatching { cancelSections(st) }
                // no request will be answered on it: our direction ends too, or the stream (and its credit) stays open
                // until the connection ends when the client did not stop it (RFC 9114 section 4.1.1)
                runCatching { st.reset(Http3ErrorCode.REQUEST_REJECTED) }
                countClientReset(e)
                return
            } catch (e: StreamAbandoned) {
                runCatching { st.reset(Http3ErrorCode.REQUEST_REJECTED) }
                countClientReset(st.input.closedCause)
                return // reset while its HEADERS waited for inserts: the Stream Cancellation went out
            }
        val block =
            when (first) {
                RequestFrame.End -> {
                    headSettled() // answered: the deadline must not reset the stream with another code meanwhile
                    abort(st, Http3ErrorCode.REQUEST_INCOMPLETE)
                    return
                }

                is RequestFrame.Data -> {
                    throw H3ProtocolError(Http3ErrorCode.FRAME_UNEXPECTED, "DATA before HEADERS on stream ${st.id}")
                }

                is RequestFrame.HeadersTooLarge -> {
                    headSettled()
                    reject431(st)
                    return
                }

                is RequestFrame.Headers -> {
                    first.block
                }
            }
        val fields =
            try {
                decodeSection(st, block)
            } catch (
                e: StreamFailure,
            ) {
                headSettled()
                reject431(st, e.code)
                return
            } catch (e: StreamAbandoned) {
                return
            }
        val parsed =
            try {
                PseudoHeaders.parseRequest(fields, settings.enableConnectProtocol).let { r ->
                    PseudoHeaders.Request(r.method, r.scheme, r.authority, r.path, r.protocol, r.regular.receivedNeverIndexed(fields))
                }
            } catch (
                e: MalformedMessage,
            ) {
                headSettled()
                abort(st, Http3ErrorCode.MESSAGE_ERROR)
                // a reset the client made us send (RFC 9114 section 10.5; MadeYouReset, CVE-2025-8671), as on HTTP/2
                glitch("a malformed request")
                return
            }
        pendingHeaders.remove(st.id)
        headSettled()
        // the head is read: trailers each have the deadline of a field section
        frames.sectionDeadline = settings.maxHeaderBlockTime
        bidiSettled(st.id)
        // datagrams kept while the HEADERS were on the way belong to a request without datagram semantics: RFC 9297 section
        // 2 has it aborted with H3_DATAGRAM_ERROR (an Extended CONNECT with them takes them when its channel registers)
        if (!hasDatagramSemantics(parsed.method, parsed.protocol) && datagrams.dropPending(st.id)) {
            abort(st, Http3ErrorCode.DATAGRAM_ERROR)
            return
        }
        if (settings.webTransport && parsed.method == "CONNECT" && WtTokens.isWebTransport(parsed.protocol)) {
            val draft02 =
                parsed.protocol.equals(WtTokens.LEGACY, ignoreCase = true) && parsed.regular[WtTokens.DRAFT02_REQUEST_FIELD] == "1"
            // refused before the application: section 5.1 without flow control, section 5.2 (draft-14 section 5.2) over the
            // limit; the connection stays (draft-14: "The server MUST NOT close the connection if the client opens sessions
            // exceeding this limit")
            // section 5.2: faster than the rate, refused unprocessed; a peer that keeps trying spends glitch tokens too
            if (!wtSessionRate.spend(glitchClock())) {
                abort(st, Http3ErrorCode.REQUEST_REJECTED)
                wt.unregister(st.id)
                glitch("WebTransport sessions above the rate")
                return
            }
            if (!wtAdmits(draft02)) {
                abort(st, Http3ErrorCode.REQUEST_REJECTED)
                wt.unregister(st.id)
                return
            }
            wtSessionAdmitted(st.id, draft02)
        }
        val req = ServerRequestImpl(this, st, parsed)
        // RFC 8470: a request that came in 0-RTT and is not replayable runs only on a completed handshake (ADR-0015)
        if (st.receivedEarly && !quic.isHandshakeComplete) {
            val policy = settings.earlyData
            if (policy.replayable(req)) {
                req.receivedEarly = true
            } else if (policy is Http3EarlyDataPolicy.Reject425) {
                reject425(st)
                handedOff = true
                req.done() // the request registered itself (its datagrams too): never handed over, it ends here
                return
            } else {
                earlyHeldForHandshake.incrementAndFetch()
                try {
                    quic.awaitHandshake()
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Throwable) {
                    // the handshake failed: a replayed request never runs
                    handedOff = true
                    req.done()
                    return
                }
            }
        }
        handedOff = true // from here ServerRequestImpl.done() ends the request
        if (!requests.offer(req)) {
            abort(st, Http3ErrorCode.REQUEST_REJECTED)
            req.done()
            return
        }
        onDelivered() // the application holds it now: it gives the stream's credit back
        // a stop of the response before it is complete abandons the request as a reset does, and spends the same token. The
        // watch ends with the complete response ([ServerRequestImpl.responseComplete]), after which a stop costs nothing: left
        // waiting for the stream's end, its frame held the request (its body channel, headers, deferreds) for as long as the
        // stream lived, an idle connection's last request included
        if (!req.respondedInFull) {
            val watch =
                scope.launch {
                    val code =
                        try {
                            st.awaitSendStopped()
                        } catch (_: QuicException) {
                            null
                        }
                    if (code != null) {
                        try {
                            countClientStop(req)
                        } catch (e: H3ProtocolError) {
                            // not cancellable: the complete response cancels this watch, and once fail completed `closed` it
                            // must still send the CONNECTION_CLOSE (a cancel inside quic.close dropped it)
                            withContext(NonCancellable) { fail(e.code, e.message ?: "") }
                        }
                    }
                }
            stopWatchStartedForTest?.invoke(req, watch)
            req.stopWatch = watch
            // the response may complete on the writer's thread meanwhile: it sets respondedInFull before it reads stopWatch, this
            // sets stopWatch before it reads respondedInFull, so one of the two cancels the watch
            if (req.respondedInFull) {
                watch.cancel()
                req.stopWatch = null
            }
        }
        // a CONNECT has no content: what follows its header section is the tunnel, which its content-length does not
        // describe (RFC 9110 section 9.3.6, RFC 9114 section 4.1.2)
        val bodyLimit = if (parsed.method == "CONNECT") null else contentLength(parsed.regular)
        pumpBody(
            st,
            frames,
            req.bodyChannel,
            req.trailersDeferred,
            bodyLimit,
            tunnel = { req.tunnel },
            responseComplete = { req.respondedInFull },
            abandoned = req,
        ) { f ->
            // the 431 claims the response on this dispatcher first: an application's respond() meanwhile finds it taken
            if (f.error is Http3Exception.FieldSectionTooLarge && req.claimResponseFor431()) reject431(st, f.code) else abort(st, f.code)
            req.done()
        }
        // the client reset its request (other than with H3_NO_ERROR after a complete early response): it abandoned it
        (st.input.closedCause?.let { H3Session.transportCause(it) } as? QuicException.StreamError.Reset)?.let {
            if (it.initiator == Initiator.Peer && it.code != Http3ErrorCode.NO_ERROR) req.peerAbandoned.complete(Unit)
        }
        req.receiveEnded()
    } finally {
        pendingHeaders.remove(st.id)
        if (!handedOff) {
            requestDone()
            if (st.id in wtSessions) wtSessionEnded(st.id, null)
        }
    }
}

/** A WebTransport CONNECT is over (refused, ended, or never handed over): the slot is free and its streams are rejected. */
internal fun H3Session.wtSessionEnded(
    streamId: Long,
    session: WtSessionImpl?,
) {
    wtSessionRemoved(streamId)
    session?.ended() ?: wt.unregister(streamId)
}

/**
 * Server: whether another WebTransport CONNECT ([draft02]: a draft-02 request) may join the sessions already on this
 * connection. The first always may (its acceptance checks the client's SETTINGS). Another one needs flow control on for
 * it and for every session already there, which the client's SETTINGS tell, so they are awaited first (bounded by
 * [H3Session.wtDeadline]; draft-16 section 7.1: "the server MUST NOT process any incoming WebTransport requests until the
 * client's SETTINGS have been received"); then: section 5.1, "A server that receives more than one session on an
 * underlying transport connection when flow control is not enabled MUST reset the excessive CONNECT streams with a
 * H3_REQUEST_REJECTED status", and section 5.2, "Servers SHOULD limit the rate of incoming WebTransport sessions",
 * here at most [io.kuicksilver.http3.Http3Settings.webTransportMaxSessions] at once (draft-14 section 5.2: "it MUST reset
 * all of the CONNECT streams it is not willing to process with the H3_REQUEST_REJECTED status"). Session dispatcher only;
 * the caller records an admitted session before it suspends again.
 */
internal suspend fun H3Session.wtAdmits(draft02: Boolean): Boolean {
    if (wtSessions.isEmpty()) return true
    withinWtDeadline { awaitPeerSettings() } ?: return false
    if (wtSessions.isEmpty()) return true // the others ended meanwhile

    fun flowControlled(d02: Boolean): Boolean = wtServerVersion(this, d02).first?.let { WtFlow.enabled(this, it) } == true
    return wtSessions.size < settings.webTransportMaxSessions &&
        flowControlled(draft02) &&
        wtSessions.values.all { flowControlled(it) }
}

/**
 * 425 Too Early for a request that came in 0-RTT and the policy does not run early (RFC 8470 section 5.2): the request is
 * not read (STOP_SENDING H3_NO_ERROR) and the client may send it again after the handshake.
 */
private suspend fun H3Session.reject425(st: QuicStream) {
    runCatching {
        st.stopSending(Http3ErrorCode.NO_ERROR)
        writeHeadersFrame(st, PseudoHeaders.buildResponse(425, Http3Headers.Empty))
        st.output.flushAndClose()
    }
    runCatching { cancelSections(st) }
}

/**
 * 431 and STOP_SENDING (RFC 9114 section 4.2.2; quic-go CVE-2025-64702): H3_EXCESSIVE_LOAD, or [stopCode]
 * QPACK_DECOMPRESSION_FAILED for a value longer than we decode, the stream error RFC 9204 section 7.4 requires.
 */
private suspend fun H3Session.reject431(
    st: QuicStream,
    stopCode: Long = Http3ErrorCode.EXCESSIVE_LOAD,
) {
    runCatching {
        st.stopSending(stopCode)
        writeHeadersFrame(st, PseudoHeaders.buildResponse(431, Http3Headers.Empty))
        afterReject431HeadersForTest?.invoke(st)
        st.output.flushAndClose()
    }
    runCatching { cancelSections(st) }
}

internal class ServerRequestImpl(
    private val session: H3Session,
    private val st: QuicStream,
    parsed: PseudoHeaders.Request,
) : Http3ServerRequest {
    override val streamId: Long get() = st.id
    override var receivedEarly: Boolean = false
    override val method: String = parsed.method
    override val scheme: String? = parsed.scheme
    override val authority: String? = parsed.authority
    override val path: String? = parsed.path
    override val protocol: String? = parsed.protocol
    override val headers: Http3Headers = parsed.regular
    override val isWebTransport: Boolean =
        session.settings.webTransport && method == "CONNECT" && WtTokens.isWebTransport(protocol)
    override val availableProtocols: List<String> =
        if (isWebTransport) {
            headers.getAll(WtProtocols.AVAILABLE_FIELD).takeIf { it.isNotEmpty() }?.let { WtProtocols.parseList(it.joinToString(", ")) }
                ?: emptyList()
        } else {
            emptyList()
        }

    /** The session [acceptWebTransport] made; it ends with the exchange. */
    private var wtSession: WtSessionImpl? = null
    val bodyChannel = ByteChannel()
    override val body: ByteReadChannel =
        BodyReadChannel(
            bodyChannel,
            onCancel = {
                // the application wants no more of the request: stop the client now (RFC 9114 section 4.1), not at its next DATA
                if (!receiveEnded) runCatching { st.stopSending(Http3ErrorCode.NO_ERROR) }
            },
            onFailureSeen = { applicationDone() }, // the application read that the request failed (a reset, an error)
        )
    val trailersDeferred = CompletableDeferred<Http3Headers?>()
    override val trailers: Deferred<Http3Headers?> get() = trailersDeferred

    /** The client's signal: an early PRIORITY_UPDATE beats the header (RFC 9218 section 7.1). */
    private val earlyPriority = session.takeEarlyPriority(st.id)

    private val priorityField = parsed.regular.priorityFieldValue()

    private val priorityFlow = MutableStateFlow(earlyPriority ?: PriorityField.parse(priorityField))
    private var serverPriority: StreamPriority? = null
    internal val stream: QuicStream get() = st
    override val priority: StateFlow<StreamPriority> get() = priorityFlow

    /** The client's address now: the live active path, read at request time; the session's last seen one only when none is left. */
    override val remoteAddress: InetSocketAddress get() = session.quic.activePath?.remoteAddress ?: session.currentPath.remoteAddress

    /** Set on the session's dispatcher ([respond], [claimResponseFor431]); read elsewhere only as a hint. */
    @Volatile var responseStarted: Boolean = false
        private set
    private var finished = false

    /** The runtime answered 431 itself (request trailers above our limit, RFC 9114 section 4.2.2). */
    private var answered431 = false

    /**
     * The runtime's 431 takes the response unless the application's started first. Session dispatcher only, as is the
     * application's own claim in [respond]: two final responses never reach the stream.
     */
    fun claimResponseFor431(): Boolean {
        if (responseStarted || finished) return false
        answered431 = true
        responseStarted = true // after: whoever sees it started sees why
        return true
    }

    /** The request's own fault ([answered431]): an I/O failure of this exchange, as its trailers are to the application. */
    private fun checkNotAnswered431() {
        if (answered431) throw Http3Exception.FieldSectionTooLarge(st.id, session.settings.maxFieldSectionSize)
    }

    /** Set when the request ended with its connection ([connectionEnded]): an answer then fails with the connection's error. */
    @Volatile private var endedWithConnection = false

    /**
     * The connection is gone and the request was still registered (its handler never answered, or its end was lost with
     * the session's coroutines): it ends here. A handler that still runs is not stopped: its answer fails with the
     * connection's error, and the body and trailers it reads are untouched ([done] does not close them). Session
     * dispatcher only.
     */
    fun connectionEnded() {
        endedWithConnection = true
        applicationDone() // for symmetry with every other end: the stream credit of a connection that is gone means nothing
        done()
    }

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class) // closed is complete once the request ended with the connection
    private fun checkConnectionNotEnded() {
        if (endedWithConnection) throw session.closed.getCompleted()
    }

    /** Session dispatcher only: the final response can still be sent. */
    private fun checkResponseOpen() {
        checkConnectionNotEnded()
        checkNotAnswered431()
        check(!responseStarted) { "response already started" }
        check(!finished) { "request is finished" }
    }

    /** Set by an engine that reports its handler's end ([handlerEnded]): only that gives the stream's credit back then. */
    @Volatile var engineManaged = false

    /** The client's abandonment of this request (its STOP_SENDING or reset) was counted ([H3Session.countClientStop]). Session dispatcher only. */
    var abandonmentCounted = false

    /**
     * The watch for the client's STOP_SENDING on the response ([H3Session.countClientStop]): cancelled once the response is
     * complete, when a stop no longer abandons anything.
     */
    @Volatile var stopWatch: Job? = null

    /**
     * The application is done with this request: its response ended (complete or abandoned), it reset the request, or a
     * call to answer it failed. The stream's MAX_STREAMS credit may go back to the client once the stream is finished at
     * the transport too; until then a request the client reset still counts, so a client cannot run more handlers than it
     * may open streams (RFC 9114 section 10.5; Rapid Reset, CVE-2023-44487). An engine that tracks its handlers
     * ([engineManaged]) gives it back at [handlerEnded] instead. Idempotent, any thread.
     */
    fun applicationDone() {
        if (!engineManaged) st.releaseStreamCredit()
    }

    /** Completed when the client abandoned the request: it reset the request, or stopped our response (see [awaitAbandoned]). */
    val peerAbandoned = CompletableDeferred<Unit>()

    /**
     * Suspends until the client abandoned the request: STOP_SENDING on the response (it will not read it), or a reset of
     * the request other than with H3_NO_ERROR (RFC 9114 section 4.1.1: "A client can cancel requests by resetting and
     * aborting the stream with H3_REQUEST_CANCELLED"), or the connection is gone. An engine cancels the request's
     * handler then, so a cancelled long poll gives its stream back at once instead of when it would have answered. Never
     * returns for a request kept on a live connection, nor once the response was sent in full (a handler that answered
     * and goes on with other work is not cancelled by a late STOP_SENDING or the connection's end).
     */
    suspend fun awaitAbandoned() {
        abandonedBeforeTheFullResponse()
        // a response already sent in full: the handler has nothing left the client could abandon
        if (respondedInFull) kotlinx.coroutines.awaitCancellation()
    }

    private suspend fun abandonedBeforeTheFullResponse() {
        if (respondedInFull) kotlinx.coroutines.awaitCancellation()
        kotlinx.coroutines.coroutineScope {
            // a STOP_SENDING abandons the request; a stream that ended both ways without one (null) does not, and the end of the
            // connection (which awaitSendStopped throws) is the watch below
            val stopped =
                launch {
                    val code =
                        try {
                            st.awaitSendStopped()
                        } catch (_: io.kuicksilver.quic.QuicException) {
                            null
                        }
                    if (code != null) peerAbandoned.complete(Unit)
                }
            val lost =
                launch {
                    session.quic.closed
                        .await()
                        .also { peerAbandoned.complete(Unit) }
                }
            peerAbandoned.await()
            stopped.cancel()
            lost.cancel()
        }
    }

    /** The engine's handler of this request returned: the stream's credit may go back to the client. Idempotent, any thread. */
    fun handlerEnded() {
        st.releaseStreamCredit()
    }

    /** The exchange is over (response sent, both tunnel directions ended, or stream aborted): counts once towards the GOAWAY idle close. */
    fun done() {
        // a tunnel's exchange ends with both its directions: the application's stream is over (RFC 9114 section 4.4)
        if (tunnel) applicationDone()
        if (!finished) {
            finished = true
            session.activeServerRequests.remove(st.id)
            LeakRegistry.close(leakId)
            session.datagrams.unregister(st.id)
            if (isWebTransport) session.wtSessionEnded(st.id, wtSession)
            session.responseHandedOver(st)
            session.requestDone()
        }
    }

    /**
     * [done] after a complete response: a body the application never finished reading is dropped and the peer is stopped
     * with H3_NO_ERROR (RFC 9114 section 4.1). The STOP_SENDING goes out here, not from the pump: a CancellationException
     * on the channel reached the pump as its own cancellation and the peer was never stopped.
     */

    /** The whole response was handed to the transport (FIN sent): no abandonment cancels the handler now, and an H3_NO_ERROR reset is free. */
    @Volatile var respondedInFull = false
        private set

    fun responseComplete() {
        if (!tunnel) {
            respondedInFull = true
            stopWatch?.cancel() // nothing left to abandon: a stop from now on is free ([H3Session.countClientStop])
            stopWatch = null
        }
        if (tunnel) {
            sendEnded = true
            if (receiveEnded) done()
            return
        } // a half-close: the peer's direction stays open (RFC 9114 section 4.4)
        done()
        if (!bodyChannel.isClosedForRead) {
            // the pump has not seen the request's end
            if (!bodyChannel.isClosedForWrite) runCatching { st.stopSending(Http3ErrorCode.NO_ERROR) }
            bodyChannel.cancel(kotlinx.io.IOException("response complete: the rest of the request body is not read"))
        }
    }

    private val datagramChannel = if (hasDatagramSemantics(method, protocol)) session.datagrams.register(st.id) else null

    /** This host's addresses the request's connection shows ([io.kuicksilver.quic.ownAddresses]): a proxy refuses them as targets. */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    internal val connectionOwnAddresses: List<io.ktor.network.sockets.InetSocketAddress>
        get() = session.quic.ownAddresses

    /** Tests: datagrams for this request wait to be read (they arrived before its CONNECT was answered). */
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    internal val datagramsWaitingForTest: Boolean get() = datagramChannel?.isEmpty == false

    /** A CONNECT answered with 2xx: each direction ends on its own, the exchange is over when both did; only DATA may arrive (RFC 9114 section 4.4). */
    var tunnel = false
        private set
    private var sendEnded = false
    private var receiveEnded = false

    /** The request's direction ended (FIN, reset or a stream error); ends a tunnel whose response side already ended. */
    fun receiveEnded() {
        receiveEnded = true
        session.datagrams.unregister(st.id) // datagrams after the receive side closed are dropped (RFC 9297 section 2.1)
        if (tunnel && sendEnded) done()
    }

    init {
        // the client's signal, else RFC 9218's defaults (section 4), a CONNECT too
        st.priority = priorityFlow.value
        // whatever its priority, a tunnel gets "some amount of bandwidths" behind more urgent streams (section 10.1)
        if (method == "CONNECT") st.markTunnel()
        session.activeServerRequests[st.id] = this
    }

    /** The leak sentinel's record of this request while [H3Session.activeServerRequests] holds it (0 in production). */
    private val leakId = LeakRegistry.open("h3.serverRequest")

    override suspend fun acceptConnect(headers: Http3Headers): Http3Stream {
        check(method == "CONNECT") { "acceptConnect() needs a CONNECT request" }
        // RFC 9297 section 3.2: a request that enables the Capsule Protocol and carries content-length, content-type or
        // transfer-encoding is malformed ("A receiver that observes a violation of these requirements MUST treat the HTTP
        // message as malformed"): found here, before any 2xx, not when the application first speaks capsules
        if (CapsuleRules.isEnabled(this.headers)) CapsuleRules.violation(this.headers, null)?.let { refuseMalformed(it) }
        val writer = respond(200, headers)
        return Http3StreamImpl(
            session,
            st,
            body,
            writer,
            datagramChannel ?: Channel<ByteArray>(0).also { it.close() },
            this.headers,
            status = 200,
            localHeaders = headers,
            isClient = false,
            onReset = { session.afterEnd.launch { done() } }, // as in reset(): also once the connection is gone
            datagramsAllowed = datagramChannel != null,
        )
    }

    /** `acceptWebTransport` (draft-ietf-webtrans-http3-16 sections 3.2, 3.3, 7.1). */
    suspend fun acceptWebTransport(
        headers: Http3Headers,
        protocol: String?,
    ): WebTransportSession {
        check(!responseStarted) { "response already started" }
        require(protocol == null || protocol in availableProtocols) {
            "WebTransport protocol '$protocol' is not one the client offered: $availableProtocols"
        }
        val ps = session.withinWtDeadline { session.awaitPeerSettings() }
        // section 3.1: "If the server receives SETTINGS that do not have correct values for every required setting, or
        // transport parameters that do not have correct values for every required transport parameter, the server MUST treat
        // all established and newly incoming WebTransport sessions as malformed"; a session is established only here, once
        // the client's SETTINGS arrived, so none was before. The client's own WebTransport setting is required too: "For
        // draft versions of WebTransport only, clients MUST also send SETTINGS_WT_ENABLED with the draft-specific codepoint"
        // (draft-14: SETTINGS_WT_MAX_SESSIONS above 0, draft-02: SETTINGS_ENABLE_WEBTRANSPORT=1, as Chrome and Firefox send)
        // A client that announces a newer draft without its transport parameters but also draft-02 is served only when this
        // CONNECT is a draft-02 request ([wtServerVersion]).
        val draft02Request =
            this@ServerRequestImpl.protocol.equals(WtTokens.LEGACY, ignoreCase = true) &&
                this.headers[WtTokens.DRAFT02_REQUEST_FIELD] == "1"
        val (version, refusal) = wtServerVersion(session, draft02Request)
        val missing =
            when {
                ps == null -> {
                    "no SETTINGS from the client within ${session.wtDeadline}"
                }

                session.highestCommonWtVersion() == null -> {
                    "the client sent no WebTransport setting (SETTINGS_WT_ENABLED, draft-14 SETTINGS_WT_MAX_SESSIONS or " +
                        "draft-02 SETTINGS_ENABLE_WEBTRANSPORT), which WebTransport needs"
                }

                !ps.h3Datagram -> {
                    "the client did not send SETTINGS_H3_DATAGRAM=1, which WebTransport needs"
                }

                else -> {
                    refusal
                }
            }
        if (missing != null) {
            // a malformed request (RFC 9114 section 4.1.2: a stream error H3_MESSAGE_ERROR), answered with 400 first so the
            // client learns why
            runCatching { st.stopSending(Http3ErrorCode.MESSAGE_ERROR) }
            runCatching { respond(400).finish() }
            throw Http3Exception.Settings(missing)
        }
        // the session speaks capsules on this stream: a request that rules them out is malformed (RFC 9297 section 3.2),
        // answered with 400 before any 200
        CapsuleRules.violation(this.headers, null)?.let { refuseMalformed(it) }
        val fields =
            buildList {
                addAll(headers.fields)
                if (protocol != null) add(WtProtocols.SELECTED_FIELD to WtProtocols.quote(protocol))
                // Chrome's draft-02 client refuses a 2xx without it
                if (this@ServerRequestImpl.headers[WtTokens.DRAFT02_REQUEST_FIELD] != null) {
                    add(WtTokens.DRAFT02_RESPONSE_FIELD to WtTokens.DRAFT02_RESPONSE_VALUE)
                }
            }
        val stream = acceptConnect(Http3Headers(fields))
        val s = WtSessionImpl(session, stream, this.headers, protocol, version!!)
        withContext(session.dispatcher) {
            if (finished || session.endBeforeStartForTest) {
                s.ended()
            } else {
                wtSession = s
                session.wt.register(st.id, s)
                s.start()
            }
        }
        return s
    }

    /**
     * A malformed request the application's accept found: a stream error H3_MESSAGE_ERROR (RFC 9114 section 4.1.2), the
     * client's direction stopped with it, after the 400 that section allows "prior to closing or resetting the stream";
     * throws [Http3Exception.MessageError].
     */
    private suspend fun refuseMalformed(reason: String): Nothing {
        runCatching { st.stopSending(Http3ErrorCode.MESSAGE_ERROR) }
        runCatching { respond(400).finish() }
        throw Http3Exception.MessageError(st.id, reason)
    }

    /** A PRIORITY_UPDATE from the client; a priority the server chose in [respond] stays. */
    fun onPriorityUpdate(p: StreamPriority) {
        // the stream first, then the flow: an application that sees the new value finds the stream already scheduled by it
        if (serverPriority == null) {
            st.priority = p
            wtSession?.priorityChanged() // a WebTransport session's streams go with its CONNECT stream (draft-16 section 3.4)
        }
        priorityFlow.value = p
    }

    override suspend fun sendInformational(
        status: Int,
        headers: Http3Headers,
    ) {
        require(status in 100..199 && status != 101) { "interim status must be 1xx other than 101" }
        withContext(session.dispatcher) {
            checkNotAnswered431()
            check(!responseStarted) { "the final response was already sent" }
            writeHeaders(status, headers)
            try {
                st.output.flush()
            } catch (
                e: CancellationException,
            ) {
                throw e
            } catch (e: Throwable) {
                throw session.map(e) // a client that stopped or reset the stream meanwhile: an Http3Exception, as from writeHeaders
            }
        }
    }

    override suspend fun respond(
        status: Int,
        headers: Http3Headers,
        priority: StreamPriority?,
    ): Http3ResponseWriter =
        try {
            respondInternal(status, headers, priority)
        } catch (e: Throwable) {
            applicationDone() // the application was told: the request is over for it
            throw e
        }

    private suspend fun respondInternal(
        status: Int,
        headers: Http3Headers,
        priority: StreamPriority?,
    ): Http3ResponseWriter {
        require(status in 200..599) { "final status must be 200..599" }
        checkConnectionNotEnded() // a hint, as below
        if (responseStarted) { // a hint; the claim below is on the dispatcher
            checkNotAnswered431()
            throw IllegalStateException("response already started")
        }
        check(!finished) { "request is finished" }
        // a rejected field or a failed write never leaves the stream half-open: the response is abandoned, reset with
        // H3_REQUEST_CANCELLED (RFC 9114 section 4.1.1), and the exchange ends
        try {
            validateFields(status, headers)
        } catch (e: IllegalArgumentException) {
            withContext(session.dispatcher) { abortInternal() }
            throw e
        } // done() touches session state: on its dispatcher
        return withContext(session.dispatcher) {
            // claimed here, where the runtime's own 431 claims it ([claimResponseFor431]) and the body pump reads [tunnel]
            checkResponseOpen()
            responseStarted = true
            tunnel = method == "CONNECT" && status in 200..299
            // an explicit priority wins; else the response's own `priority` field merged into the stream's current schedule
            // (RFC 9218 section 8: a parameter it leaves out keeps that value), as h2o does: the client's signal, else the
            // defaults
            // (a field that fails to parse is no choice of the server's: RFC 8941 section 4.2, "as if the field were not present")
            val field = headers.priorityFieldValue()
            (priority ?: field?.takeIf { PriorityField.isSignal(it) }?.let { PriorityField.merge(st.priority, it) })?.let {
                serverPriority = it
                st.priority = it
            }
            try {
                writeHeaders(status, headers)
            } catch (
                e: CancellationException,
            ) {
                throw e
            } catch (e: Throwable) {
                abortInternal()
                throw e
            }
            session.afterResponseHeadersForTest?.invoke(st)
            try {
                st.output.flush()
            } catch (
                e: CancellationException,
            ) {
                throw e
            } catch (e: Throwable) {
                // every write already handed the HEADERS frame to the transport: a client that stopped the stream once it had
                // the response (one abandoning a rejected CONNECT) ends the body, which the writer reports, not the response
                if (!stoppedByPeer(e)) {
                    abortInternal()
                    throw session.map(e)
                }
            }
            // HEAD, 204 and 304 carry no content (RFC 9110 sections 9.3.2, 15.3.5, 15.4.5): what the application writes is dropped
            val discard = method == "HEAD" || status == 204 || status == 304
            // the content must match its content-length (RFC 9114 section 4.1.2); a tunnel's says nothing about its bytes
            val declared = if (discard || tunnel) null else headers["content-length"]?.let { parseContentLength(it) ?: throw IllegalArgumentException("invalid content-length '$it'") }
            ResponseWriterImpl(session, st, this@ServerRequestImpl, discardBody = discard, declaredLength = declared, tunnel = tunnel)
        }
    }

    /** The client's STOP_SENDING behind a failed write. */
    private fun stoppedByPeer(e: Throwable): Boolean =
        (H3Session.transportCause(e) as? QuicException.StreamError.Stopped)?.initiator == Initiator.Peer

    /** Session dispatcher only: [done] changes the session's maps and counters. */
    private fun abortInternal() {
        // RFC 9114 section 4.1.1: "When a server abandons a response after partial processing, it SHOULD abort its response
        // stream with the error code H3_REQUEST_CANCELLED"
        runCatching { st.reset(Http3ErrorCode.REQUEST_CANCELLED) }
        runCatching { st.stopSending(Http3ErrorCode.REQUEST_CANCELLED) }
        done()
    }

    /**
     * Response fields: no pseudo-headers, no connection-specific fields, and no `te` (a request-only field, RFC 9110 section
     * 10.1.4); no `content-length` in a 1xx or 204 (RFC 9110 section 8.6) nor in a 2xx to CONNECT (section 9.3.6); no
     * `capsule-protocol` outside 2xx (RFC 9297 section 3.4), and a 2xx to CONNECT that enables the Capsule Protocol follows
     * section 3.2.
     */
    private fun validateFields(
        status: Int,
        headers: Http3Headers,
    ) {
        for ((n, v) in headers.fields) {
            require(
                !n.startsWith(':') && FieldValidator.checkName(n) == null && FieldValidator.checkValue(v) == null &&
                    n !in FieldValidator.CONNECTION_SPECIFIC && n != "te",
            ) { "invalid response field '$n'" }
        }
        // RFC 9110 sections 2.2, 8.6: 1*DIGIT, several values only when identical (as we require of the peer)
        try {
            FieldValidator.checkContentLength(headers.fields)
        } catch (m: MalformedMessage) {
            throw IllegalArgumentException("invalid response: ${m.reason}")
        }
        if (status in 100..199 || status == 204 || (method == "CONNECT" && status in 200..299)) {
            require(
                headers["content-length"] == null,
            ) { "content-length in a $status response${if (method == "CONNECT") " to CONNECT" else ""}" }
        }
        // RFC 9297 section 3.4: "The Capsule-Protocol header field MUST NOT be used on HTTP responses with a status code that
        // is both different from 101 (Switching Protocols) and outside the 2xx (Successful) range" (HTTP/3 has no 101)
        require(
            headers[CapsuleRules.FIELD] == null || status in 200..299,
        ) { "capsule-protocol in a $status response (RFC 9297 section 3.4)" }
        // section 3.2: a message that uses the Capsule Protocol has no content-length, content-type or transfer-encoding, and
        // no 204, 205 or 206 status
        if (method == "CONNECT" && CapsuleRules.isEnabled(headers)) {
            CapsuleRules.violation(headers, status)?.let { throw IllegalArgumentException("invalid response: $it") }
        }
    }

    private suspend fun writeHeaders(
        status: Int,
        headers: Http3Headers,
    ) {
        validateFields(status, headers)
        val fields = PseudoHeaders.buildResponse(status, headers)
        session.checkPeerFieldLimit(st.id, fields)
        try {
            session.writeHeadersFrame(st, fields, headers.neverIndexNames())
        } catch (
            e: CancellationException,
        ) {
            throw e
        } catch (e: Throwable) {
            throw session.map(e)
        }
    }

    /** The application reset the request ([reset]). */
    @Volatile private var resetByApplication = false

    /**
     * An engine's handler is over, whether or not it ran: a request it never answered nor reset is reset with [code] here,
     * so it ends (STOP_SENDING and RESET_STREAM, [done]) also when its handler was cancelled before it started its work.
     * Any thread.
     */
    fun resetIfUnanswered(code: Long) {
        if (!responseStarted && !resetByApplication) reset(code)
    }

    override fun reset(code: Long) {
        resetByApplication = true
        st.reset(code)
        st.stopSending(code)
        // on the session's dispatcher, in afterEnd: a launch into the session's scope after the connection ended never runs,
        // and the request stayed registered
        session.afterEnd.launch { done() }
        applicationDone()
    }
}

/**
 * Copies what the application writes into DATA frames; [finish] adds trailers and FIN. With [discardBody] (a response
 * that has no content) the bytes are read and dropped, so the peer never sees DATA it must treat as malformed.
 */
internal class ResponseWriterImpl(
    private val session: H3Session,
    private val st: QuicStream,
    private val request: ServerRequestImpl?,
    private val discardBody: Boolean = false,
    /** The response's content-length: content that does not match it is never sent as a complete response. */
    private val declaredLength: Long? = null,
    /** The body of an established CONNECT tunnel (either side): only DATA follows the 2xx, never trailers. */
    private val tunnel: Boolean = false,
) : Http3ResponseWriter {
    private val channel = ByteChannel()
    override val output: ByteWriteChannel get() = channel
    private var finishing = false

    /**
     * The bytes of [output] the pump has handed to the QUIC stream so far, each piece counted once the stream's own
     * buffer handed it to the connection's send buffer (its flush returned): what a reset can still discard is no
     * longer queued in front of the transport ([io.kuicksilver.http3.contentHandedToTransport]).
     */
    @Volatile internal var handedToTransport: Long = 0
        private set

    /** Why the pump abandoned the response (set before it ends): [finish] reports it, also once the channel was closed. */
    @Volatile private var abandoned: Throwable? = null
    internal val pump: Job =
        session.scope.launch {
            val buf = ByteArray(CHUNK)
            var sent = 0L
            try {
                while (true) {
                    val n = channel.readAvailable(buf, 0, buf.size)
                    if (n < 0) break
                    if (n > 0 && !discardBody) {
                        // RFC 9114 section 4.1.2: content beyond its content-length makes the response malformed; the piece
                        // that would cross it is not sent, and the response is abandoned (below)
                        if (declaredLength != null &&
                            sent + n > declaredLength
                        ) {
                            throw ContentLengthMismatch(declaredLength, sent + n, more = true)
                        }
                        st.output.writeFrame(FrameType.DATA, buf, 0, n)
                        session.qlog { it.frameCreated(st.id, FrameType.DATA, n.toLong(), H3Qlog.DATA) }
                        st.output.flush()
                        sent += n
                        handedToTransport = sent
                    }
                }
                session.atResponseContentEndForTest?.invoke(st)
                channel.closedCause?.let { throw it }
                if (declaredLength != null && sent != declaredLength) throw ContentLengthMismatch(declaredLength, sent, more = false)
                if (!finishing) {
                    st.output.flushAndClose()
                    request?.responseComplete()
                    request?.applicationDone()
                }
            } catch (e: Throwable) {
                // the pump itself was cancelled (the connection is gone): nothing more goes out
                if (e is CancellationException && !isActive) throw e
                // the application's content failed mid-body, a channel cancelled with a CancellationException included: the
                // response is abandoned after partial processing, "it SHOULD abort its response stream with the error code
                // H3_REQUEST_CANCELLED" (RFC 9114 section 4.1.1); never left without a FIN or a reset
                if (H3Session.transportCause(e) == null) runCatching { st.reset(Http3ErrorCode.REQUEST_CANCELLED) }
                abandoned = session.map(e)
                channel.cancel(abandoned)
                request?.done()
                request?.applicationDone()
            }
        }

    init {
        // cancelled with the connection, before it ran or while it waited: the application's writes fail, never hang
        session.onCancelled(pump) { e -> channel.cancel(e) }
        // and the request ends with it: a handler whose write then failed may never call finish, and nothing else would
        // take it out of the session's maps. done() runs on the session's dispatcher; its scope is gone, afterEnd is not
        if (request != null) {
            pump.invokeOnCompletion { e ->
                if (e == null) return@invokeOnCompletion
                // no effect on a connection that is gone (its stream credit no longer matters): kept so that every end of
                // the request also ends it for the application, as the pump's own failure path does
                request.applicationDone()
                session.afterEnd.launch { request.done() }
            }
        }
    }

    override suspend fun finish(trailers: Http3Headers?) {
        // RFC 9114 section 4.4: "Once the CONNECT method has completed, only DATA frames are permitted to be sent on the
        // stream": trailers (a HEADERS frame) are refused before anything changes, and the tunnel can still end with a FIN
        require(trailers == null || !tunnel) { "trailers on a CONNECT tunnel: only DATA follows its 2xx (RFC 9114 section 4.4)" }
        try {
            finishInternal(trailers)
        } finally {
            request?.applicationDone() // finished, or failed and told the application so
        }
    }

    private suspend fun finishInternal(trailers: Http3Headers?) {
        finishing = true
        // the pump leaves the stream's end to this call from here: a caller cancelled before the FIN went out abandons the
        // response, or the stream would be left without FIN or reset and the request registered for good
        var finSent = false
        try {
            finishStream(trailers) { finSent = true }
        } catch (e: CancellationException) {
            if (!finSent) abandonCancelledFinish(e)
            throw e
        }
    }

    /**
     * [finish]'s caller was cancelled before the FIN went out: the response is abandoned after partial processing, "it
     * SHOULD abort its response stream with the error code H3_REQUEST_CANCELLED" (RFC 9114 section 4.1.1), and the
     * exchange ends. Runs to its end whatever the caller's state. On a server tunnel this aborts both directions (reset and
     * STOP_SENDING), as an abrupt end of a tunnel does (RFC 9114 section 4.4), unlike the client's tunnel writer, which has
     * no request here and resets only its send half.
     */
    private suspend fun abandonCancelledFinish(e: CancellationException) {
        withContext(NonCancellable + session.dispatcher) {
            channel.cancel(e) // a pump still waiting for content ends too
            runCatching { st.reset(Http3ErrorCode.REQUEST_CANCELLED) }
            if (request != null) runCatching { st.stopSending(Http3ErrorCode.REQUEST_CANCELLED) } // as abortInternal
            request?.done()
        }
    }

    private suspend fun finishStream(
        trailers: Http3Headers?,
        onFinSent: () -> Unit,
    ) {
        channel.flushAndClose()
        pump.join()
        abandoned?.let { throw it }
        channel.closedCause?.let { throw session.map(it) }
        withContext(session.dispatcher) {
            if (trailers != null) {
                // checked before anything is closed: refused trailers reset the stream instead of leaving it without FIN
                val refused =
                    try {
                        PseudoHeaders.requireValidTrailers(trailers.fields)
                        session.checkPeerFieldLimit(st.id, trailers.fields)
                        null
                    } catch (e: IllegalArgumentException) {
                        e
                    } catch (e: Http3Exception.FieldSectionTooLarge) {
                        e
                    }
                if (refused != null) {
                    runCatching { st.reset(Http3ErrorCode.REQUEST_CANCELLED) } // abandoned after partial processing
                    runCatching { st.stopSending(Http3ErrorCode.REQUEST_CANCELLED) }
                    request?.done()
                    throw refused
                }
            }
            // a caller cancelled before the FIN went out is abandoned ([abandonCancelledFinish]): its response is never marked
            // complete first, so neither respondedInFull nor a STOP_SENDING with H3_NO_ERROR comes ahead of the reset
            var cancelled = false
            try {
                if (trailers != null) {
                    session.writeHeadersFrame(st, trailers.fields, trailers.neverIndexNames())
                }
                session.beforeResponseFinForTest?.invoke(st)
                st.output.flushAndClose()
                onFinSent()
            } catch (
                e: CancellationException,
            ) {
                cancelled = true
                throw e
            } catch (e: Throwable) {
                throw session.map(e)
            } finally {
                if (!cancelled) request?.responseComplete()
            }
        }
    }
}

/**
 * Content that does not match its content-length (RFC 9114 section 4.1.2): the message would be malformed, so it is
 * abandoned (reset with H3_REQUEST_CANCELLED, section 4.1.1) instead of being sent as if complete.
 */
internal class ContentLengthMismatch(
    declared: Long,
    actual: Long,
    more: Boolean,
) : kotlinx.io.IOException(
        if (more) {
            "more content than its content-length $declared (RFC 9114 section 4.1.2); the stream was reset"
        } else {
            "$actual bytes of content, content-length $declared (RFC 9114 section 4.1.2); the stream was reset"
        },
    )
