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
import io.kuicksilver.http3.webtransport.WtProtocols
import io.kuicksilver.http3.webtransport.WtSessionImpl
import io.kuicksilver.http3.webtransport.WtTokens
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.activePath
import io.kuicksilver.quic.readAhead
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.incrementAndFetch

/** A request stream accepted by a server: HEADERS first, then the body pump (RFC 9114 section 4.1). */
internal suspend fun handleRequestStream(
    session: H3Session,
    st: QuicStream,
) = with(session) {
    // WebTransport: a bidirectional stream that starts with WT_STREAM is no request (draft-ietf-webtrans-http3-16 section
    // 4.3). Read before anything a request does: such a stream does not count as one, and our GOAWAY does not refuse it
    // RFC 9204 section 2.2.1: with blocked sections possible, nothing of the first field section is taken ahead of it
    if (settings.qpackBlockedStreams > 0) st.readAhead = RequestFrames.FRAME_HEADER_AHEAD
    val firstType =
        if (settings.webTransport) {
            try {
                st.input.readVarIntOrNull()
            } catch (_: IncompleteFrame) {
                truncated(st, null, null)
                return@with
            } catch (e: CancellationException) {
                throw e
            } catch (_: Throwable) {
                null // a reset or a lost connection: the request path below meets it again and handles it as before
            }
        } else {
            null
        }
    if (firstType == FrameType.WT_STREAM) {
        bidiSettled(st.id) // a WebTransport stream, not a request: never a session
        st.readAhead = Long.MAX_VALUE // its data carries no field section: read ahead as any stream
        wt.onBidi(st)
        return@with
    }
    if (st.id > maxRequestId) maxRequestId = st.id
    goAwaySentId?.let {
        if (st.id >= it || headerDeadlinePassed) {
            abort(st, Http3ErrorCode.REQUEST_REJECTED)
            return@with
        }
    }
    // in flight from its first frame type (its first byte; with WebTransport, once that type was read above), not from
    // the parsed HEADERS: a request below the GOAWAY id whose HEADERS are still arriving must keep the idle close away
    // (RFC 9114 section 5.2), until the header deadline after GOAWAY
    requestStarted()
    pendingHeaders[st.id] = st to currentCoroutineContext()[Job]!!
    var handedOff = false
    try {
        val frames =
            RequestFrames(
                st.input,
                isServerSide = true,
                maxHeadersFrame = maxHeadersFrame,
                onSkipped = { glitch("unknown frame on a request stream") },
                onBuffered = { bufferedHeaderBytes += it },
                firstType = firstType,
                webTransport = settings.webTransport,
                // RFC 9204 section 2.2.1: a blocked section stays unread, in the stream's flow-control window
                beforeFieldSection = { ric -> qpack.awaitInserts(st.id, ric) { st.input.closedCause != null || noMoreInserts() } },
                limitReadAhead = if (settings.qpackBlockedStreams > 0) ({ st.readAhead = it }) else null,
            )
        beforeRequestHeadersForTest?.invoke(st)
        val first =
            try {
                frames.next()
            } catch (
                e: IncompleteFrame,
            ) {
                truncated(st, null, null)
                return@with
            } catch (e: QuicException.StreamError) {
                // reset before its HEADERS were read: no request, but the peer's encoder may count a section that was lost
                // or dropped with the reset (RFC 9204 section 4.4.2)
                runCatching { cancelSections(st) }
                return@with
            } catch (e: StreamAbandoned) {
                return@with // reset while its HEADERS waited for inserts: the Stream Cancellation went out
            }
        val block =
            when (first) {
                RequestFrame.End -> {
                    abort(st, Http3ErrorCode.REQUEST_INCOMPLETE)
                    return@with
                }

                is RequestFrame.Data -> {
                    throw H3ProtocolError(Http3ErrorCode.FRAME_UNEXPECTED, "DATA before HEADERS on stream ${st.id}")
                }

                is RequestFrame.HeadersTooLarge -> {
                    reject431(st)
                    return@with
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
                reject431(st, e.code)
                return@with
            } catch (e: StreamAbandoned) {
                return@with
            }
        val parsed =
            try {
                PseudoHeaders.parseRequest(fields, settings.enableConnectProtocol).let { r ->
                    PseudoHeaders.Request(r.method, r.scheme, r.authority, r.path, r.protocol, r.regular.receivedNeverIndexed(fields))
                }
            } catch (
                e: MalformedMessage,
            ) {
                abort(st, Http3ErrorCode.MESSAGE_ERROR)
                return@with
            }
        pendingHeaders.remove(st.id)
        bidiSettled(st.id)
        // datagrams kept while the HEADERS were on the way belong to a request without datagram semantics: RFC 9297 section
        // 2 has it aborted with H3_DATAGRAM_ERROR (an Extended CONNECT with them takes them when its channel registers)
        if (!hasDatagramSemantics(parsed.method, parsed.protocol) && datagrams.dropPending(st.id)) {
            abort(st, Http3ErrorCode.DATAGRAM_ERROR)
            return@with
        }
        if (settings.webTransport && parsed.method == "CONNECT" && WtTokens.isWebTransport(parsed.protocol)) {
            // one session per connection without flow control: a second is refused before the application (section 5.1)
            if (wtSessionStream != null) {
                abort(st, Http3ErrorCode.REQUEST_REJECTED)
                wt.unregister(st.id)
                return@with
            }
            wtSessionStream = st.id
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
                return@with
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
                    return@with
                }
            }
        }
        handedOff = true // from here ServerRequestImpl.done() ends the request
        if (requests.trySend(req).isFailure) {
            abort(st, Http3ErrorCode.REQUEST_REJECTED)
            req.done()
            return@with
        }
        // a CONNECT has no content: what follows its header section is the tunnel, which its content-length does not
        // describe (RFC 9110 section 9.3.6, RFC 9114 section 4.1.2)
        val bodyLimit = if (parsed.method == "CONNECT") null else contentLength(parsed.regular)
        pumpBody(st, frames, req.bodyChannel, req.trailersDeferred, bodyLimit, tunnel = { req.tunnel }) { f ->
            // the 431 claims the response on this dispatcher first: an application's respond() meanwhile finds it taken
            if (f.error is Http3Exception.FieldSectionTooLarge && req.claimResponseFor431()) reject431(st, f.code) else abort(st, f.code)
            req.done()
        }
        req.receiveEnded()
    } finally {
        pendingHeaders.remove(st.id)
        if (!handedOff) {
            requestDone()
            if (wtSessionStream == st.id) wtSessionEnded(st.id, null)
        }
    }
}

/** A WebTransport CONNECT is over (refused, ended, or never handed over): the slot is free and its streams are rejected. */
internal fun H3Session.wtSessionEnded(
    streamId: Long,
    session: WtSessionImpl?,
) {
    if (wtSessionStream == streamId) wtSessionStream = null
    session?.ended() ?: wt.unregister(streamId)
}

/**
 * 425 Too Early for a request that came in 0-RTT and the policy does not run early (RFC 8470 section 5.2): the request is
 * not read (STOP_SENDING H3_NO_ERROR) and the client may send it again after the handshake.
 */
private suspend fun H3Session.reject425(st: QuicStream) {
    runCatching {
        st.stopSending(Http3ErrorCode.NO_ERROR)
        st.output.writeFrame(FrameType.HEADERS, qpack.encode(st.id, PseudoHeaders.buildResponse(425, Http3Headers.Empty)))
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
        st.output.writeFrame(FrameType.HEADERS, qpack.encode(st.id, PseudoHeaders.buildResponse(431, Http3Headers.Empty)))
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
        BodyReadChannel(bodyChannel) {
            // the application wants no more of the request: stop the client now (RFC 9114 section 4.1), not at its next DATA
            if (!receiveEnded) runCatching { st.stopSending(Http3ErrorCode.NO_ERROR) }
        }
    val trailersDeferred = CompletableDeferred<Http3Headers?>()
    override val trailers: Deferred<Http3Headers?> get() = trailersDeferred

    /** The client's signal: an early PRIORITY_UPDATE beats the header (RFC 9218 section 7.1). */
    private val earlyPriority = session.takeEarlyPriority(st.id)

    /** The client gave a signal: the `priority` field or a PRIORITY_UPDATE that came first. */
    private val signalled = earlyPriority != null || parsed.regular["priority"] != null
    private val priorityFlow = MutableStateFlow(earlyPriority ?: PriorityField.parse(parsed.regular.priorityFieldValue()))
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

    /** Session dispatcher only: the final response can still be sent. */
    private fun checkResponseOpen() {
        checkNotAnswered431()
        check(!responseStarted) { "response already started" }
        check(!finished) { "request is finished" }
    }

    /** The exchange is over (response sent, both tunnel directions ended, or stream aborted): counts once towards the GOAWAY idle close. */
    fun done() {
        if (!finished) {
            finished = true
            session.activeServerRequests.remove(st.id)
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
    fun responseComplete() {
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
        // a tunnel without a signal shares bandwidth (RFC 9218 sections 10.1, 11); the client's signal itself stays the default
        st.priority = if (!signalled && method == "CONNECT") TUNNEL_PRIORITY else priorityFlow.value
        session.activeServerRequests[st.id] = this
    }

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
            onReset = { session.scope.launch { done() } },
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
        val missing =
            when {
                ps == null -> "no SETTINGS from the client within ${session.wtDeadline}"
                !ps.h3Datagram -> "the client did not send SETTINGS_H3_DATAGRAM=1, which WebTransport needs"
                else -> null
            }
        if (missing != null) {
            // a request the client could not make (section 3.1): malformed, answered with 400 so it learns why
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
        val s = WtSessionImpl(session, stream, this.headers, protocol)
        withContext(session.dispatcher) {
            if (finished) {
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
        if (serverPriority == null) st.priority = p
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
    ): Http3ResponseWriter {
        require(status in 200..599) { "final status must be 200..599" }
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
            // (RFC 9218 section 8: a parameter it leaves out keeps that value), as h2o does: the client's signal, or for an
            // unsignalled tunnel its incremental default (sections 10.1, 11), which a field like `u=1` then keeps
            (priority ?: headers.priorityFieldValue()?.let { PriorityField.merge(st.priority, it) })?.let {
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
            val declared = if (discard || tunnel) null else headers["content-length"]?.toLong()
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
            st.output.writeFrame(FrameType.HEADERS, session.qpack.encode(st.id, fields, headers.neverIndexNames()))
        } catch (
            e: CancellationException,
        ) {
            throw e
        } catch (e: Throwable) {
            throw session.map(e)
        }
    }

    override fun reset(code: Long) {
        st.reset(code)
        st.stopSending(code)
        session.scope.launch { done() }
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
                        st.output.flush()
                        sent += n
                    }
                }
                channel.closedCause?.let { throw it }
                if (declaredLength != null && sent != declaredLength) throw ContentLengthMismatch(declaredLength, sent, more = false)
                if (!finishing) {
                    st.output.flushAndClose()
                    request?.responseComplete()
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
            }
        }

    init {
        // cancelled with the connection, before it ran or while it waited: the application's writes fail, never hang
        session.onCancelled(pump) { e -> channel.cancel(e) }
    }

    override suspend fun finish(trailers: Http3Headers?) {
        // RFC 9114 section 4.4: "Once the CONNECT method has completed, only DATA frames are permitted to be sent on the
        // stream": trailers (a HEADERS frame) are refused before anything changes, and the tunnel can still end with a FIN
        require(trailers == null || !tunnel) { "trailers on a CONNECT tunnel: only DATA follows its 2xx (RFC 9114 section 4.4)" }
        finishing = true
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
            try {
                if (trailers != null) {
                    st.output.writeFrame(FrameType.HEADERS, session.qpack.encode(st.id, trailers.fields, trailers.neverIndexNames()))
                }
                st.output.flushAndClose()
            } catch (
                e: CancellationException,
            ) {
                throw e
            } catch (e: Throwable) {
                throw session.map(e)
            } finally {
                request?.responseComplete()
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
