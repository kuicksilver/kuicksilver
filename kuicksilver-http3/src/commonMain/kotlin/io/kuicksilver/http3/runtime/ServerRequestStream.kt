// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readAvailable
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3ResponseWriter
import io.kuicksilver.http3.Http3ServerRequest
import io.kuicksilver.http3.Http3Stream
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.H3ProtocolError
import io.kuicksilver.http3.message.FieldValidator
import io.kuicksilver.http3.message.MalformedMessage
import io.kuicksilver.http3.message.PriorityField
import io.kuicksilver.http3.message.PseudoHeaders
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.StreamPriority
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** A request stream accepted by a server: HEADERS first, then the body pump (RFC 9114 section 4.1). */
internal suspend fun handleRequestStream(
    session: H3Session,
    st: QuicStream,
) = with(session) {
    if (st.id > maxRequestId) maxRequestId = st.id
    goAwaySentId?.let {
        if (st.id >= it || headerDeadlinePassed) {
            abort(st, Http3ErrorCode.REQUEST_REJECTED)
            return@with
        }
    }
    // in flight from the first byte, not from the parsed HEADERS: a request below the GOAWAY id whose HEADERS are
    // still arriving must keep the idle close away (RFC 9114 section 5.2), until the header deadline after GOAWAY
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
            )
        val first =
            try {
                frames.next()
            } catch (
                e: IncompleteFrame,
            ) {
                truncated(st, null, null)
                return@with
            } catch (e: QuicException.StreamError) {
                return@with
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
                reject431(st)
                return@with
            } catch (e: StreamAbandoned) {
                return@with
            }
        val parsed =
            try {
                PseudoHeaders.parseRequest(fields, settings.enableConnectProtocol)
            } catch (
                e: MalformedMessage,
            ) {
                abort(st, Http3ErrorCode.MESSAGE_ERROR)
                return@with
            }
        pendingHeaders.remove(st.id)
        val req = ServerRequestImpl(this, st, parsed)
        handedOff = true // from here ServerRequestImpl.done() ends the request
        if (requests.trySend(req).isFailure) {
            abort(st, Http3ErrorCode.REQUEST_REJECTED)
            req.done()
            return@with
        }
        pumpBody(st, frames, req.bodyChannel, req.trailersDeferred, contentLength(parsed.regular)) { f ->
            if (f.code == Http3ErrorCode.EXCESSIVE_LOAD && !req.responseStarted) reject431(st) else abort(st, f.code)
            req.done()
        }
        req.receiveEnded()
    } finally {
        pendingHeaders.remove(st.id)
        if (!handedOff) requestDone()
    }
}

/** 431 and STOP_SENDING H3_EXCESSIVE_LOAD (RFC 9114 section 4.2.2; quic-go CVE-2025-64702). */
private suspend fun H3Session.reject431(st: QuicStream) {
    runCatching {
        st.stopSending(Http3ErrorCode.EXCESSIVE_LOAD)
        st.output.writeFrame(FrameType.HEADERS, qpack.encode(st.id, PseudoHeaders.buildResponse(431, Http3Headers.Empty)))
        st.output.flushAndClose()
    }
    runCatching { qpack.cancelStream(st.id) }
}

internal class ServerRequestImpl(
    private val session: H3Session,
    private val st: QuicStream,
    parsed: PseudoHeaders.Request,
) : Http3ServerRequest {
    override val streamId: Long get() = st.id
    override val method: String = parsed.method
    override val scheme: String? = parsed.scheme
    override val authority: String? = parsed.authority
    override val path: String? = parsed.path
    override val protocol: String? = parsed.protocol
    override val headers: Http3Headers = parsed.regular
    val bodyChannel = ByteChannel()
    override val body: ByteReadChannel get() = bodyChannel
    val trailersDeferred = CompletableDeferred<Http3Headers?>()
    override val trailers: Deferred<Http3Headers?> get() = trailersDeferred

    /** The client's signal: an early PRIORITY_UPDATE beats the header (RFC 9218 section 7.1). */
    private val priorityFlow = MutableStateFlow(session.takeEarlyPriority(st.id) ?: PriorityField.parse(parsed.regular["priority"]))
    private var serverPriority: StreamPriority? = null
    internal val stream: QuicStream get() = st
    override val priority: StateFlow<StreamPriority> get() = priorityFlow
    override val remoteAddress: InetSocketAddress get() = session.currentPath.remoteAddress
    var responseStarted: Boolean = false
        private set
    private var finished = false

    /** The exchange is over (response sent, both tunnel directions ended, or stream aborted): counts once towards the GOAWAY idle close. */
    fun done() {
        if (!finished) {
            finished = true
            session.activeServerRequests.remove(st.id)
            session.datagrams.unregister(st.id)
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

    private val datagramChannel = if (method == "CONNECT") session.datagrams.register(st.id) else null

    /** A CONNECT answered with 2xx: each direction ends on its own, the exchange is over when both did. */
    private var tunnel = false
    private var sendEnded = false
    private var receiveEnded = false

    /** The request's direction ended (FIN, reset or a stream error); ends a tunnel whose response side already ended. */
    fun receiveEnded() {
        receiveEnded = true
        if (tunnel && sendEnded) done()
    }

    init {
        st.priority = priorityFlow.value
        session.activeServerRequests[st.id] = this
    }

    override suspend fun acceptConnect(headers: Http3Headers): Http3Stream {
        check(method == "CONNECT") { "acceptConnect() needs a CONNECT request" }
        val writer = respond(200, headers)
        return Http3StreamImpl(session, st, bodyChannel, writer, datagramChannel!!, this.headers) { session.scope.launch { done() } }
    }

    /** A PRIORITY_UPDATE from the client; a priority the server chose in [respond] stays. */
    fun onPriorityUpdate(p: StreamPriority) {
        priorityFlow.value = p
        if (serverPriority == null) st.priority = p
    }

    override suspend fun sendInformational(
        status: Int,
        headers: Http3Headers,
    ) {
        require(status in 100..199 && status != 101) { "interim status must be 1xx other than 101" }
        check(!responseStarted) { "the final response was already sent" }
        withContext(session.dispatcher) {
            writeHeaders(status, headers)
            st.output.flush()
        }
    }

    override suspend fun respond(
        status: Int,
        headers: Http3Headers,
        priority: StreamPriority?,
    ): Http3ResponseWriter {
        require(status in 200..599) { "final status must be 200..599" }
        check(!responseStarted) { "response already started" }
        check(!finished) { "request is finished" }
        // a rejected field or a failed write never leaves the stream half-open: it is reset with H3_INTERNAL_ERROR and the exchange ends
        try {
            validateFields(headers)
        } catch (e: IllegalArgumentException) {
            withContext(session.dispatcher) { abortInternal() }
            throw e
        } // done() touches session state: on its dispatcher
        responseStarted = true
        tunnel = method == "CONNECT" && status in 200..299
        return withContext(session.dispatcher) {
            priority?.let {
                serverPriority = it
                st.priority = it
            }
            try {
                writeHeaders(status, headers)
                st.output.flush()
            } catch (
                e: CancellationException,
            ) {
                throw e
            } catch (e: Throwable) {
                abortInternal()
                throw e
            }
            // HEAD, 204 and 304 carry no content (RFC 9110 sections 9.3.2, 15.3.5, 15.4.5): what the application writes is dropped
            ResponseWriterImpl(session, st, this@ServerRequestImpl, discardBody = method == "HEAD" || status == 204 || status == 304)
        }
    }

    /** Session dispatcher only: [done] changes the session's maps and counters. */
    private fun abortInternal() {
        runCatching { st.reset(Http3ErrorCode.INTERNAL_ERROR) }
        runCatching { st.stopSending(Http3ErrorCode.INTERNAL_ERROR) }
        done()
    }

    /** Response fields: no pseudo-headers, no connection-specific fields, and no `te` (a request-only field, RFC 9110 section 10.1.4). */
    private fun validateFields(headers: Http3Headers) {
        for ((n, v) in headers.fields) {
            require(
                !n.startsWith(':') && FieldValidator.checkName(n) == null && FieldValidator.checkValue(v) == null &&
                    n !in FieldValidator.CONNECTION_SPECIFIC && n != "te",
            ) { "invalid response field '$n'" }
        }
    }

    private suspend fun writeHeaders(
        status: Int,
        headers: Http3Headers,
    ) {
        validateFields(headers)
        val fields = PseudoHeaders.buildResponse(status, headers)
        session.checkPeerFieldLimit(st.id, fields)
        try {
            st.output.writeFrame(FrameType.HEADERS, session.qpack.encode(st.id, fields))
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
) : Http3ResponseWriter {
    private val channel = ByteChannel()
    override val output: ByteWriteChannel get() = channel
    private var finishing = false
    internal val pump: Job =
        session.scope.launch {
            val buf = ByteArray(CHUNK)
            try {
                while (true) {
                    val n = channel.readAvailable(buf, 0, buf.size)
                    if (n < 0) break
                    if (n > 0 && !discardBody) {
                        st.output.writeFrame(FrameType.DATA, buf, 0, n)
                        st.output.flush()
                    }
                }
                channel.closedCause?.let { throw it }
                if (!finishing) {
                    st.output.flushAndClose()
                    request?.responseComplete()
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                // the application failed mid-body
                if (H3Session.transportCause(e) == null) runCatching { st.reset(Http3ErrorCode.INTERNAL_ERROR) }
                channel.cancel(session.map(e))
                request?.done()
            }
        }

    override suspend fun finish(trailers: Http3Headers?) {
        finishing = true
        channel.flushAndClose()
        pump.join()
        channel.closedCause?.let { throw session.map(it) }
        withContext(session.dispatcher) {
            if (trailers != null) {
                // checked before anything is closed: refused trailers reset the stream instead of leaving it without FIN
                try {
                    session.checkPeerFieldLimit(st.id, trailers.fields)
                } catch (e: Http3Exception.FieldSectionTooLarge) {
                    runCatching { st.reset(Http3ErrorCode.INTERNAL_ERROR) }
                    runCatching { st.stopSending(Http3ErrorCode.INTERNAL_ERROR) }
                    request?.done()
                    throw e
                }
            }
            try {
                if (trailers != null) {
                    st.output.writeFrame(FrameType.HEADERS, session.qpack.encode(st.id, trailers.fields))
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
