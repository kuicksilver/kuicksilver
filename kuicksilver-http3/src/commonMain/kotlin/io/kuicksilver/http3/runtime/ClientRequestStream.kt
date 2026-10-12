// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3Request
import io.kuicksilver.http3.Http3Response
import io.kuicksilver.http3.Http3Stream
import io.kuicksilver.http3.frame.ControlFrames
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.H3ProtocolError
import io.kuicksilver.http3.message.FieldValidator
import io.kuicksilver.http3.message.MalformedMessage
import io.kuicksilver.http3.message.PriorityField
import io.kuicksilver.http3.message.PseudoHeaders
import io.kuicksilver.http3.qpack.QpackError
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.StreamPriority
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.coroutines.ContinuationInterceptor

/** Extended CONNECT (RFC 9220 section 3): waits for the peer's SETTINGS, then a request whose stream stays open both ways. */
internal suspend fun H3Session.connect(
    r: Http3Request,
    protocol: String,
): Http3Stream {
    val caller = callerDispatcher()
    return withContext(dispatcher) {
        val ps = awaitPeerSettings()
        if (!ps.enableConnectProtocol) throw Http3Exception.Settings("the peer did not send SETTINGS_ENABLE_CONNECT_PROTOCOL")
        val req =
            Http3Request(
                "CONNECT",
                r.scheme,
                r.authority,
                r.path,
                r.headers,
                priority = r.priority,
                protocol = protocol,
                onInformational = r.onInformational,
            )
        val resp = request(req, keepOpen = true, caller = caller) as ResponseImpl
        if (resp.status !in
            200..299
        ) {
            resp.cancel(Http3ErrorCode.REQUEST_CANCELLED)
            datagrams.unregister(resp.streamId)
            throw Http3Exception.ConnectRejected(resp.status, resp.headers)
        }
        val writer = ResponseWriterImpl(this@connect, resp.stream, null)
        // the datagram registration goes when both directions ended, or at a reset
        scope.launch {
            resp.pump.join()
            writer.pump.join()
            datagrams.unregister(resp.streamId)
        }
        Http3StreamImpl(this@connect, resp.stream, resp.body, writer, resp.datagramChannel!!, resp.headers) {
            scope.launch { datagrams.unregister(resp.streamId) }
        }
    }
}

/**
 * The dispatcher of the coroutine calling into the session: user callbacks ([Http3Request.onInformational],
 * [Http3Request.trailers]) run there, so a slow callback never stalls the connection's single-threaded dispatcher.
 */
private suspend fun callerDispatcher(): ContinuationInterceptor =
    currentCoroutineContext()[ContinuationInterceptor] ?: Dispatchers.Default

internal suspend fun H3Session.request(
    r: Http3Request,
    keepOpen: Boolean = false,
    caller: ContinuationInterceptor? = null,
): Http3Response {
    val callbacks = caller ?: callerDispatcher()
    return withContext(dispatcher) {
        if (closed.isCompleted) throw connectionError()
        if (goAwayReceived.value != null) throw Http3Exception.RequestNotProcessed(true)
        check(goAwaySentId == null) { "this client sent GOAWAY: no new requests" }
        for ((n, v) in r.headers.fields) {
            require(
                !n.startsWith(':') && FieldValidator.checkName(n) == null && FieldValidator.checkValue(v) == null &&
                    n !in FieldValidator.CONNECTION_SPECIFIC,
            ) { "invalid request field '$n'" }
        }
        // before a stream is opened: a refused section costs no stream credit (the id is not known yet: -1)
        checkPeerFieldLimit(-1, PseudoHeaders.buildRequest(r))
        val st =
            try {
                quic.openBidi(r.priority ?: StreamPriority.Default)
            } catch (e: QuicException) {
                throw map(e)
            }
        goAwayReceived.value?.let {
            if (st.id >=
                it
            ) {
                st.reset(Http3ErrorCode.REQUEST_CANCELLED)
                throw Http3Exception.RequestNotProcessed(true)
            }
        }
        clientStreams[st.id] = st
        val dgrams = if (keepOpen) datagrams.register(st.id) else null
        try {
            exchange(st, r, keepOpen, callbacks).also { it.datagramChannel = dgrams }
        } catch (e: Throwable) {
            if (dgrams != null) datagrams.unregister(st.id)
            // a GOAWAY that did not cover this stream aborted it: the server never processed it (RFC 9114 section 5.2)
            if (st.id in rejectedByGoAway && e !is CancellationException) throw Http3Exception.RequestNotProcessed(true)
            throw e
        } finally {
            clientStreams.remove(st.id)
            rejectedByGoAway.remove(st.id)
        }
    }
}

private suspend fun H3Session.exchange(
    st: QuicStream,
    r: Http3Request,
    keepOpen: Boolean,
    callbacks: ContinuationInterceptor,
): ResponseImpl {
    var sender: Job? = null
    // a request the sender had to abandon (trailers above the peer's limit): that failure is the exchange's result
    val sendFailure = CompletableDeferred<Unit>()
    try {
        try {
            st.output.writeFrame(FrameType.HEADERS, qpack.encode(st.id, PseudoHeaders.buildRequest(r)))
            if (keepOpen) {
                st.output.flush() // Extended CONNECT: the stream carries data both ways after the response
            } else if (r.body == null && r.trailers == null) {
                st.output.flushAndClose()
            } else {
                st.output.flush()
                sender = scope.launch { sendBody(st, r, callbacks, sendFailure) }
            }
        } catch (e: Throwable) {
            // a server that answered without the rest of the request may stop it with H3_NO_ERROR before our FIN left: the response still counts (RFC 9114 section 4.1)
            if (!stoppedWithNoError(e)) throw e
        }
        val frames =
            RequestFrames(
                st.input,
                isServerSide = false,
                maxHeadersFrame = maxHeadersFrame,
                onSkipped = { glitch("unknown frame on a request stream") },
                onBuffered = { bufferedHeaderBytes += it },
            )
        var interim = 0
        while (true) {
            when (val f = frames.next()) {
                RequestFrame.End -> {
                    throw StreamFailure(
                        Http3ErrorCode.REQUEST_INCOMPLETE,
                        Http3Exception.Protocol(
                            Http3ErrorCode.REQUEST_INCOMPLETE,
                            Initiator.Peer,
                            st.id,
                            "stream ${st.id} ended without a response",
                        ),
                    )
                }

                is RequestFrame.Data -> {
                    throw H3ProtocolError(Http3ErrorCode.FRAME_UNEXPECTED, "DATA before the response HEADERS on stream ${st.id}")
                }

                is RequestFrame.HeadersTooLarge -> {
                    throw StreamFailure(
                        Http3ErrorCode.EXCESSIVE_LOAD,
                        Http3Exception.FieldSectionTooLarge(st.id, settings.maxFieldSectionSize),
                    )
                }

                is RequestFrame.Headers -> {
                    val (status, headers) =
                        try {
                            PseudoHeaders.parseResponse(decodeSection(st, f.block))
                        } catch (
                            e: MalformedMessage,
                        ) {
                            throw malformed(st.id, e)
                        }
                    if (status in 100..199) {
                        if (status == 101) throw malformed(st.id, MalformedMessage("101 is not allowed in HTTP/3"))
                        if (++interim >
                            settings.maxInformationalResponses
                        ) {
                            throw StreamFailure(
                                Http3ErrorCode.EXCESSIVE_LOAD,
                                Http3Exception.Protocol(
                                    Http3ErrorCode.EXCESSIVE_LOAD,
                                    Initiator.Local,
                                    st.id,
                                    "more than ${settings.maxInformationalResponses} interim responses",
                                ),
                            )
                        }
                        r.onInformational?.let { cb -> withContext(callbacks) { cb(status, headers) } }
                        continue
                    }
                    sendFailure.getFailureOrNull()?.let { throw it } // the request was abandoned before the response came
                    return ResponseImpl(
                        this,
                        st,
                        status,
                        headers,
                        frames,
                        sender,
                        sendFailure,
                        bodyLimit =
                            when {
                                r.method == "CONNECT" && status in 200..299 -> null // a tunnel: no message framing
                                r.method == "HEAD" || status == 204 || status == 304 -> 0L // no content (RFC 9110 sections 9.3.2, 15.3.5, 15.4.5)
                                else -> contentLength(headers)
                            },
                    )
                }
            }
        }
        @Suppress("UNREACHABLE_CODE")
        throw IllegalStateException()
    } catch (e: CancellationException) {
        sender?.cancel()
        withContext(NonCancellable) { abort(st, Http3ErrorCode.REQUEST_CANCELLED) }
        throw e
    } catch (e: StreamFailure) {
        sender?.cancel()
        abort(st, e.code)
        throw sendFailure.failureOr(e.error)
    } catch (e: IncompleteFrame) {
        sender?.cancel()
        truncated(st, null, null)
        throw connectionError()
    } catch (e: H3ProtocolError) {
        sender?.cancel()
        fail(e.code, e.message ?: "")
        throw connectionError()
    } catch (e: QpackError) {
        sender?.cancel()
        fail(e.code, e.message ?: "")
        throw connectionError()
    } catch (e: StreamAbandoned) {
        sender?.cancel()
        throw sendFailure.failureOr(map(st.input.closedCause ?: e))
    } catch (e: Throwable) {
        sender?.cancel()
        throw sendFailure.failureOr(map(e)) // transport failures (possibly wrapped by ktor-io) become HTTP/3 exceptions
    }
}

/** The sender's own failure when it abandoned the request, else [e]. */
private fun CompletableDeferred<Unit>.failureOr(e: Throwable): Throwable = getFailureOrNull() ?: e

@OptIn(ExperimentalCoroutinesApi::class)
private fun CompletableDeferred<Unit>.getFailureOrNull(): Throwable? = if (isCompleted) getCompletionExceptionOrNull() else null

private fun stoppedWithNoError(e: Throwable): Boolean =
    (H3Session.transportCause(e) as? QuicException.StreamError.Stopped)?.code == Http3ErrorCode.NO_ERROR

/** Request body as DATA frames, then trailers, then FIN. A server that stops reading with H3_NO_ERROR ends this quietly (RFC 9114 section 4.1). */
private suspend fun H3Session.sendBody(
    st: QuicStream,
    r: Http3Request,
    callbacks: ContinuationInterceptor,
    sendFailure: CompletableDeferred<Unit>,
) {
    val buf = ByteArray(CHUNK)
    try {
        r.body?.let { body ->
            while (true) {
                val n = body.readAvailable(buf, 0, buf.size)
                if (n <
                    0
                ) {
                    break
                }
                if (n >
                    0
                ) {
                    st.output.writeFrame(FrameType.DATA, buf, 0, n)
                    st.output.flush()
                }
            }
            body.closedCause?.let { throw it }
        }
        r.trailers?.let { cb -> withContext(callbacks) { cb() } }?.let { t ->
            for ((n, v) in t.fields) {
                require(
                    !n.startsWith(':') && FieldValidator.checkName(n) == null && FieldValidator.checkValue(v) == null,
                ) { "invalid trailer field '$n'" }
            }
            try {
                checkPeerFieldLimit(st.id, t.fields)
            } catch (e: Http3Exception.FieldSectionTooLarge) {
                // the request cannot be completed: the exchange is abandoned both ways and its caller gets this failure
                sendFailure.completeExceptionally(e)
                runCatching { st.reset(Http3ErrorCode.REQUEST_CANCELLED) }
                runCatching { st.stopSending(Http3ErrorCode.REQUEST_CANCELLED) }
                r.body?.cancel(e)
                return
            }
            st.output.writeFrame(FrameType.HEADERS, qpack.encode(st.id, t.fields))
        }
        st.output.flushAndClose()
    } catch (e: CancellationException) {
        runCatching { st.reset(Http3ErrorCode.REQUEST_CANCELLED) }
        throw e
    } catch (e: Throwable) {
        val q = H3Session.transportCause(e)
        if (q == null) runCatching { st.reset(Http3ErrorCode.REQUEST_CANCELLED) }
        // the transport reason itself: ktor-io drops a cancel cause that is a ClosedWriteChannelException (its copy is null)
        r.body?.cancel(q ?: e)
    }
}

/**
 * [bodyLimit] is how many DATA bytes the response may carry: 0 for HEAD, 204 and 304 (any DATA is a malformed message),
 * the `content-length` otherwise, null when unbounded (no `content-length`, or a 2xx to CONNECT whose content-length
 * describes no body, RFC 9114 section 4.1.2).
 */
internal class ResponseImpl(
    private val session: H3Session,
    internal val stream: QuicStream,
    override val status: Int,
    override val headers: Http3Headers,
    frames: RequestFrames,
    private val sender: Job?,
    sendFailure: CompletableDeferred<Unit>? = null,
    bodyLimit: Long? = null,
) : Http3Response {
    private val st get() = stream
    override val streamId: Long get() = st.id
    internal var datagramChannel: kotlinx.coroutines.channels.Channel<ByteArray>? = null
    private val bodyChannel = ByteChannel()
    override val body: ByteReadChannel get() = bodyChannel
    private val trailersDeferred = CompletableDeferred<Http3Headers?>()
    override val trailers: Deferred<Http3Headers?> get() = trailersDeferred
    internal val pump: Job =
        session.scope.launch {
            session.pumpBody(st, frames, bodyChannel, trailersDeferred, bodyLimit) { f -> session.run { abortClient(f.code) } }
        }

    init {
        // the request was abandoned after the response began: the body and trailers end with the sender's failure
        sendFailure?.invokeOnCompletion { cause ->
            if (cause != null) {
                pump.cancel()
                bodyChannel.cancel(cause)
                trailersDeferred.completeExceptionally(cause)
            }
        }
    }

    private suspend fun abortClient(code: Long) {
        runCatching { st.stopSending(code) }
        runCatching { st.reset(code) }
        runCatching { session.qpack.cancelStream(st.id) }
    }

    override suspend fun updatePriority(priority: StreamPriority) {
        st.priority = priority
        session.sendControl(
            FrameType.PRIORITY_UPDATE_REQUEST,
            ControlFrames.priorityUpdatePayload(
                st.id,
                PriorityField.format(priority) ?: "u=3",
            ),
        )
    }

    override fun cancel(code: Long) {
        pump.cancel()
        sender?.cancel()
        runCatching { st.stopSending(code) }
        runCatching { st.reset(code) }
        session.scope.launch { runCatching { session.qpack.cancelStream(st.id) } }
        val e = CancellationException("response cancelled with ${Http3ErrorCode.name(code)}")
        bodyChannel.cancel(e)
        trailersDeferred.cancel(e)
    }
}
