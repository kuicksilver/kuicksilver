// Copyright 2014-2026 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Vendored from Ktor 3.6.0 ktor-server-cio ServerPipeline.kt (startServerConnectionPipeline, @InternalAPI there), adapted:
// request framing per RFC 9112 section 6 ([RequestFraming]: Content-Length with Transfer-Encoding, invalid lengths and
// unknown codings are refused with 400 and close; no framing means no body; chunked trailers are accepted); our own
// [H1Connection] and [H1RequestScope] instead of `ServerIncomingConnection` and `ServerRequestScope` (whose constructor
// is internal to ktor-server-cio), without its `onClose` hook.
package io.kuicksilver.ktor.server.h1

import io.ktor.http.HttpProtocolVersion
import io.ktor.http.cio.ConnectionOptions
import io.ktor.http.cio.Request
import io.ktor.http.cio.RequestResponseBuilder
import io.ktor.http.cio.expectHttpUpgrade
import io.ktor.http.cio.parseRequest
import io.ktor.server.plugins.BadRequestException
import io.ktor.util.cio.ChannelReadException
import io.ktor.util.network.NetworkAddress
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.charsets.TooLongLineException
import io.ktor.utils.io.close
import io.ktor.utils.io.copyAndClose
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.writePacket
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CopyableThrowable
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.EOFException
import kotlinx.io.IOException
import kotlinx.io.Source
import kotlin.time.Duration

/** One accepted (TLS) TCP connection: its plaintext channels and addresses. */
internal class H1Connection(
    val input: ByteReadChannel,
    val output: ByteWriteChannel,
    val remoteAddress: NetworkAddress?,
    val localAddress: NetworkAddress?,
)

/**
 * One request of an [H1Connection]: its body ([input]), its response ([output]), for an upgrade whether it happened, and
 * [closing]: true once the server stops, when the connection ends after this response.
 */
internal class H1RequestScope(
    override val coroutineContext: kotlin.coroutines.CoroutineContext,
    val input: ByteReadChannel,
    val output: ByteWriteChannel,
    val remoteAddress: NetworkAddress?,
    val localAddress: NetworkAddress?,
    val upgraded: CompletableDeferred<Boolean>?,
    val closing: () -> Boolean = { false },
) : CoroutineScope

private val PipelineName = CoroutineName("kuicksilver-h1-pipeline")
private val PipelineWriterName = CoroutineName("kuicksilver-h1-pipeline-writer")
private val RequestHandlerName = CoroutineName("kuicksilver-h1-request")

/**
 * How a request body ends (RFC 9112 section 6.3): by the chunked coding (item 4), by Content-Length (item 6), or not at
 * all — no Content-Length and no Transfer-Encoding is a request without a body (item 7), whatever its method or
 * `Connection` header. [fault] is set for a request whose framing is faulty: Content-Length together with
 * Transfer-Encoding (section 6.1: the server MUST close the connection after responding; it is refused here), a
 * transfer coding other than a final `chunked` (item 4), Transfer-Encoding in an HTTP/1.0 request (section 6.1), or
 * Content-Length values that are not `1*DIGIT` or differ (item 5; identical repeats are one length, RFC 9110 section 8.6).
 * It is also set for a request whose Host is missing (HTTP/1.1) or repeated (section 3.2: the server MUST respond with
 * 400; Ktor's parser checks only the syntax of a Host value): a front proxy that keys on another Host line than ours
 * routes and caches by another host.
 */
internal class RequestFraming private constructor(
    val chunked: Boolean,
    val contentLength: Long,
    val fault: String?,
) {
    /** Whether the request has body bytes to read. */
    val hasBody: Boolean get() = fault == null && (chunked || contentLength > 0)

    suspend fun readBody(
        input: ByteReadChannel,
        out: ByteWriteChannel,
    ) {
        if (chunked) return decodeChunkedBody(input, out) { if (it is MalformedChunkedBodyException) MalformedRequestBody(it) else it }
        val copied = input.copyTo(out, contentLength)
        if (copied < contentLength) throw EOFException("The connection closed after $copied of $contentLength body bytes")
    }

    companion object {
        fun of(request: Request): RequestFraming {
            val hosts = request.headers.getAll("Host").count()
            if (hosts > 1) return faulty("More than one Host field")
            if (hosts == 0 && HttpProtocolVersion.parse(request.version) == HttpProtocolVersion.HTTP_1_1) {
                return faulty("No Host field in an HTTP/1.1 request")
            }
            val te = request.headers.getAll("Transfer-Encoding").toList()
            val cl = request.headers.getAll("Content-Length").toList()
            if (te.isNotEmpty()) {
                if (cl.isNotEmpty()) return faulty("Content-Length and Transfer-Encoding in one request")
                if (HttpProtocolVersion.parse(request.version) == HttpProtocolVersion.HTTP_1_0) {
                    return faulty("Transfer-Encoding in an HTTP/1.0 request")
                }
                val codings =
                    te
                        .flatMap { it.split(',') }
                        .map { it.trim().lowercase() }
                        .filter { it.isNotEmpty() && it != "identity" }
                if (codings != listOf("chunked")) return faulty("Unsupported transfer coding: ${te.joinToString()}")
                return RequestFraming(chunked = true, contentLength = -1, fault = null)
            }
            if (cl.isEmpty()) return RequestFraming(chunked = false, contentLength = 0, fault = null)
            val length = contentLengthOf(cl) ?: return faulty("Invalid or conflicting Content-Length")
            return RequestFraming(chunked = false, contentLength = length, fault = null)
        }

        private fun faulty(message: String) = RequestFraming(chunked = false, contentLength = 0, fault = message)

        /** The one length that every value states, or null when one is not 1*DIGIT or they differ. */
        private fun contentLengthOf(values: List<CharSequence>): Long? {
            var result: Long? = null
            for (v in values) {
                for (part in v.split(',')) {
                    val t = part.trim()
                    if (t.isEmpty() || t.length > 18 || t.any { it !in '0'..'9' }) return null
                    val n = t.toLong()
                    if (result != null && result != n) return null
                    result = n
                }
            }
            return result
        }
    }
}

/**
 * What the handler's receive sees for a chunked body that breaks the grammar (RFC 9112 section 7.1): a client error, so
 * Ktor answers 400 (it maps [BadRequestException]) with this fixed message, not 500 with the parser's. Copyable, as the
 * request body channel hands its reader a copy of a [CopyableThrowable] close cause and wraps any other. The pipeline
 * closes the connection after the response, since where the next request would start is unknown.
 */
@OptIn(ExperimentalCoroutinesApi::class)
internal class MalformedRequestBody(
    cause: Throwable?,
) : BadRequestException("Malformed chunked request body", cause),
    CopyableThrowable<MalformedRequestBody> {
    override fun createCopy(): MalformedRequestBody = MalformedRequestBody(this)
}

/**
 * Starts the HTTP/1.1 pipeline of [connection], invoking [handler] for every request (concurrently with reading the next
 * one, as HTTP/1.1 pipelining allows); responses are written in request order.
 *
 * [timeout] closes an idle connection, both directions: no response handed to the writer for that long ends the
 * pipeline. [headerTimeout] bounds each request head, counted from the end of the previous response (the start of the
 * pipeline for the first request, which gets [firstHeadTimeout], what is left of the deadline after the TLS handshake);
 * bytes trickling in do not extend it. A client that sent part of a head by then gets `408 Request Timeout` with
 * `Connection: close` (RFC 9110 section 15.5.9: the server has decided to close rather than wait). One that sent nothing
 * is closed without a response, as Go's `net/http` (`ReadHeaderTimeout`, `IdleTimeout`) and nginx
 * (`client_header_timeout`, `keepalive_timeout`) do: RFC 9112 section 9.5 lets a server close an inactive connection at
 * any time, and a 408 there could cross a request the client is just sending and be taken as its answer.
 *
 * [draining] completes when the server stops: the pipeline then reads no further request. A connection waiting for the
 * first byte of its next request head ends at once (RFC 9112 section 9.5: a server MAY close an idle connection at any
 * time; Go's `Server.Shutdown` closes idle connections the same way); a request in flight, or one whose head has started
 * to arrive, is answered first, its response with `Connection: close` when it is written after [draining] completed.
 */
@OptIn(InternalAPI::class)
internal fun CoroutineScope.startH1Pipeline(
    connection: H1Connection,
    timeout: Duration,
    headerTimeout: Duration,
    firstHeadTimeout: Duration = headerTimeout,
    draining: Job? = null,
    handler: suspend H1RequestScope.(request: Request) -> Unit,
): Job =
    launch(PipelineName) {
        val actorChannel =
            Channel<ByteReadChannel>(
                capacity = 3,
                onUndeliveredElement = { response -> response.cancel(IOException("Response was not delivered")) },
            )
        // responses handed to the writer and not yet written: the deadline of the next request head starts at zero
        val unwritten = MutableStateFlow(0)
        val pipelineJob = coroutineContext.job
        startPipelineWriter(actorChannel, timeout, connection, unwritten) {
            pipelineJob.cancel(CancellationException("HTTP/1.1 connection idle for $timeout"))
        }

        val requestContext = RequestHandlerName + Dispatchers.Unconfined

        try {
            var headBudget = firstHeadTimeout
            while (true) { // parse requests loop
                val request =
                    try {
                        readRequestHead(connection.input, headBudget, unwritten, draining)
                    } catch (e: RequestHeadTimeout) {
                        if (e.partial) respondRequestTimeout(actorChannel) else actorChannel.close()
                        break
                    } catch (_: TooLongLineException) {
                        respondBadRequest(actorChannel)
                        break
                    } catch (io: IOException) {
                        throw io
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (_: Throwable) {
                        respondBadRequest(actorChannel)
                        break
                    } ?: break
                headBudget = headerTimeout

                // faulty framing: 400 and close before anything of the request is handed on (RFC 9112 sections 6.1, 6.3)
                val framing = RequestFraming.of(request)
                if (framing.fault != null) {
                    request.release()
                    respondBadRequest(actorChannel)
                    break
                }

                val response = ByteChannel()
                val upgrade = request.headers["Upgrade"]
                val version = HttpProtocolVersion.parse(request.version)
                val connectionOptions: ConnectionOptions?

                unwritten.update { it + 1 }
                try {
                    actorChannel.send(response)
                } catch (cause: Throwable) {
                    request.release()
                    response.cancel(cause)
                    break
                }

                val expectedHttpBody = framing.hasBody
                val expectedHttpUpgrade: Boolean
                try {
                    connectionOptions = ConnectionOptions.parse(request.headers["Connection"])
                    expectedHttpUpgrade = !expectedHttpBody && expectHttpUpgrade(request.method, upgrade, connectionOptions)
                } catch (_: Throwable) {
                    request.release()
                    response.writePacket(badRequestPacket())
                    response.close()
                    break
                }

                val requestBody =
                    if (expectedHttpBody || expectedHttpUpgrade) {
                        ByteChannel(true)
                    } else {
                        ByteReadChannel.Empty
                    }

                val upgraded = if (expectedHttpUpgrade) CompletableDeferred<Boolean>() else null

                launch(requestContext, start = CoroutineStart.UNDISPATCHED) {
                    val handlerScope =
                        H1RequestScope(
                            coroutineContext,
                            requestBody,
                            response,
                            connection.remoteAddress,
                            connection.localAddress,
                            upgraded,
                            closing = { draining?.isCompleted == true },
                        )
                    try {
                        handler(handlerScope, request)
                    } catch (cause: Throwable) {
                        response.close(cause)
                        upgraded?.completeExceptionally(cause)
                    } finally {
                        response.close()
                        upgraded?.complete(false)
                    }
                }

                if (upgraded != null) {
                    if (upgraded.await()) { // suspend a pipeline until we know if the upgrade performed?
                        actorChannel.close()
                        connection.input.copyAndClose(requestBody as ByteChannel)
                        break
                    } else if (requestBody is ByteChannel) { // not upgraded, for example, 404
                        requestBody.close()
                    }
                }

                if (expectedHttpBody && requestBody is ByteChannel) {
                    try {
                        framing.readBody(connection.input, requestBody)
                    } catch (cause: IOException) {
                        requestBody.close(ChannelReadException("Failed to read request body", cause))
                        throw cause
                    } catch (cause: CancellationException) {
                        requestBody.close(ChannelReadException("Failed to read request body", cause))
                        throw cause
                    } catch (cause: Throwable) {
                        requestBody.close(ChannelReadException("Failed to read request body", cause))
                        response.writePacket(badRequestPacket())
                        response.close()
                        break
                    } finally {
                        requestBody.close()
                    }
                }

                if (isLastHttpRequest(version, connectionOptions)) break
            }
        } catch (_: IOException) {
            // the client went away
        } finally {
            actorChannel.close()
        }
    }

/**
 * Waits for the first byte of the next request head: true once it is there (or the input ended, which the parser
 * reports), false when [draining] completes first.
 */
@OptIn(InternalAPI::class)
private suspend fun awaitRequestStart(
    input: ByteReadChannel,
    draining: Job,
): Boolean {
    if (!input.readBuffer.exhausted() || input.isClosedForRead) return true
    if (draining.isCompleted) return false
    return coroutineScope {
        val started = async(start = CoroutineStart.UNDISPATCHED) { input.awaitContent() }
        select {
            started.onAwait { true }
            draining.onJoin {
                started.cancel()
                false
            }
        }
    }
}

@OptIn(InternalAPI::class)
private fun CoroutineScope.startPipelineWriter(
    actorChannel: Channel<ByteReadChannel>,
    timeout: Duration,
    connection: H1Connection,
    unwritten: MutableStateFlow<Int>,
    onIdle: () -> Unit,
): Job =
    launch(context = PipelineWriterName, start = CoroutineStart.UNDISPATCHED) {
        var failure: Throwable? = null
        try {
            pipelineWriterLoop(actorChannel, timeout, connection, unwritten, onIdle)
        } catch (cause: Throwable) {
            failure = cause
        } finally {
            actorChannel.close(failure)
            connection.output.close(failure)
            actorChannel.cancelPendingResponses(failure)
        }
    }

private fun Channel<ByteReadChannel>.cancelPendingResponses(cause: Throwable?) {
    var cancellationCause: Throwable? = cause
    while (true) {
        val response = tryReceive().getOrNull() ?: break
        cancellationCause = cancellationCause ?: IOException("Response writer has stopped")
        response.cancel(cancellationCause)
    }
}

/**
 * `400 Bad Request` with `Connection: close` and a fixed text body. Ktor CIO sends the parser's message instead, and a
 * `ParserException` message embeds the header section read so far: cookies, credentials and the fields a front proxy
 * added would be echoed to the client (the class of Apache's CVE-2012-0053).
 */
private fun badRequestPacket(): Source =
    RequestResponseBuilder()
        .apply {
            responseLine("HTTP/1.0", 400, "Bad Request")
            headerLine("Connection", "close")
            headerLine("Content-Type", "text/plain; charset=utf-8")
            headerLine("Content-Length", BAD_REQUEST_BODY.size.toString())
            emptyLine()
            bytes(BAD_REQUEST_BODY)
        }.build()

private val BAD_REQUEST_BODY = "Bad Request".encodeToByteArray()

/** `408 Request Timeout` with `Connection: close` (RFC 9110 section 15.5.9). */
private fun requestTimeoutPacket(): Source =
    RequestResponseBuilder()
        .apply {
            responseLine("HTTP/1.1", 408, "Request Timeout")
            headerLine("Connection", "close")
            headerLine("Content-Length", "0")
            emptyLine()
        }.build()

/** Queues the 408 behind the responses already written (the deadline starts only once they are) and ends the pipeline. */
private suspend fun respondRequestTimeout(actorChannel: Channel<ByteReadChannel>) {
    val bc = ByteChannel()
    if (actorChannel.trySend(bc).isSuccess) {
        bc.writePacket(requestTimeoutPacket())
        bc.close()
    }
    actorChannel.close()
}

/** The request head did not arrive within its deadline; [partial] when some of it did. */
private class RequestHeadTimeout(
    val partial: Boolean,
) : Exception("The request head did not arrive in time")

/** Cancels the read of a request head at its deadline; private, so no other cancellation is mistaken for it. */
private class HeadDeadline : CancellationException("request head deadline")

/**
 * Parses the next request head, or throws [RequestHeadTimeout] when it is not complete [budget] after every earlier
 * response has been written ([unwritten] is zero). Waiting for the first byte separately tells an idle connection from
 * one that started a request. Returns null, as at the end of the input, when [draining] completes before a head starts.
 */
@OptIn(InternalAPI::class)
private suspend fun readRequestHead(
    input: ByteReadChannel,
    budget: Duration,
    unwritten: StateFlow<Int>,
    draining: Job?,
): Request? {
    if (budget == Duration.INFINITE) {
        if (draining != null && !awaitRequestStart(input, draining)) return null
        return parseRequest(input)
    }
    var started = false
    try {
        return coroutineScope {
            val head = coroutineContext.job
            val deadline =
                launch {
                    unwritten.first { it <= 0 }
                    delay(budget)
                    head.cancel(HeadDeadline())
                }
            try {
                // the server stopping ends a connection that is waiting for its next head (h1-client's draining)
                if (draining != null && !awaitRequestStart(input, draining)) return@coroutineScope null
                started = input.awaitContent() // false: the client closed without starting a request
                parseRequest(input)
            } finally {
                deadline.cancel()
            }
        }
    } catch (e: CancellationException) {
        currentCoroutineContext().ensureActive() // the connection itself was cancelled: not a deadline
        if (e is HeadDeadline) throw RequestHeadTimeout(started)
        throw e
    }
}

private suspend fun respondBadRequest(actorChannel: Channel<ByteReadChannel>) {
    val bc = ByteChannel()
    if (actorChannel.trySend(bc).isSuccess) {
        bc.writePacket(badRequestPacket())
        bc.close()
    }
    actorChannel.close()
}

@OptIn(InternalAPI::class)
private suspend fun pipelineWriterLoop(
    channel: ReceiveChannel<ByteReadChannel>,
    timeout: Duration,
    connection: H1Connection,
    unwritten: MutableStateFlow<Int>,
    onIdle: () -> Unit,
) {
    while (true) {
        val next = withTimeoutOrNull(timeout) { channel.receiveCatching() }
        if (next == null) {
            // idle: the reader is waiting for a head that does not come, so the whole connection ends, not only this side
            onIdle()
            break
        }
        val child = next.getOrNull() ?: break
        try {
            child.copyTo(connection.output)
            connection.output.flush()
        } catch (cause: Throwable) {
            if (child is ByteWriteChannel) child.close(cause)
        } finally {
            unwritten.update { it - 1 }
        }
    }
}

private fun isLastHttpRequest(
    version: HttpProtocolVersion,
    connectionOptions: ConnectionOptions?,
): Boolean =
    when {
        connectionOptions == null && version == HttpProtocolVersion.HTTP_1_0 -> true
        connectionOptions == null -> version != HttpProtocolVersion.HTTP_1_1
        connectionOptions.keepAlive -> false
        connectionOptions.close -> true
        else -> false
    }
