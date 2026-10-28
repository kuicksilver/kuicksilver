// Copyright 2014-2026 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Vendored from Ktor 3.6.0 ktor-server-cio ServerPipeline.kt (startServerConnectionPipeline, @InternalAPI there), adapted:
// request framing per RFC 9112 section 6 ([RequestFraming]: Content-Length with Transfer-Encoding, invalid lengths and
// unknown codings are refused with 400 and close; no framing means no body; chunked trailers are accepted); our own
// [H1Connection] and [H1RequestScope] instead of `ServerIncomingConnection` and `ServerRequestScope` (whose constructor
// is internal to ktor-server-cio), without its `onClose` hook; a deadline and a size limit for every request head (408,
// 431), an idle timeout that ends the whole connection, not only its output, and a deadline on response writes that
// make no progress.
package io.kuicksilver.ktor.server.h1

import io.ktor.http.Headers
import io.ktor.http.HeadersBuilder
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.cio.CIOHeaders
import io.ktor.http.cio.ConnectionOptions
import io.ktor.http.cio.Request
import io.ktor.http.cio.RequestResponseBuilder
import io.ktor.http.cio.expectHttpUpgrade
import io.ktor.http.cio.parseRequest
import io.ktor.http.toHttpDate
import io.ktor.server.plugins.BadRequestException
import io.ktor.util.cio.ChannelReadException
import io.ktor.util.date.GMTDate
import io.ktor.util.network.NetworkAddress
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.charsets.TooLongLineException
import io.ktor.utils.io.close
import io.ktor.utils.io.copyAndClose
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.discard
import io.ktor.utils.io.writePacket
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CopyableThrowable
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedSendChannelException
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
import kotlinx.io.InternalIoApi
import kotlinx.io.Source
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/** One accepted (TLS) TCP connection: its plaintext channels and addresses. */
internal class H1Connection(
    val input: ByteReadChannel,
    val output: ByteWriteChannel,
    val remoteAddress: NetworkAddress?,
    val localAddress: NetworkAddress?,
) {
    /**
     * Set when the pipeline ended because the client took nothing of a response for the send-stall deadline: its close
     * need not wait for a drain that has already been given that long.
     */
    @kotlin.concurrent.Volatile
    var clientStoppedReading: Boolean = false
}

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
    /**
     * For a request with `Expect: 100-continue`: complete it once `100 Continue` went out, which starts the deadline of the
     * body (the client may hold the body back until then) as soon as the earlier pipelined responses are written. Null
     * for other requests.
     */
    val continueSent: CompletableJob? = null,
    /**
     * Completed as the response head goes out, true when the response says `Connection: close` (see [H1Response]): the
     * connection ends after it (RFC 9112 section 9.6). False when the handler ends without a response head.
     */
    val endsConnection: CompletableDeferred<Boolean>? = null,
    /** The request's header fields as the client sent them (see [requestFields]); Ktor's parsed map may differ. */
    val fields: Headers = Headers.Empty,
) : CoroutineScope

/**
 * The largest request head (request line, header section, their line ends and any empty lines before it) the server
 * reads: 64 KiB, the default `maxFieldSectionSize` of our HTTP/3 server (`Http3Settings`), so both protocols take the
 * same headers. Above it: 431 (RFC 6585 section 5). Comparable limits: Node.js 16 KiB, nginx 4 x 8 KiB buffers, Netty
 * and Tomcat 8 KiB, Go 1 MiB.
 */
internal const val MAX_REQUEST_HEAD_BYTES: Int = 65_536

/**
 * The shortest time a response write may wait for a client that reads nothing before the connection is closed. The
 * engine sees a client's progress only when the `ByteChannel` in front of the socket takes its buffer, about 1 MiB at a
 * time (Ktor's `CHANNEL_MAX_SIZE`; the flush does not suspend below it), so the deadline sets the slowest rate it
 * serves: 1 MiB in 5 minutes, about 3.4 KiB/s, below EDGE and GPRS-class links and throttled plans (1 MiB at 4 KiB/s
 * takes 4.3 minutes). The 45 s idle timeout as the deadline would cut every client below about 23 KiB/s.
 */
internal val MIN_SEND_STALL_TIMEOUT: Duration = 5.minutes

/** The send-stall deadline for an idle timeout of [idle]: the longer of the two. */
internal fun sendStallTimeout(idle: Duration): Duration = maxOf(idle, MIN_SEND_STALL_TIMEOUT)

/** How long input after a refused head is read and dropped, so the client sees the refusal rather than a reset. */
private val LINGER = 2.seconds

private val PipelineName = CoroutineName("kuicksilver-h1-pipeline")
private val PipelineWriterName = CoroutineName("kuicksilver-h1-pipeline-writer")
private val RequestHandlerName = CoroutineName("kuicksilver-h1-request")

/**
 * How a request body ends (RFC 9112 section 6.3): by the chunked coding (item 4), by Content-Length (item 6), or not at
 * all — no Content-Length and no Transfer-Encoding is a request without a body (item 7), whatever its method or
 * `Connection` header. [fault] is set for a request whose framing is faulty: Content-Length together with
 * Transfer-Encoding (section 6.1: the server MUST close the connection after responding; it is refused here), a
 * Transfer-Encoding that is not a list of transfer codings or whose final coding is not `chunked` (item 4) or that applies
 * `chunked` twice (section 6.1), a coding the server does not implement before the final `chunked` (section 6.1: 501),
 * Transfer-Encoding in an HTTP/1.0 request (section 6.1), or Content-Length values that are not `1*DIGIT` or differ
 * (item 5; identical repeats are one length, RFC 9110 section 8.6). OWS is only SP and HTAB (RFC 9110 section 5.6.3):
 * `Content-Length: 5<VT>` or `Transfer-Encoding: chunked<U+00A0>` is invalid, as a front proxy that ignores it frames
 * the message otherwise (CL.0 or TE obfuscation smuggling).
 * It is also set for a request whose Host is missing (HTTP/1.1), repeated or not `uri-host [ ":" port ]` (section 3.2:
 * the server MUST respond with 400; Ktor's parser refuses only `/?#@` and a trailing colon in a Host value): a front
 * proxy that keys on another Host line than ours routes and caches by another host; and for an absolute-form target with
 * an empty host or with userinfo.
 */
internal class RequestFraming private constructor(
    val chunked: Boolean,
    val contentLength: Long,
    val fault: String?,
    /** The status that refuses a request with a [fault]: 400, or 501 for a transfer coding the server does not implement. */
    val faultStatus: Int = 400,
) {
    /** Whether the request has body bytes to read. */
    val hasBody: Boolean get() = fault == null && (chunked || contentLength > 0)

    /** Copies the body from [input] to [out]; [onComplete] runs once all of it has been read, before [out] is closed. */
    suspend fun readBody(
        input: ByteReadChannel,
        out: ByteWriteChannel,
        onComplete: () -> Unit = {},
    ) {
        if (chunked) {
            return decodeChunkedBody(
                input,
                out,
                readerFailure = { if (it is MalformedChunkedBodyException) MalformedRequestBody(it) else it },
                onComplete = onComplete,
            )
        }
        val copied = input.copyTo(out, contentLength)
        if (copied < contentLength) throw EOFException("The connection closed after $copied of $contentLength body bytes")
        onComplete()
    }

    companion object {
        fun of(
            request: Request,
            fields: Headers = CIOHeaders(request.headers),
        ): RequestFraming {
            val hosts = fields.getAll("Host").orEmpty().size
            if (hosts > 1) return faulty("More than one Host field")
            if (hosts == 0 && HttpProtocolVersion.parse(request.version) == HttpProtocolVersion.HTTP_1_1) {
                return faulty("No Host field in an HTTP/1.1 request")
            }
            fields["Host"]?.let { if (!isValidHostField(it)) return faulty("Invalid Host field") }
            splitAbsoluteForm(request.uri.toString())?.let { (authority, _) ->
                // RFC 9110 section 4.2.1: an "http" URI with an empty host MUST be rejected as invalid; section 4.2.4:
                // userinfo SHOULD be treated as an error (it is likely used to obscure the authority)
                if (splitHostField(authority).first.isEmpty()) return faulty("Empty host in an absolute-form target")
                if ('@' in authority) return faulty("Userinfo in an absolute-form target")
                if (!isValidHostField(authority)) return faulty("Invalid authority in an absolute-form target")
            }
            val te = fields.getAll("Transfer-Encoding").orEmpty()
            val cl = fields.getAll("Content-Length").orEmpty()
            if (te.isNotEmpty()) {
                if (cl.isNotEmpty()) return faulty("Content-Length and Transfer-Encoding in one request")
                if (HttpProtocolVersion.parse(request.version) == HttpProtocolVersion.HTTP_1_0) {
                    return faulty("Transfer-Encoding in an HTTP/1.0 request")
                }
                val codings = transferCodingsOf(te) ?: return faulty("Invalid Transfer-Encoding")
                val last = codings.lastOrNull()
                val finalChunked = last != null && last.name == "chunked" && !last.hasParameters
                if (!finalChunked) return faulty("Transfer coding other than a final chunked")
                if (codings.size > 1) {
                    if (codings.any { it.name == "chunked" && it !== last }) return faulty("chunked applied more than once")
                    return faulty("Unsupported transfer coding", status = 501)
                }
                return RequestFraming(chunked = true, contentLength = -1, fault = null)
            }
            if (cl.isEmpty()) return RequestFraming(chunked = false, contentLength = 0, fault = null)
            val length = contentLengthOf(cl) ?: return faulty("Invalid or conflicting Content-Length")
            return RequestFraming(chunked = false, contentLength = length, fault = null)
        }

        private fun faulty(
            message: String,
            status: Int = 400,
        ) = RequestFraming(chunked = false, contentLength = 0, fault = message, faultStatus = status)
    }
}

/**
 * The header fields of [request] as the client sent them: Ktor's parsed map, except for the values in [kept] (from
 * [checkRequestHead]: values that start with obs-text Ktor's parser takes for whitespace and strips), and without
 * Upgrade in an HTTP/1.0 request: a server MUST ignore it there (RFC 9110 section 7.8), and MUST NOT send the 101 an
 * upgrade would bring to an HTTP/1.0 client (section 15.2). Every reader of a request field in the engine and the
 * application reads this.
 */
internal fun requestFields(
    request: Request,
    kept: List<KeptFieldValue>,
    version: HttpProtocolVersion?,
): Headers {
    val parsed = CIOHeaders(request.headers)
    val dropUpgrade = version == HttpProtocolVersion.HTTP_1_0 && parsed.contains("Upgrade")
    if (kept.isEmpty() && !dropUpgrade) return parsed
    // names() lists each spelling of a name (`X-A`, `x-a`), getAll() ignores case: one pass per name
    val seen = HashSet<String>()
    return HeadersBuilder()
        .apply {
            for (name in parsed.names()) {
                if (!seen.add(name.lowercase())) continue
                if (dropUpgrade && name.equals("Upgrade", ignoreCase = true)) continue
                val values = parsed.getAll(name).orEmpty()
                for ((index, value) in values.withIndex()) {
                    append(name, kept.firstOrNull { it.name.equals(name, ignoreCase = true) && it.occurrence == index }?.value ?: value)
                }
            }
        }.build()
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
 * Starts the HTTP/1.1 pipeline of [connection], invoking [handler] for every request; responses are written in request
 * order. The next request is read once the response head of the one before it is out; the handlers of pipelined
 * requests with safe methods may then run in parallel, a request with an unsafe method runs alone, after the handlers
 * before it and before those after it (RFC 9112 section 9.3.2).
 *
 * [timeout] closes an idle connection, both directions: no response handed to the writer for that long ends the
 * pipeline. [sendTimeout] (the longer of [timeout] and [MIN_SEND_STALL_TIMEOUT] by default) ends it when the client's
 * socket took nothing of a response for that long (a client that stopped reading). A request body that sends no byte
 * for [timeout] fails the handler's read with [RequestBodyTimeout] (after `100 Continue` when the request asked for it,
 * see [H1RequestScope.continueSent]); the response then goes out as 408 and the connection ends after it.
 *
 * [headerTimeout] bounds each request head, counted from the end of the previous response (the start of the
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
    maxHeadBytes: Int = MAX_REQUEST_HEAD_BYTES,
    sendTimeout: Duration = sendStallTimeout(timeout),
    handler: suspend H1RequestScope.(request: Request) -> Unit,
): Job =
    launch(PipelineName) {
        val actorChannel =
            Channel<ByteReadChannel>(
                capacity = 3,
                onUndeliveredElement = { response -> response.cancel(IOException("Response was not delivered")) },
            )
        val input = HeadLimitedInput(connection.input, maxHeadBytes)
        // completed when a request body timed out: the connection ends after that request
        val bodyTimedOut = Job()
        // responses handed to the writer and not yet written: the deadline of the next request head starts at zero
        val unwritten = MutableStateFlow(0)
        val pipelineJob = coroutineContext.job
        startPipelineWriter(actorChannel, timeout, sendTimeout, connection, unwritten) { why ->
            pipelineJob.cancel(CancellationException(why))
        }

        val requestContext = RequestHandlerName + Dispatchers.Unconfined
        // handlers of earlier requests that may still run: only requests with safe methods run in parallel (RFC 9112
        // section 9.3.2), so these are all safe ones
        val running = ArrayList<Job>()

        try {
            var headBudget = firstHeadTimeout
            while (true) { // parse requests loop
                val request =
                    try {
                        readRequestHead(input, headBudget, unwritten, draining)
                    } catch (e: RequestHeadTimeout) {
                        if (e.partial) respondRequestTimeout(actorChannel) else actorChannel.close()
                        break
                    } catch (_: RequestHeadTooLarge) {
                        respondStatus(actorChannel, 431, "Request Header Fields Too Large")
                        lingerAfterRefusal(actorChannel, connection, draining)
                        break
                    } catch (refused: RequestHeadRefused) {
                        if (refused.status == 400) {
                            respondBadRequest(actorChannel)
                        } else {
                            respondClosing(
                                actorChannel,
                                closingResponsePacket(refused.status, refused.reason, refused.location, refused.body),
                            )
                        }
                        lingerAfterRefusal(actorChannel, connection, draining)
                        break
                    } catch (_: TooLongLineException) {
                        respondBadRequest(actorChannel)
                        lingerAfterRefusal(actorChannel, connection, draining)
                        break
                    } catch (io: IOException) {
                        throw io
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (_: Throwable) {
                        respondBadRequest(actorChannel)
                        lingerAfterRefusal(actorChannel, connection, draining)
                        break
                    } ?: break
                headBudget = headerTimeout

                val fields = requestFields(request, input.keptFieldValues, HttpProtocolVersion.parse(request.version))
                // faulty framing: 400 and close before anything of the request is handed on (RFC 9112 sections 6.1, 6.3)
                val framing = RequestFraming.of(request, fields)
                if (framing.fault != null) {
                    request.release()
                    if (framing.faultStatus == 501) respondStatus(actorChannel, 501, "Not Implemented") else respondBadRequest(actorChannel)
                    lingerAfterRefusal(actorChannel, connection, draining)
                    break
                }

                val response = ByteChannel()
                val upgrade = fields["Upgrade"]
                val version = HttpProtocolVersion.parse(request.version)
                // read before the handler runs: it may release the request's fields
                val lastRequest =
                    requestEndsConnection(version, fields.getAll("Connection").orEmpty())
                val safe = request.method.value in SAFE_METHODS
                val connect = request.method.value == "CONNECT"
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
                    connectionOptions = ConnectionOptions.parse(fields["Connection"])
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
                // completed when `100 Continue` has been written (the engine's `addHandlerForExpectedHeader`)
                val continueSent =
                    if (expectedHttpBody && expectsContinue(fields, version)) Job() else null
                val body = if (expectedHttpBody) RequestBody(framing, input, continueSent) else null
                val endsConnection = CompletableDeferred<Boolean>()

                if (!safe) {
                    // an unsafe request runs alone: after the handlers before it (its response waits for theirs anyway)
                    for (earlier in running) earlier.join()
                    running.clear()
                }
                val handlerJob =
                    launch(requestContext, start = CoroutineStart.UNDISPATCHED) {
                        val handlerScope =
                            H1RequestScope(
                                coroutineContext,
                                requestBody,
                                response,
                                connection.remoteAddress,
                                connection.localAddress,
                                upgraded,
                                closing = {
                                    draining?.isCompleted == true || bodyTimedOut.isCompleted || body?.endsConnectionAtResponse() == true
                                },
                                continueSent = continueSent,
                                endsConnection = endsConnection,
                                fields = fields,
                            )
                        try {
                            handler(handlerScope, request)
                        } catch (cause: Throwable) {
                            if (upgraded?.completeExceptionally(cause) == true) {
                                // the outcome of the upgrade was still open, so no response started (the response
                                // settles it first): nothing to cut short, the connection then ends with a close, not a
                                // reset that could destroy the responses before this one
                                response.close()
                            } else {
                                response.close(cause)
                            }
                        } finally {
                            response.close()
                            upgraded?.complete(false)
                            endsConnection.complete(false)
                        }
                    }

                if (upgraded != null) {
                    // a handler that failed before any response started (its error response failed too) completes it
                    // exceptionally: no upgrade, and no answer to this request, so the connection ends after the
                    // responses before it. Rethrown, the failure reset the connection and lost them
                    val up =
                        try {
                            upgraded.await() // suspend a pipeline until we know if the upgrade performed?
                        } catch (c: CancellationException) {
                            throw c
                        } catch (_: Throwable) {
                            null
                        }
                    if (up == true) {
                        actorChannel.close()
                        input.copyAndClose(requestBody as ByteChannel)
                        break
                    } else if (requestBody is ByteChannel) { // not upgraded, for example, 404
                        requestBody.close()
                    }
                    if (up == null) break
                }

                if (body != null && requestBody is ByteChannel) {
                    // the deadline of the body starts once `100 Continue` is on its way to the client, or when the handler
                    // ends without it. The client may wait for it before sending the body (RFC 9110 section 10.1.1), and
                    // it waits in this request's response behind the earlier ones: the deadline starts only once those
                    // are written too (only this request's response unwritten, as for the head deadline)
                    val gate =
                        continueSent?.let { sent ->
                            Job().also { g ->
                                val opener =
                                    launch(start = CoroutineStart.UNDISPATCHED) {
                                        sent.join()
                                        unwritten.first { it <= 1 }
                                        g.complete()
                                    }
                                g.invokeOnCompletion { opener.cancel() }
                                handlerJob.invokeOnCompletion { g.complete() }
                            }
                        }
                    input.startBody(timeout, gate, bodyTimedOut)
                    val reader = async(start = CoroutineStart.UNDISPATCHED) { readRequestBody(body, requestBody, response) }
                    val outcome =
                        select {
                            reader.onAwait { it }
                            handlerJob.onJoin { null }
                        } ?: settleUnreadBody(body, reader, requestBody)
                    input.endBody()
                    when (outcome) {
                        is BodyOutcome.ClientGone -> {
                            throw outcome.cause
                        }

                        BodyOutcome.Complete -> {
                            if (body.endsConnection) break
                        }

                        BodyOutcome.Abandoned -> {
                            // the client may still be sending the body
                            if (body.continueWithheld) actorChannel.close() else lingerAfterRefusal(actorChannel, connection, draining)
                            break
                        }

                        BodyOutcome.Malformed -> {
                            // the 400 for a broken chunked body: the rest of it may still be coming
                            lingerAfterRefusal(actorChannel, connection, draining)
                            break
                        }

                        else -> {
                            break
                        }
                    }
                }

                if (connect) {
                    // a CONNECT is the last request on its connection: the engine refuses every one (a 2xx from the
                    // application goes out as 501, see H1Response.refuseTunnel), and a server MUST close when it rejects
                    // one, without processing any further request, close option or not (RFC 9931 section 8, updating
                    // RFC 9112): the bytes behind it may be the client's tunnel data
                    // sent optimistically, which read as a request would be smuggled. The handler's response goes out,
                    // then the input is drained so the refusal (a 407 the client needs) is not lost to a reset
                    handlerJob.join()
                    lingerAfterRefusal(actorChannel, connection, draining)
                    break
                }
                if (lastRequest) break
                // a response that says `Connection: close` (the application's, a stopping server's, or an HTTP/1.0
                // response of unknown length that the close delimits, section 6.3 item 8) ends the connection: the server
                // MUST NOT process any further request received on it (RFC 9112 section 9.6), so the next one is read
                // only once this response's head shows it may be
                if (endsConnection.await()) break
                if (safe) {
                    running.removeAll { it.isCompleted }
                    running += handlerJob
                } else {
                    // and before the handlers after it: the next request is read once this one's handler has ended
                    handlerJob.join()
                }
            }
        } catch (_: IOException) {
            // the client went away
        } finally {
            actorChannel.close()
        }
    }

/**
 * The safe methods (RFC 9110 section 9.2.1): pipelined requests with only these may be processed in parallel (RFC 9112
 * section 9.3.2); a request with any other method runs alone.
 */
private val SAFE_METHODS = setOf("GET", "HEAD", "OPTIONS", "TRACE")

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
    sendTimeout: Duration,
    connection: H1Connection,
    unwritten: MutableStateFlow<Int>,
    onEnd: (String) -> Unit,
): Job =
    launch(context = PipelineWriterName, start = CoroutineStart.UNDISPATCHED) {
        var failure: Throwable? = null
        try {
            pipelineWriterLoop(actorChannel, timeout, sendTimeout, connection, unwritten, onEnd)
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
 * added would be echoed to the client (the class of Apache's CVE-2012-0053). Its version is HTTP/1.1: a server SHOULD
 * send the highest version it conforms to (RFC 9110 section 6.2), as it does for every other response.
 */
private fun badRequestPacket(): Source =
    RequestResponseBuilder()
        .apply {
            responseLine("HTTP/1.1", 400, "Bad Request")
            headerLine("Date", httpDateNow())
            headerLine("Connection", "close")
            headerLine("Content-Type", "text/plain; charset=utf-8")
            headerLine("Content-Length", BAD_REQUEST_BODY.size.toString())
            emptyLine()
            bytes(BAD_REQUEST_BODY)
        }.build()

private val BAD_REQUEST_BODY = "Bad Request".encodeToByteArray()

/**
 * The current time as a Date field value (IMF-fixdate). RFC 9110 section 6.6.1: an origin server with a clock MUST
 * generate a Date field in its 2xx, 3xx and 4xx responses and MAY in its 1xx and 5xx ones; the engine sends one on every
 * final response it writes or frames, unless the application set its own (as Ktor's DefaultHeaders plugin does).
 */
internal fun httpDateNow(): String = GMTDate().toHttpDate()

/**
 * A [status] response with `Connection: close`, a Location field when [location] is given, and [body] as `text/plain`
 * when given, else empty.
 */
private fun closingResponsePacket(
    status: Int,
    reason: String,
    location: String? = null,
    body: String? = null,
): Source {
    val content = body?.encodeToByteArray()
    return RequestResponseBuilder()
        .apply {
            responseLine("HTTP/1.1", status, reason)
            headerLine("Date", httpDateNow())
            if (location != null) headerLine("Location", location)
            headerLine("Connection", "close")
            if (content != null) headerLine("Content-Type", "text/plain; charset=utf-8")
            headerLine("Content-Length", (content?.size ?: 0).toString())
            emptyLine()
            if (content != null) bytes(content)
        }.build()
}

/**
 * Queues an empty [status] response that closes the connection behind the responses already queued and ends the
 * pipeline.
 */
private suspend fun respondStatus(
    actorChannel: Channel<ByteReadChannel>,
    status: Int,
    reason: String,
) = respondClosing(actorChannel, closingResponsePacket(status, reason))

/**
 * Queues [packet], a complete response that closes the connection, behind the responses already queued, and ends the
 * pipeline. It waits for room in the queue rather than dropping the response when the queue is full: the refusal is the
 * answer the client MUST get (RFC 9112 sections 3.2 and 6.3 items 4 and 5: 400; RFC 6585 section 5: 431). A writer
 * held up by a slow earlier response is bounded by the send-stall and idle deadlines. Nothing is sent only when the
 * writer has already ended (the connection is gone).
 */
private suspend fun respondClosing(
    actorChannel: Channel<ByteReadChannel>,
    packet: Source,
) {
    val bc = ByteChannel()
    bc.writePacket(packet)
    bc.close()
    try {
        actorChannel.send(bc)
    } catch (_: ClosedSendChannelException) {
        bc.cancel(IOException("Response was not delivered"))
    }
    actorChannel.close()
}

/**
 * After a response that ends the connection while the client may still be sending (a refused head, a body not read): a
 * close over unread input makes the kernel send a reset, which can destroy that response before the client reads it
 * (RFC 9112 section 9.6: servers close in stages). Lets the writer finish (and half-close), then reads and drops the
 * input for up to [LINGER] (Go's closeWriteAndWait, nginx `lingering_close`), or until [draining] completes: a stopping
 * server does not wait out the linger of every refused connection.
 */
private suspend fun lingerAfterRefusal(
    actorChannel: Channel<ByteReadChannel>,
    connection: H1Connection,
    draining: Job?,
) {
    actorChannel.close()
    try {
        withTimeoutOrNull(LINGER) {
            if (draining == null) {
                connection.input.discard()
            } else {
                coroutineScope {
                    val discarded = async(start = CoroutineStart.UNDISPATCHED) { connection.input.discard() }
                    select {
                        discarded.onAwait {}
                        draining.onJoin {}
                    }
                    discarded.cancel()
                }
            }
        }
    } catch (_: IOException) {
        // the client went away: nothing left to protect the response from
    }
}

/** `408 Request Timeout` (RFC 9110 section 15.5.9); its deadline starts only once earlier responses are written. */
private suspend fun respondRequestTimeout(actorChannel: Channel<ByteReadChannel>) = respondStatus(actorChannel, 408, "Request Timeout")

/**
 * No byte of a request body arrived for [timeout] (slow POST, R.U.D.Y.): the handler's read of the body fails with this
 * (as the cause of a `ChannelReadException`); the engine answers 408 when no response has started, and the connection
 * closes after the request.
 */
internal class RequestBodyTimeout(
    timeout: Duration,
) : IOException("No byte of the request body for $timeout")

/** The request head is larger than the limit of its [HeadLimitedInput]. */
private class RequestHeadTooLarge : Exception("The request head is too large")

/** The request head did not arrive within its deadline; [partial] when some of it did. */
private class RequestHeadTimeout(
    val partial: Boolean,
) : Exception("The request head did not arrive in time")

/** Cancels the read of a request head at its deadline; private, so no other cancellation is mistaken for it. */
private class HeadDeadline : CancellationException("request head deadline")

/**
 * Parses the next request head from [input] within its size limit, or throws [RequestHeadTooLarge] when it is larger.
 */
private suspend fun readRequestHead(
    input: HeadLimitedInput,
    budget: Duration,
    unwritten: StateFlow<Int>,
    draining: Job?,
): Request? {
    input.startHead()
    val request =
        try {
            readRequestHeadInTime(input, budget, unwritten, draining)
        } catch (e: Throwable) {
            // a head cut at the limit ends like a closed connection: an EOF, a parser error or no request at all
            if (input.exceeded && e !is RequestHeadTimeout) throw RequestHeadTooLarge()
            throw e
        }
    if (input.exceeded) {
        request?.release()
        throw RequestHeadTooLarge()
    }
    input.endHead()
    return request
}

/**
 * Parses the next request head, or throws [RequestHeadTimeout] when it is not complete [budget] after every earlier
 * response has been written ([unwritten] is zero), or [RequestHeadRefused] for a head [checkRequestHead] refuses. Waiting for the first byte separately tells an idle connection from
 * one that started a request. Returns null, as at the end of the input, when [draining] completes before a head starts.
 */
@OptIn(InternalAPI::class)
private suspend fun readRequestHeadInTime(
    input: HeadLimitedInput,
    budget: Duration,
    unwritten: StateFlow<Int>,
    draining: Job?,
): Request? {
    if (budget == Duration.INFINITE) {
        if (draining != null && !awaitRequestStart(input, draining)) return null
        if (input.skipEmptyLines()) input.checkRequestHead()
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
                started = input.skipEmptyLines()
                if (started) input.checkRequestHead()
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

/**
 * Drops the empty lines (CRLF or LF) in front of a request line, which RFC 9112 section 2.2 lets a server ignore, and
 * returns once a byte of something else is there: true, a request has started; false when the input ended first.
 */
@OptIn(InternalAPI::class, InternalIoApi::class)
private suspend fun ByteReadChannel.skipEmptyLines(): Boolean {
    while (true) {
        if (readBuffer.exhausted() && !awaitContent()) return false
        // read the buffered bytes in place, as Ktor's own line reader does (no peek source per line)
        when (readBuffer.buffer[0]) {
            LF -> {
                readBuffer.skip(1)
            }

            CR -> {
                if (!awaitContent(2)) return true
                if (readBuffer.buffer[1] != LF) return true
                readBuffer.skip(2)
            }

            else -> {
                return true
            }
        }
    }
}

private const val CR: Byte = '\r'.code.toByte()
private const val LF: Byte = '\n'.code.toByte()

private suspend fun respondBadRequest(actorChannel: Channel<ByteReadChannel>) = respondClosing(actorChannel, badRequestPacket())

@OptIn(InternalAPI::class)
private suspend fun pipelineWriterLoop(
    channel: ReceiveChannel<ByteReadChannel>,
    timeout: Duration,
    sendTimeout: Duration,
    connection: H1Connection,
    unwritten: MutableStateFlow<Int>,
    onEnd: (String) -> Unit,
) {
    while (true) {
        val next = withTimeoutOrNull(timeout) { channel.receiveCatching() }
        if (next == null) {
            // idle: the reader is waiting for a head that does not come, so the whole connection ends, not only this side
            onEnd("HTTP/1.1 connection idle for $timeout")
            break
        }
        val child = next.getOrNull() ?: break
        try {
            child.copyToClient(connection.output, sendTimeout)
        } catch (cause: Throwable) {
            if (child is ByteWriteChannel) child.close(cause)
            if (cause is ClientNotReading) {
                // the socket has taken nothing for [sendTimeout]: end the connection, its handler (blocked on this response) too
                connection.clientStoppedReading = true
                onEnd(cause.message ?: "HTTP/1.1 client stopped reading")
                break
            }
        } finally {
            unwritten.update { it - 1 }
        }
    }
}

/** The client took no bytes of a response for [timeout]. */
private class ClientNotReading(
    timeout: Duration,
) : IOException("HTTP/1.1 client stopped reading: nothing of the response taken for $timeout")

/**
 * Ktor's `copyTo`, with a deadline on every hand-over to the connection's [output]: a flush that does not return within
 * [stall] (the socket and the channel in front of it full, the client not reading) throws [ClientNotReading]. The deadline
 * is on progress, not on the response: each flush returns as soon as the socket takes data again, so a client that reads
 * slowly keeps its response, as nginx's `send_timeout` ("only between two successive write operations"). Waiting for the
 * application's next bytes has no deadline (a server-sent event stream may be quiet for long).
 */
@OptIn(InternalAPI::class)
private suspend fun ByteReadChannel.copyToClient(
    output: ByteWriteChannel,
    stall: Duration,
) {
    try {
        while (!isClosedForRead) {
            readBuffer.transferTo(output.writeBuffer)
            withTimeoutOrNull(stall) { output.flush() } ?: throw ClientNotReading(stall)
            awaitContent()
        }
        // a response whose handler failed is "closed for read" too, also before this copy reached it (it waited behind
        // a pipelined one): it ends the connection with its failure, not with nothing sent for it
        closedCause?.let { throw it }
    } catch (cause: Throwable) {
        cancel(cause)
        output.close(cause)
        throw cause
    }
}

/** `Expect: 100-continue` on an HTTP/1.1 request, the case `addHandlerForExpectedHeader` answers with `100 Continue`. */
private fun expectsContinue(
    fields: Headers,
    version: HttpProtocolVersion,
): Boolean = version != HttpProtocolVersion.HTTP_1_0 && fields["Expect"]?.lowercase() == "100-continue"

/** How the read of a request body ended. */
private sealed interface BodyOutcome {
    data object Complete : BodyOutcome

    /** No byte for the deadline ([RequestBodyTimeout]); the handler answers 408. */
    data object TimedOut : BodyOutcome

    /** The framing was broken (a bad chunk); a 400 was written. */
    data object Malformed : BodyOutcome

    /** The handler ended with the body unread and the connection ends instead of reading it ([settleUnreadBody]). */
    data object Abandoned : BodyOutcome

    class ClientGone(
        val cause: IOException,
    ) : BodyOutcome
}

/**
 * A request body as the pipeline reads it, for what happens when the handler leaves it unread. Go's net/http reads at
 * most 256 KiB of such a body (`maxPostHandlerReadBytes`) and otherwise closes the connection after the response; so
 * does this, and a request that asked for `100 Continue` and was answered without it is not waited for at all (RFC 9110
 * section 10.1.1: the client may never send the body).
 */
private class RequestBody(
    val framing: RequestFraming,
    val input: HeadLimitedInput,
    val continueSent: Job?,
) {
    /** The whole body has been read. */
    @kotlin.concurrent.Volatile
    var complete: Boolean = false

    /** Decided: the connection ends after this response (it said `Connection: close`). */
    @kotlin.concurrent.Volatile
    var endsConnection: Boolean = false
        private set

    /** Bytes of the body that may still come: null when not known (chunked). */
    private fun remaining(): Long? = if (framing.chunked) null else (framing.contentLength - input.bodyBytesArrived).coerceAtLeast(0)

    /**
     * Whether the rest of the body is not worth reading: never coming (no `100 Continue`), known to be more than the cap,
     * or of unknown size (a chunked body not complete yet). The last is decided as the response head goes out, so the
     * head says `Connection: close` whenever the connection may end. Go drains up to the cap at that point instead
     * (chunkWriter.writeHeader), which consumes a body a handler still means to read while it responds (a streaming
     * echo) unless the handler opted into full duplex; there is no such opt-in here, so a chunked body the handler has
     * not read by its response ends the connection.
     */
    fun notWorthReading(): Boolean =
        !complete && (continueSent?.isCompleted == false || (remaining() ?: Long.MAX_VALUE) > MAX_UNREAD_BODY_BYTES)

    /** No `100 Continue` went out for a request that asked for it: the client holds the body back, nothing to drain. */
    val continueWithheld: Boolean get() = continueSent?.isCompleted == false

    /** At the response head: true (and decided) when the connection is to end after it, which the head then says. */
    fun endsConnectionAtResponse(): Boolean {
        if (!endsConnection && notWorthReading()) endsConnection = true
        return endsConnection
    }

    fun abandon() {
        endsConnection = true
    }
}

/** The most of a body the handler left unread that the pipeline reads (and drops) to keep the connection. */
internal const val MAX_UNREAD_BODY_BYTES: Long = 256 * 1024

/** Reads [body] into [requestBody] for the handler; never throws but for a cancellation. */
private suspend fun readRequestBody(
    body: RequestBody,
    requestBody: ByteChannel,
    response: ByteChannel,
): BodyOutcome =
    try {
        // complete before the handler can see the end: a chunked decoder closes its output itself
        body.framing.readBody(body.input, requestBody) { body.complete = true }
        BodyOutcome.Complete
    } catch (cause: RequestBodyTimeout) {
        // the handler sees it through its read and is answered 408 (H1CallPhase); no further request on this connection,
        // and its response says so (the input completed `bodyTimedOut` before failing)
        requestBody.close(ChannelReadException("Failed to read request body", cause))
        BodyOutcome.TimedOut
    } catch (cause: IOException) {
        requestBody.close(ChannelReadException("Failed to read request body", cause))
        BodyOutcome.ClientGone(cause)
    } catch (cause: CancellationException) {
        requestBody.close(ChannelReadException("Failed to read request body", cause))
        throw cause
    } catch (cause: Throwable) {
        requestBody.close(ChannelReadException("Failed to read request body", cause))
        response.writePacket(badRequestPacket())
        response.close()
        BodyOutcome.Malformed
    } finally {
        requestBody.close()
    }

/**
 * The handler has ended while its body was still being read: a rest that is not worth reading ends the connection (the
 * reader is stopped); a small one is read and dropped, up to [MAX_UNREAD_BODY_BYTES], so the next request can follow.
 */
private suspend fun settleUnreadBody(
    body: RequestBody,
    reader: Deferred<BodyOutcome>,
    requestBody: ByteChannel,
): BodyOutcome {
    if (body.endsConnection || body.notWorthReading()) {
        body.abandon()
        // joined: the reader must be off the input before anything else reads it (ByteChannel has one reader)
        reader.cancelAndJoin()
        requestBody.cancel(IOException("The handler ended before reading the request body"))
        return BodyOutcome.Abandoned
    }
    requestBody.discard(MAX_UNREAD_BODY_BYTES + 1) // a body of exactly the cap is drained in full
    if (!requestBody.isClosedForRead) {
        // more than the cap after all (the Content-Length rest was larger than the count of bytes that had arrived said)
        body.abandon()
        reader.cancelAndJoin()
        requestBody.cancel(IOException("The request body the handler left unread is larger than $MAX_UNREAD_BODY_BYTES bytes"))
        return BodyOutcome.Abandoned
    }
    return reader.await()
}

/**
 * Whether the connection ends after the response to a request of [version] with the Connection field lines
 * [connection]: one with the `close` option (RFC 9112 section 9.6: the server MUST close after the response), in a list
 * and in any case, also next to `keep-alive`, or an HTTP/1.0 request without `keep-alive` (section 9.3, RFC 9112
 * appendix C.2.2). Ktor's `ConnectionOptions` read only the first line and took `keep-alive` over `close`, and an unknown
 * option alone as `keep-alive`. [H1Response] says `close` in the response whenever this holds.
 */
internal fun requestEndsConnection(
    version: HttpProtocolVersion?,
    connection: List<String>,
): Boolean {
    val options = connection.flatMap { line -> line.split(',').map { it.trim(' ', '\t').lowercase() } }
    if ("close" in options) return true
    return version != HttpProtocolVersion.HTTP_1_1 && "keep-alive" !in options
}
