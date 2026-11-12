// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server.h2

import io.ktor.http.Headers
import io.ktor.http.HeadersBuilder
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.engine.BaseApplicationCall
import io.ktor.server.request.ApplicationReceivePipeline
import io.ktor.server.response.respond
import io.ktor.util.pipeline.PipelinePhase
import io.kuicksilver.http2.runtime.H2ServerStream
import io.kuicksilver.ktor.server.EARLY_DATA_FIELD
import io.kuicksilver.ktor.server.NeverIndexedReceivedKey
import io.kuicksilver.ktor.server.PeerCertificatesKey
import io.kuicksilver.ktor.server.ReceivedEarlyKey
import io.kuicksilver.ktor.server.RequestPriorityKey
import io.kuicksilver.ktor.server.h1Priority
import io.kuicksilver.tls.Certificate
import kotlinx.coroutines.CoroutineScope
import kotlin.coroutines.CoroutineContext
import kotlin.time.Duration

/**
 * One HTTP/2 request as a Ktor call (RFC 9113 section 8): version "HTTP/2", the scheme from `:scheme`, `:authority` as
 * `Host`, split `cookie` fields joined (section 8.2.3). Its response goes out as HEADERS and DATA within the client's
 * flow-control windows ([H2Response]); its body is read through the stream's window, each wait bounded by [bodyIdle].
 */
internal class H2Call(
    application: Application,
    val h2: H2ServerStream,
    local: io.ktor.network.sockets.InetSocketAddress?,
    remote: io.ktor.network.sockets.InetSocketAddress?,
    peerCertificates: List<Certificate>,
    override val coroutineContext: CoroutineContext,
    bodyIdle: Duration,
    sendStallMillis: Long,
    altSvc: () -> String?,
) : BaseApplicationCall(application),
    CoroutineScope {
    override val request = H2Request(this, h2, local, remote, toKtorHeaders(h2), bodyIdle)
    override val response = H2Response(this, h2, sendStallMillis, altSvc)

    init {
        putResponseAttribute()
        attributes.put(PeerCertificatesKey, peerCertificates)
        if (h2.neverIndexed.isNotEmpty()) attributes.put(NeverIndexedReceivedKey, h2.neverIndexed)
        // the Priority field (RFC 9218 section 5) is end to end: read as on HTTP/1.1 (PRIORITY_UPDATE is not used on HTTP/2)
        attributes.put(RequestPriorityKey, h1Priority(request.headers.getAll("Priority")))
        // a gateway forwarded it from early data (RFC 8470 section 5.1)
        if (h2.fields.any { it.first == EARLY_DATA_FIELD.lowercase() }) {
            @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
            attributes.put(ReceivedEarlyKey, true)
        }
        answerExpectation()
    }

    /**
     * RFC 9110 section 10.1.1: a client that sent `Expect: 100-continue` waits for an interim 100 before the content, which
     * "MUST" be "an immediate 100 (Continue) response" when the head alone does not determine a final status (those, 425
     * and 501, went out before the call was made): it goes out as the call starts (as on HTTP/1.1), never twice, and not
     * when the request has no content (its END_STREAM came with the head, or `content-length: 0`). Before, it went out only
     * when the application first read the body. Another expectation is answered 417 when the application reads.
     */
    private fun answerExpectation() {
        val expect = request.headers[HttpHeaders.Expect]?.lowercase() ?: return
        if (expect == "100-continue") {
            if (h2.contentLength != 0L && !h2.body.isClosedForRead) {
                runCatching { h2.respond(100) } // a stream that failed meanwhile fails the read that follows
            }
            return
        }
        val phase = PipelinePhase("H2ExpectedHeaderPhase")
        request.pipeline.insertPhaseBefore(ApplicationReceivePipeline.Before, phase)
        var sent = false
        request.pipeline.intercept(phase) {
            if (sent || response.isCommitted) return@intercept
            sent = true
            this@H2Call.respond(HttpStatusCode.ExpectationFailed)
        }
    }

    /** The call is over: the response's content has gone out (or failed), then the stream goes back to the connection. */
    suspend fun finish() {
        response.awaitContentSent()
    }

    companion object {
        /** HTTP/2 fields as Ktor headers; `:authority` becomes `Host`, split `cookie` fields one (RFC 9113 section 8.2.3). */
        fun toKtorHeaders(r: H2ServerStream): Headers {
            val b = HeadersBuilder()
            val cookies = ArrayList<String>()
            for ((n, v) in r.fields) if (n == "cookie") cookies += v else b.append(n, v)
            if (cookies.isNotEmpty()) b.append("cookie", cookies.joinToString("; "))
            if (b["host"] == null) r.authority?.let { b.append("host", it) }
            return b.build()
        }

        /** The method of [r] as Ktor's. */
        fun method(r: H2ServerStream): HttpMethod = HttpMethod.parse(r.method)
    }
}
