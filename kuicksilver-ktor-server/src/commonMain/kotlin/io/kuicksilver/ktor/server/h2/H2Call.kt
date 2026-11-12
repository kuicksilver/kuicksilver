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
import io.kuicksilver.http2.runtime.PriorityPolicy
import io.kuicksilver.http3.message.PriorityField
import io.kuicksilver.ktor.server.EARLY_DATA_FIELD
import io.kuicksilver.ktor.server.PeerCertificatesKey
import io.kuicksilver.ktor.server.ReceivedEarlyKey
import io.kuicksilver.ktor.server.RequestPriorityKey
import io.kuicksilver.ktor.server.h1Priority
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.tls.Certificate
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalForInheritanceCoroutinesApi
import kotlinx.coroutines.flow.FlowCollector
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
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
    /** An Extended CONNECT for `websocket`: presented as Ktor's HTTP/1.1 upgrade request (RFC 8441, [WebSocketOverH2]). */
    webSocket: Boolean,
    engineDispatcher: CoroutineContext,
    userDispatcher: CoroutineContext,
    /** The engine's `webSocketMaxMessageSize`, for an Extended CONNECT for `websocket`. */
    webSocketMaxMessageSize: Long,
) : BaseApplicationCall(application),
    CoroutineScope {
    override val request =
        H2Request(
            this,
            h2,
            local,
            remote,
            if (webSocket) WebSocketOverH2.upgradeHeaders(h2) else toKtorHeaders(h2),
            bodyIdle,
            if (webSocket) HttpMethod.Get else method(h2),
            idleBounded = !webSocket,
        )
    override val response: H2Response =
        if (webSocket) {
            H2UpgradeResponse(this, h2, sendStallMillis, engineDispatcher, userDispatcher, webSocketMaxMessageSize)
        } else {
            H2Response(this, h2, sendStallMillis, altSvc)
        }

    init {
        putResponseAttribute()
        attributes.put(PeerCertificatesKey, peerCertificates)
        // the client's signal (RFC 9218): the Priority field, then each PRIORITY_UPDATE (section 7.1), one that came before
        // the request included (it overrides the field, section 7); the response's DATA goes by it (section 10) until the
        // response chose its own (section 8, [H2Response]); a CONNECT without a signal is a tunnel, incremental as on
        // HTTP/3 (sections 10.1, 11)
        val field = request.headers.getAll("Priority")
        val signal = ClientSignal(h1Priority(field).value)
        attributes.put(RequestPriorityKey, signal.flow)
        // an Extended CONNECT stream (a WebSocket over HTTP/2 with RFC 8441) carries a tunnel
        val p =
            if (h2.method == "CONNECT" && !PriorityField.isSignal(field?.joinToString(", "))) TUNNEL_PRIORITY else signal.flow.value
        h2.schedule(p.urgency, p.incremental, signal)
        // a gateway forwarded it from early data (RFC 8470 section 5.1)
        if (h2.fields.any { it.first == EARLY_DATA_FIELD.lowercase() }) {
            @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
            attributes.put(ReceivedEarlyKey, true)
        }
        if (!webSocket) answerExpectation()
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
        /** A tunnel's scheduling without a signal from its client: the default urgency, incremental (as on HTTP/3). */
        private val TUNNEL_PRIORITY = StreamPriority(3, incremental = true)

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

/**
 * The client's PRIORITY_UPDATEs as the HTTP/2 engine reads them (RFC 9218 section 7: "a complete set of all priority
 * parameters", a parameter left out meaning its default; a value that fails to parse means the defaults, as on HTTP/3),
 * and [flow], the signal the application sees. One state flow holds the latest signal with its order (seq) and only ever
 * moves to a newer one, so neither its value nor its collectors ever go back to an older signal, however the calls
 * interleave.
 */
internal class ClientSignal(
    initial: StreamPriority,
) : PriorityPolicy {
    internal class Latest(
        val seq: Long,
        val priority: StreamPriority,
    )

    internal val state = MutableStateFlow(Latest(-1, initial))
    val flow: StateFlow<StreamPriority> = PriorityView(state)

    override fun parse(value: String): Int = PriorityField.parse(value).let { it.urgency * 2 + if (it.incremental) 1 else 0 }

    override fun signal(
        urgency: Int,
        incremental: Boolean,
        seq: Long,
    ) {
        val next = Latest(seq, StreamPriority(urgency, incremental))
        while (true) {
            val cur = state.value
            if (cur.seq >= seq) return // a newer one is in already
            if (state.compareAndSet(cur, next)) return
        }
    }

    /** [state]'s priorities: the value at once, collectors without repeats. */
    @OptIn(ExperimentalForInheritanceCoroutinesApi::class)
    private class PriorityView(
        private val state: StateFlow<Latest>,
    ) : StateFlow<StreamPriority> {
        override val value: StreamPriority get() = state.value.priority
        override val replayCache: List<StreamPriority> get() = listOf(value)

        override suspend fun collect(collector: FlowCollector<StreamPriority>): Nothing {
            var last: StreamPriority? = null
            state.collect {
                if (it.priority != last) {
                    last = it.priority
                    collector.emit(it.priority)
                }
            }
        }
    }
}
