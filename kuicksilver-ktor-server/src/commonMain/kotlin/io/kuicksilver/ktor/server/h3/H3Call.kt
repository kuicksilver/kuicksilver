// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h3

import io.ktor.http.Headers
import io.ktor.http.HeadersBuilder
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.RequestConnectionPoint
import io.ktor.http.content.OutgoingContent
import io.ktor.http.parseQueryString
import io.ktor.http.withEmptyStringForValuelessKeys
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.Application
import io.ktor.server.application.PipelineCall
import io.ktor.server.engine.BaseApplicationCall
import io.ktor.server.engine.BaseApplicationRequest
import io.ktor.server.engine.BaseApplicationResponse
import io.ktor.server.request.ApplicationReceivePipeline
import io.ktor.server.request.RequestCookies
import io.ktor.server.request.encodeParameters
import io.ktor.server.response.ResponseHeaders
import io.ktor.server.response.respond
import io.ktor.util.cio.use
import io.ktor.util.pipeline.PipelinePhase
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3ResponseWriter
import io.kuicksilver.http3.Http3ServerRequest
import io.kuicksilver.ktor.server.EARLY_DATA_FIELD
import io.kuicksilver.ktor.server.PeerCertificatesKey
import io.kuicksilver.ktor.server.ReceivedEarlyKey
import io.kuicksilver.ktor.server.RequestPriorityKey
import io.kuicksilver.ktor.server.WebTransportRequestKey
import io.kuicksilver.ktor.server.WebTransportUpgrade
import io.kuicksilver.ktor.server.copyContentFrom
import io.kuicksilver.quic.ipLiteral
import io.kuicksilver.tls.Certificate
import kotlinx.coroutines.CoroutineScope
import kotlin.coroutines.CoroutineContext

/** One HTTP/3 request as a Ktor call: version "HTTP/3", the scheme from `:scheme` ("https" for a classic CONNECT), no Transfer-Encoding. */
internal class H3Call(
    application: Application,
    val h3: Http3ServerRequest,
    local: InetSocketAddress,
    peerCertificates: List<Certificate>,
    override val coroutineContext: CoroutineContext,
    engineDispatcher: CoroutineContext,
    userDispatcher: CoroutineContext,
    /** An Extended CONNECT for `websocket`: presented as Ktor's HTTP/1.1 upgrade request (RFC 9220). */
    webSocket: Boolean = false,
    /** A WebTransport CONNECT: a CONNECT call marked for `webTransport(path)` routes. */
    webTransport: Boolean = false,
    /** KuicksilverApplicationEngine.beforeH3UpgradeForTest. */
    beforeUpgradeForTest: (() -> Unit)? = null,
    /** The engine's `Alt-Svc` for a plain response, read as its head goes out (`clear` while HTTP/3 is withdrawn); null for none. */
    altSvc: () -> String? = { null },
) : BaseApplicationCall(application),
    CoroutineScope {
    override val request =
        H3Request(
            this,
            h3,
            local,
            if (webSocket) WebSocketOverH3.upgradeHeaders(h3) else toKtorHeaders(h3),
            if (webSocket) HttpMethod.Get else HttpMethod.parse(h3.method),
        )
    override val response: H3Response =
        if (webTransport) {
            H3WebTransportResponse(this, h3, beforeUpgradeForTest)
        } else if (webSocket) {
            H3UpgradeResponse(
                this,
                h3,
                engineDispatcher,
                userDispatcher,
                beforeUpgradeForTest,
            )
        } else {
            H3Response(this, h3, altSvc)
        }

    init {
        putResponseAttribute()
        if (webTransport) attributes.put(WebTransportRequestKey, h3)
        attributes.put(PeerCertificatesKey, peerCertificates)
        attributes.put(RequestPriorityKey, h3.priority)
        // in 0-RTT here, or forwarded from early data by a gateway (RFC 8470 section 5.1)
        val gatewayMarked = h3.headers[EARLY_DATA_FIELD.lowercase()] != null
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        if (h3.receivedEarly || gatewayMarked) attributes.put(ReceivedEarlyKey, true)
        if (!webSocket && !webTransport) answerExpectation()
    }

    /**
     * RFC 9110 section 10.1.1: `Expect: 100-continue` gets its interim 100 as the call starts (Http3Listener sends it, as on
     * HTTP/1.1 and HTTP/2), never twice. Another expectation is answered 417 when the application reads.
     */
    private fun answerExpectation() {
        val expect = request.headers[HttpHeaders.Expect]?.lowercase() ?: return
        if (expect == "100-continue") return
        val phase = PipelinePhase("H3ExpectedHeaderPhase")
        request.pipeline.insertPhaseBefore(ApplicationReceivePipeline.Before, phase)
        var sent = false
        request.pipeline.intercept(phase) {
            if (sent || response.isCommitted) return@intercept
            sent = true
            this@H3Call.respond(HttpStatusCode.ExpectationFailed)
        }
    }

    companion object {
        /** HTTP/3 fields as Ktor headers; `:authority` becomes `Host` (HTTP/1.1 routing and `host()` matchers rely on it). */
        fun toKtorHeaders(r: Http3ServerRequest): Headers {
            val b = HeadersBuilder()
            appendFields(b, r)
            if (b["host"] == null) r.authority?.let { b.append("host", it) }
            return b.build()
        }

        /** The request's fields into [b]; split `cookie` fields become one, joined with "; " (RFC 9114 section 4.2.1). */
        fun appendFields(
            b: HeadersBuilder,
            r: Http3ServerRequest,
        ) {
            val cookies = ArrayList<String>()
            for ((n, v) in r.headers.fields) if (n == "cookie") cookies += v else b.append(n, v)
            if (cookies.isNotEmpty()) b.append("cookie", cookies.joinToString("; "))
        }
    }
}

internal class H3Request(
    call: PipelineCall,
    private val h3: Http3ServerRequest,
    local: InetSocketAddress,
    override var engineHeaders: Headers,
    method: HttpMethod,
) : BaseApplicationRequest(call) {
    override val cookies: RequestCookies by lazy { RequestCookies(this) }
    override val engineReceiveChannel: ByteReadChannel get() = h3.body
    override val rawQueryParameters: Parameters by lazy {
        val uri =
            h3.path ?: ""
        val q = uri.indexOf('?')
        if (q <
            0
        ) {
            Parameters.Empty
        } else {
            parseQueryString(uri, startIndex = q + 1, decode = false)
        }
    }

    @OptIn(io.ktor.utils.io.InternalAPI::class)
    override val queryParameters: Parameters by lazy {
        encodeParameters(rawQueryParameters).withEmptyStringForValuelessKeys()
    } // as the CIO request: `?auto` gives ""
    override val local: RequestConnectionPoint = H3ConnectionPoint(h3, local, method)
}

@OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
internal class H3ConnectionPoint(
    private val h3: Http3ServerRequest,
    private val localAddr: InetSocketAddress,
    override val method: HttpMethod,
) : RequestConnectionPoint {
    /** The request's `:scheme` (`http` too, RFC 9114 section 3.1.2); `https` for a classic CONNECT, which has none. */
    override val scheme: String get() = h3.scheme ?: "https"
    override val version: String get() = "HTTP/3"
    override val uri: String get() = h3.path ?: "/"

    @Deprecated("Use localHost or serverHost instead")
    override val host: String get() = serverHost

    @Deprecated("Use localPort or serverPort instead")
    override val port: Int get() = serverPort
    override val localPort: Int get() = localAddr.port
    override val serverPort: Int get() = h3.authority?.let(::authorityPort) ?: defaultPort(h3.scheme)
    override val localHost: String get() = localAddr.ipLiteral()
    override val serverHost: String get() = h3.authority?.let(::authorityHost) ?: localHost
    override val localAddress: String get() = localAddr.ipLiteral()

    /** The client's address on the current path: it changes when the client migrates (RFC 9000 section 9). */
    override val remoteHost: String get() = h3.remoteAddress.ipLiteral() // the literal, not a reverse lookup per request
    override val remotePort: Int get() = h3.remoteAddress.port
    override val remoteAddress: String get() = h3.remoteAddress.ipLiteral()

    override fun toString(): String = "H3ConnectionPoint(uri=$uri, method=$method, remote=$remoteAddress:$remotePort)"
}

/** Connection-specific fields HTTP/3 forbids (RFC 9114 section 4.2) and `te`, a request-only field (RFC 9110 section 10.1.4): dropped from Ktor's response headers. */
private val HOP_BY_HOP = setOf("connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te")

internal open class H3Response(
    call: PipelineCall,
    protected val h3: Http3ServerRequest,
    /** The engine's `Alt-Svc` value, read as the head goes out; null for none. */
    private val altSvc: () -> String? = { null },
) : BaseApplicationResponse(call) {
    protected var statusCode: HttpStatusCode = HttpStatusCode.OK
    protected val headersBuilder = HeadersBuilder()
    private var writer: Http3ResponseWriter? = null

    /**
     * The request stream was given an answer (a response head, an accepted CONNECT or a WebTransport session) or ends on its
     * own: when a call is over without one, the engine resets the stream (handleHttp3).
     */
    internal var answered: Boolean = false

    override val headers =
        object : ResponseHeaders() {
            override fun engineAppendHeader(
                name: String,
                value: String,
            ) {
                headersBuilder.append(name, value)
            }

            override fun getEngineHeaderNames(): List<String> = headersBuilder.names().toList()

            override fun getEngineHeaderValues(name: String): List<String> = headersBuilder.getAll(name).orEmpty()
        }

    protected fun h3Headers(): Http3Headers =
        Http3Headers(
            buildList {
                for (name in headersBuilder.names()) {
                    val n = name.lowercase()
                    if (n in
                        HOP_BY_HOP
                    ) {
                        continue
                    }
                    for (v in headersBuilder.getAll(name)!!) add(n to v.trim { it == ' ' || it == '\t' })
                } // Ktor allows OWS around a value; HTTP/3 field values carry none (RFC 9110 section 5.5)
            },
        )

    private suspend fun start(): Http3ResponseWriter =
        writer ?: run {
            // an alternative is authoritative for its origin and may clear it (RFC 7838 section 2.2): the engine's `clear`
            // on every response that does not carry its own Alt-Svc, a 421 excepted, as on HTTP/1.1
            if (headersBuilder["Alt-Svc"] == null && statusCode.value != 421) altSvc()?.let { headersBuilder.append("Alt-Svc", it) }
            dropFramingFieldsOfAResponseWithoutContent()
            h3.respond(statusCode.value, h3Headers())
        }.also {
            writer = it
            answered = true
        }

    /**
     * A 204 has no Content-Length (RFC 9110 section 8.6); a 304 keeps one only when it is the length a 200 would have had,
     * which Ktor's `Content-Length: 0` for empty content does not say. As on HTTP/1.1 and HTTP/2.
     */
    private fun dropFramingFieldsOfAResponseWithoutContent() {
        when (statusCode.value) {
            204 -> headersBuilder.remove(HttpHeaders.ContentLength)
            304 -> if (headersBuilder.getAll(HttpHeaders.ContentLength) == listOf("0")) headersBuilder.remove(HttpHeaders.ContentLength)
        }
    }

    override suspend fun responseChannel(): ByteWriteChannel = start().output

    override suspend fun respondFromBytes(bytes: ByteArray) {
        val w = start()
        w.output.writeFully(bytes)
        w.finish()
    }

    override suspend fun respondNoContent(content: OutgoingContent.NoContent) {
        start().finish()
    }

    /**
     * A channel that failed cuts the response short (the stream is reset, RFC 9114 section 4.1.1), never ends it with a FIN
     * ([copyContentFrom]). A response without content (HEAD, 204, 304) does not read the channel: it ends after its head.
     */
    override suspend fun respondFromChannel(readChannel: ByteReadChannel) {
        val status = statusCode.value
        if (call.request.local.method == HttpMethod.Head || status == 204 || status == 304) {
            readChannel.cancel(null)
            start().finish()
            return
        }
        responseChannel().use { copyContentFrom(readChannel, headers[HttpHeaders.ContentLength]?.toLong()) }
    }

    override suspend fun respondUpgrade(upgrade: OutgoingContent.ProtocolUpgrade) {
        // An HTTP/1.1 upgrade has no meaning in HTTP/3 (RFC 9114 section 4.5); WebSockets come through Extended CONNECT instead.
        statusCode = HttpStatusCode.NotImplemented
        start().finish()
    }

    override fun setStatus(statusCode: HttpStatusCode) {
        this.statusCode = statusCode
    }
}

/**
 * The host of an RFC 3986 authority as kuicksilver-http3 admits it (`[ userinfo "@" ] host [ ":" port ]`, RFC 9114 section
 * 4.3.1): an IP literal keeps its brackets, and userinfo (allowed for schemes other than http and https) is not part of it.
 */
internal fun authorityHost(authority: String): String {
    val a = authority.substringAfterLast('@')
    return if (a.startsWith("[")) a.substringBefore("]") + "]" else a.substringBefore(':')
}

/** The port of an authority (see [authorityHost]), or null when it has none. */
internal fun authorityPort(authority: String): Int? {
    val a = authority.substringAfterLast('@')
    val hostEnd = if (a.startsWith("[")) a.indexOf(']') + 1 else a.indexOf(':').let { if (it < 0) a.length else it }
    return a.substring(hostEnd).removePrefix(":").toIntOrNull()
}

/** The default port of [scheme] (RFC 9110 sections 4.2.1, 4.2.2): 80 for `http`, else 443 (`https`, or none for a classic CONNECT). */
internal fun defaultPort(scheme: String?): Int = if (scheme == "http") 80 else 443

/** The response of a WebTransport call: the route's [WebTransportUpgrade] accepts the session and runs its handler. */
internal class H3WebTransportResponse(
    call: PipelineCall,
    h3: Http3ServerRequest,
    private val beforeUpgradeForTest: (() -> Unit)? = null,
) : H3Response(call, h3) {
    override suspend fun respondUpgrade(upgrade: OutgoingContent.ProtocolUpgrade) {
        if (upgrade !is WebTransportUpgrade) return super.respondUpgrade(upgrade)
        beforeUpgradeForTest?.invoke()
        // answered once acceptWebTransport has answered (the session's 200, or its own 400): an exception before that
        // leaves the stream to the engine's reset
        upgrade.acceptAndRun(h3, Http3Headers(h3Headers().fields.filter { it.first != "content-length" })) { answered = true }
    }

    /**
     * A 2xx that does not come from a `webTransport` route (another route on the path answered the CONNECT) would tell
     * the client a session exists that nobody accepted: it is answered 501 instead. Errors pass as they are.
     */
    override fun setStatus(statusCode: HttpStatusCode) {
        super.setStatus(if (statusCode.value in 200..299) HttpStatusCode.NotImplemented else statusCode)
    }
}
