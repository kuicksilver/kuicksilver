// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h3

import io.ktor.http.Headers
import io.ktor.http.HeadersBuilder
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
import io.ktor.server.request.RequestCookies
import io.ktor.server.request.encodeParameters
import io.ktor.server.response.ResponseHeaders
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3ResponseWriter
import io.kuicksilver.http3.Http3ServerRequest
import io.kuicksilver.ktor.server.PeerCertificatesKey
import io.kuicksilver.quic.ipLiteral
import io.kuicksilver.tls.Certificate
import kotlinx.coroutines.CoroutineScope
import kotlin.coroutines.CoroutineContext

/** One HTTP/3 request as a Ktor call: version "HTTP/3", scheme "https", no Transfer-Encoding. */
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
        if (webSocket) {
            H3UpgradeResponse(
                this,
                h3,
                engineDispatcher,
                userDispatcher,
            )
        } else {
            H3Response(this, h3)
        }

    init {
        putResponseAttribute()
        attributes.put(PeerCertificatesKey, peerCertificates)
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
    override val scheme: String get() = "https"
    override val version: String get() = "HTTP/3"
    override val uri: String get() = h3.path ?: "/"

    @Deprecated("Use localHost or serverHost instead")
    override val host: String get() = serverHost

    @Deprecated("Use localPort or serverPort instead")
    override val port: Int get() = serverPort
    override val localPort: Int get() = localAddr.port
    override val serverPort: Int get() = h3.authority?.substringAfterLast(":", "")?.toIntOrNull() ?: 443
    override val localHost: String get() = localAddr.ipLiteral()
    override val serverHost: String get() =
        h3.authority?.let { if (it.startsWith("[")) it.substringBefore("]") + "]" else it.substringBeforeLast(":") }
            ?: localHost
    override val localAddress: String get() = localAddr.ipLiteral()

    /** The client's address on the current path: it changes when the client migrates (RFC 9000 section 9). */
    override val remoteHost: String get() = h3.remoteAddress.ipLiteral() // the literal, not a reverse lookup per request
    override val remotePort: Int get() = h3.remoteAddress.port
    override val remoteAddress: String get() = h3.remoteAddress.ipLiteral()

    override fun toString(): String = "H3ConnectionPoint(uri=$uri, method=$method, remote=$remoteAddress:$remotePort)"
}

/** Connection-specific fields HTTP/3 forbids (RFC 9114 section 4.2): dropped from Ktor's response headers. */
private val HOP_BY_HOP = setOf("connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade")

internal open class H3Response(
    call: PipelineCall,
    protected val h3: Http3ServerRequest,
) : BaseApplicationResponse(call) {
    protected var statusCode: HttpStatusCode = HttpStatusCode.OK
    protected val headersBuilder = HeadersBuilder()
    private var writer: Http3ResponseWriter? = null

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

    private suspend fun start(): Http3ResponseWriter = writer ?: h3.respond(statusCode.value, h3Headers()).also { writer = it }

    override suspend fun responseChannel(): ByteWriteChannel = start().output

    override suspend fun respondFromBytes(bytes: ByteArray) {
        val w = start()
        w.output.writeFully(bytes)
        w.finish()
    }

    override suspend fun respondNoContent(content: OutgoingContent.NoContent) {
        start().finish()
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
