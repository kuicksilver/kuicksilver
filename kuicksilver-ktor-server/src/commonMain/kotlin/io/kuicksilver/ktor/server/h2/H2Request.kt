// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server.h2

import io.ktor.http.Headers
import io.ktor.http.HttpMethod
import io.ktor.http.Parameters
import io.ktor.http.RequestConnectionPoint
import io.ktor.http.parseQueryString
import io.ktor.http.withEmptyStringForValuelessKeys
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.PipelineCall
import io.ktor.server.engine.BaseApplicationRequest
import io.ktor.server.request.RequestCookies
import io.ktor.server.request.encodeParameters
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import io.kuicksilver.http2.runtime.H2ServerStream
import io.kuicksilver.ktor.server.h1.RequestBodyTimeout
import io.kuicksilver.ktor.server.h3.authorityHost
import io.kuicksilver.ktor.server.h3.authorityPort
import io.kuicksilver.ktor.server.h3.defaultPort
import io.kuicksilver.quic.ipLiteral
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.Source
import kotlin.time.Duration

internal class H2Request(
    call: PipelineCall,
    private val h2: H2ServerStream,
    local: InetSocketAddress?,
    remote: InetSocketAddress?,
    override var engineHeaders: Headers,
    bodyIdle: Duration,
) : BaseApplicationRequest(call) {
    override val cookies: RequestCookies by lazy { RequestCookies(this) }
    override val engineReceiveChannel: ByteReadChannel = IdleBoundedBody(h2.body, bodyIdle)

    override val rawQueryParameters: Parameters by lazy {
        val uri = h2.path
        val q = uri.indexOf('?')
        if (q < 0) Parameters.Empty else parseQueryString(uri, startIndex = q + 1, decode = false)
    }

    @OptIn(InternalAPI::class)
    override val queryParameters: Parameters by lazy {
        encodeParameters(rawQueryParameters).withEmptyStringForValuelessKeys()
    } // as the CIO request: `?auto` gives ""
    override val local: RequestConnectionPoint = H2ConnectionPoint(h2, local, remote, H2Call.method(h2))
}

internal class H2ConnectionPoint(
    private val h2: H2ServerStream,
    private val localAddr: InetSocketAddress?,
    private val remoteAddr: InetSocketAddress?,
    override val method: HttpMethod,
) : RequestConnectionPoint {
    /**
     * The connection's scheme, `https` (HTTP/2 runs only on TLS connectors), whatever the request's `:scheme` says: RFC
     * 9113 section 8.3.1 lets `:scheme` name another scheme (a gateway's request for an `http` URI, say), and Ktor's
     * connection point describes the connection, as on HTTP/1.1, where the scheme is the connector's too. The request's
     * own `:scheme` is not taken as proof that the request arrived secured or not.
     */
    override val scheme: String get() = "https"
    override val version: String get() = "HTTP/2"
    override val uri: String get() = h2.path.ifEmpty { "/" }

    @Deprecated("Use localHost or serverHost instead")
    override val host: String get() = serverHost

    @Deprecated("Use localPort or serverPort instead")
    override val port: Int get() = serverPort
    override val localPort: Int get() = localAddr?.port ?: 0
    override val serverPort: Int get() = h2.authority?.let(::authorityPort) ?: defaultPort(scheme)
    override val localHost: String get() = localAddr?.ipLiteral() ?: "localhost"
    override val serverHost: String get() = h2.authority?.let(::authorityHost) ?: localHost
    override val localAddress: String get() = localAddr?.ipLiteral() ?: "localhost"
    override val remoteHost: String get() = remoteAddr?.ipLiteral() ?: "unknown" // the literal, not a reverse lookup per request
    override val remotePort: Int get() = remoteAddr?.port ?: 0
    override val remoteAddress: String get() = remoteAddr?.ipLiteral() ?: "unknown"

    override fun toString(): String = "H2ConnectionPoint(uri=$uri, method=$method, remote=$remoteAddress:$remotePort)"
}

/**
 * A request body whose every wait for content has its own deadline, [idle], as on HTTP/1.1 (`connectionIdleTimeoutSeconds`):
 * a slow but moving upload is read in full, a client that stops sending fails the read with [RequestBodyTimeout] (answered
 * 408 when no response has started). Reading credits the client as the stream's own channel does.
 */
@OptIn(InternalAPI::class)
internal class IdleBoundedBody(
    private val delegate: ByteReadChannel,
    private val idle: Duration,
) : ByteReadChannel {
    override val closedCause: Throwable? get() = delegate.closedCause
    override val isClosedForRead: Boolean get() = delegate.isClosedForRead
    override val readBuffer: Source get() = delegate.readBuffer

    override suspend fun awaitContent(min: Int): Boolean {
        val r = withTimeoutOrNull(idle) { delegate.awaitContent(min) }
        // the stream stays: the call can still answer 408, and releasing it afterwards stops the client (RFC 9113 section 8.1)
        return r ?: throw RequestBodyTimeout(idle)
    }

    override fun cancel(cause: Throwable?) {
        delegate.cancel(cause)
    }
}
