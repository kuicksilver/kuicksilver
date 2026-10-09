// Copyright 2014-2021 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Vendored from Ktor 3.6.0 ktor-server-cio CIOApplicationRequest.kt (internal there), adapted: the scheme is the connector's.
package io.kuicksilver.ktor.server.h1

import io.ktor.http.Headers
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.Parameters
import io.ktor.http.RequestConnectionPoint
import io.ktor.http.URLProtocol
import io.ktor.http.cio.CIOHeaders
import io.ktor.http.cio.Request
import io.ktor.http.parseQueryString
import io.ktor.http.withEmptyStringForValuelessKeys
import io.ktor.server.application.PipelineCall
import io.ktor.server.engine.BaseApplicationRequest
import io.ktor.server.request.RequestCookies
import io.ktor.server.request.encodeParameters
import io.ktor.util.network.NetworkAddress
import io.ktor.util.network.address
import io.ktor.util.network.hostname
import io.ktor.util.network.port
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI

internal class H1Request(
    call: PipelineCall,
    remoteAddress: NetworkAddress?,
    localAddress: NetworkAddress?,
    private val input: ByteReadChannel,
    private val request: Request,
    scheme: String,
) : BaseApplicationRequest(call) {
    override val cookies: RequestCookies by lazy { RequestCookies(this) }

    override val engineReceiveChannel: ByteReadChannel = input

    override var engineHeaders: Headers = CIOHeaders(request.headers)

    @OptIn(InternalAPI::class)
    override val queryParameters: Parameters by lazy {
        encodeParameters(rawQueryParameters).withEmptyStringForValuelessKeys()
    }

    override val rawQueryParameters: Parameters by lazy {
        val uri = request.uri.toString()
        val queryStartIndex = uri.indexOf('?').takeIf { it != -1 } ?: return@lazy Parameters.Empty
        parseQueryString(uri, startIndex = queryStartIndex + 1, decode = false)
    }

    override val local: RequestConnectionPoint =
        H1ConnectionPoint(
            remoteAddress,
            localAddress,
            request.version.toString(),
            request.uri.toString(),
            request.headers[HttpHeaders.Host]?.toString(),
            HttpMethod.parse(request.method.value),
            scheme,
        )

    internal fun release() {
        request.release()
    }
}

internal class H1ConnectionPoint(
    private val remoteNetworkAddress: NetworkAddress?,
    private val localNetworkAddress: NetworkAddress?,
    override val version: String,
    override val uri: String,
    private val hostHeaderValue: String?,
    override val method: HttpMethod,
    override val scheme: String,
) : RequestConnectionPoint {
    private val defaultPort = URLProtocol.createOrDefault(scheme).defaultPort

    @Deprecated("Use localPort or serverPort instead")
    override val host: String
        get() =
            localNetworkAddress?.hostname
                ?: hostHeaderValue?.substringBefore(":")
                ?: "localhost"

    @Deprecated("Use localPort or serverPort instead")
    override val port: Int
        get() =
            localNetworkAddress?.port
                ?: hostHeaderValue?.substringAfter(":", defaultPort.toString())?.toInt()
                ?: defaultPort

    override val localPort: Int
        get() = localNetworkAddress?.port ?: defaultPort

    override val serverPort: Int
        get() =
            hostHeaderValue
                ?.substringAfterLast(":", defaultPort.toString())
                ?.toIntOrNull()
                ?: localPort

    override val localHost: String
        get() = localNetworkAddress?.hostname ?: "localhost"

    override val serverHost: String
        get() = hostHeaderValue?.substringBeforeLast(":") ?: localHost

    override val localAddress: String
        get() = localNetworkAddress?.address ?: "localhost"

    override val remoteHost: String
        get() = remoteNetworkAddress?.hostname ?: "unknown"

    override val remotePort: Int
        get() = remoteNetworkAddress?.port ?: 0

    override val remoteAddress: String
        get() = remoteNetworkAddress?.address ?: "unknown"

    override fun toString(): String =
        "H1ConnectionPoint(uri=$uri, method=$method, version=$version, localAddress=$localAddress, " +
            "localPort=$localPort, remoteAddress=$remoteAddress, remotePort=$remotePort)"
}
