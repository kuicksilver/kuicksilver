// Copyright 2014-2021 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Vendored from Ktor 3.6.0 ktor-server-cio CIOApplicationRequest.kt (internal there), adapted: the scheme is the connector's,
// and an IPv6 literal in the Host field keeps its brackets in `serverHost` (Ktor took everything before the last colon).
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

    /** The absolute-form's authority and origin-form, or null for another form of the request-target. */
    private val absoluteForm: Pair<String, String>? = splitAbsoluteForm(request.uri.toString())

    override val rawQueryParameters: Parameters by lazy {
        val uri = local.uri
        val queryStartIndex = uri.indexOf('?').takeIf { it != -1 } ?: return@lazy Parameters.Empty
        parseQueryString(uri, startIndex = queryStartIndex + 1, decode = false)
    }

    override val local: RequestConnectionPoint =
        H1ConnectionPoint(
            remoteAddress,
            localAddress,
            request.version.toString(),
            // absolute-form: routing sees its path and query, and the authority replaces Host, which the server MUST
            // ignore (RFC 9112 section 3.2.2)
            absoluteForm?.second ?: request.uri.toString(),
            absoluteForm?.first ?: request.headers[HttpHeaders.Host]?.toString(),
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

    /** The Host field split into `uri-host` and the port text after it, if any (RFC 9110 section 7.2). */
    private val hostAndPort: Pair<String, String?>? = hostHeaderValue?.let(::splitHostField)

    @Deprecated("Use localPort or serverPort instead")
    override val host: String
        get() =
            localNetworkAddress?.hostname
                ?: hostAndPort?.first
                ?: "localhost"

    @Deprecated("Use localPort or serverPort instead")
    override val port: Int
        get() =
            localNetworkAddress?.port
                ?: hostAndPort?.let { it.second?.toIntOrNull() ?: defaultPort }
                ?: defaultPort

    override val localPort: Int
        get() = localNetworkAddress?.port ?: defaultPort

    override val serverPort: Int
        get() =
            hostAndPort
                ?.let { (_, port) -> if (port == null) defaultPort else port.toIntOrNull() }
                ?: localPort

    override val localHost: String
        get() = localNetworkAddress?.hostname ?: "localhost"

    override val serverHost: String
        get() = hostAndPort?.first ?: localHost

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

/**
 * Splits a Host field value, `uri-host [ ":" port ]` (RFC 9110 section 7.2), into the host and the port text, if any. An
 * IP-literal (RFC 3986 section 3.2.2) keeps its brackets, as `serverHost` over HTTP/3 does: the colons inside it are
 * not a port separator.
 */
internal fun splitHostField(value: String): Pair<String, String?> {
    if (value.startsWith("[")) {
        val end = value.indexOf(']')
        if (end < 0) return value to null
        val rest = value.substring(end + 1)
        return value.substring(0, end + 1) to (if (rest.startsWith(":")) rest.substring(1) else null)
    }
    val colon = value.lastIndexOf(':')
    return if (colon < 0) value to null else value.substring(0, colon) to value.substring(colon + 1)
}

/**
 * Splits an "http" or "https" request-target in absolute-form (RFC 9112 section 3.2.2; the scheme is case-insensitive,
 * RFC 3986 section 3.1) into its authority, as is (it may be empty or carry userinfo: [RequestFraming] refuses both), and
 * its origin-form `absolute-path [ "?" query ]`, an empty path as "/" (RFC 9110 section 4.2.3). Null for an origin-form,
 * authority-form or asterisk-form target and for other schemes.
 */
internal fun splitAbsoluteForm(target: String): Pair<String, String>? {
    val start =
        when {
            target.startsWith("http://", ignoreCase = true) -> 7
            target.startsWith("https://", ignoreCase = true) -> 8
            else -> return null
        }
    val end = target.indexOfAny(charArrayOf('/', '?', '#'), start).let { if (it < 0) target.length else it }
    val rest = target.substring(end)
    val originForm = if (rest.startsWith("/")) rest else "/$rest"
    return target.substring(start, end) to originForm
}
