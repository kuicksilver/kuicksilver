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
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import io.kuicksilver.ktor.server.failureIsNoEnd
import io.kuicksilver.ktor.server.uriHost

internal class H1Request(
    call: PipelineCall,
    remoteAddress: H1Address?,
    localAddress: H1Address?,
    private val input: ByteReadChannel,
    private val request: Request,
    scheme: String,
    /** The request's fields as the client sent them ([requestFields]). */
    fields: Headers = CIOHeaders(request.headers),
) : BaseApplicationRequest(call) {
    override val cookies: RequestCookies by lazy { RequestCookies(this) }

    /** A body the connection cut short fails every read with the cause, as on HTTP/2 and HTTP/3 ([failureIsNoEnd]). */
    override val engineReceiveChannel: ByteReadChannel = input.failureIsNoEnd()

    override var engineHeaders: Headers = fields

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
            absoluteForm?.first ?: fields[HttpHeaders.Host],
            HttpMethod.parse(request.method.value),
            scheme,
        )

    internal fun release() {
        request.release()
    }
}

internal class H1ConnectionPoint(
    private val remoteEnd: H1Address?,
    private val localEnd: H1Address?,
    override val version: String,
    override val uri: String,
    private val hostHeaderValue: String?,
    override val method: HttpMethod,
    override val scheme: String,
) : RequestConnectionPoint {
    private val defaultPort = URLProtocol.createOrDefault(scheme).defaultPort

    /** The Host field split into `uri-host` and the port text after it, if any (RFC 9110 section 7.2). */
    private val hostAndPort: Pair<String, String?>? = hostHeaderValue?.let(::splitHostField)

    // as over HTTP/2 and HTTP/3 (and as Ktor's deprecation says): the server's name and port the request asked for
    @Deprecated("Use localHost or serverHost instead")
    override val host: String get() = serverHost

    @Deprecated("Use localPort or serverPort instead")
    override val port: Int get() = serverPort

    override val localPort: Int
        get() = localEnd?.port ?: defaultPort

    override val serverPort: Int
        get() =
            hostAndPort
                ?.let { (_, port) -> if (port.isNullOrEmpty()) defaultPort else port.toIntOrNull() }
                ?: localPort

    // the literals (TcpListener's toH1Address): `hostname` would look the name up (a reverse DNS query on the JVM and
    // Android)
    override val localHost: String
        get() = localEnd?.host ?: "localhost"

    // without a Host field the connection's address, an IPv6 one in brackets as a Host field writes it
    override val serverHost: String
        get() = hostAndPort?.first ?: uriHost(localHost)

    override val localAddress: String
        get() = localEnd?.host ?: "localhost"

    override val remoteHost: String
        get() = remoteEnd?.host ?: "unknown"

    override val remotePort: Int
        get() = remoteEnd?.port ?: 0

    override val remoteAddress: String
        get() = remoteEnd?.host ?: "unknown"

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
