// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.http.URLProtocol
import io.ktor.http.Url
import io.ktor.http.fullPath
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.webTransportOwningConnection
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/**
 * Opens a WebTransport session (draft-ietf-webtrans-http3-16) to [urlString], an `https` URL, on a QUIC connection of
 * its own: like a browser, each session gets a dedicated HTTP/3 connection outside the engine's pool (without
 * WebTransport flow control a connection carries one session), and the connection closes once the session ended in
 * both directions. [protocols] are offered in `WT-Available-Protocols`; [headers] go with the CONNECT (an `origin`, for
 * a server that checks it).
 *
 * The engine's `connectTimeout` bounds the connection setup ([io.ktor.client.network.sockets.ConnectTimeoutException]); then
 * the server's SETTINGS and its answer to the CONNECT are waited for up to ten seconds each. A server without
 * WebTransport fails with [io.kuicksilver.http3.Http3Exception.Settings], a refusal with
 * [io.kuicksilver.http3.Http3Exception.ConnectRejected]; there is no fallback to HTTP/1.1 or HTTP/2, which carry no
 * WebTransport here. Needs the Kuicksilver engine (IllegalStateException otherwise) and no proxy: the session needs a
 * direct UDP path (IllegalStateException when the engine has a proxy).
 */
@ExperimentalKuicksilverApi
public suspend fun HttpClient.webTransport(
    urlString: String,
    protocols: List<String> = emptyList(),
    headers: Http3Headers = Http3Headers.Empty,
): WebTransportSession {
    val engine =
        engine as? KuicksilverEngine
            ?: throw IllegalStateException("webTransport needs the Kuicksilver engine, not ${engine::class.simpleName}")
    val url = Url(urlString)
    require(url.protocol == URLProtocol.HTTPS) { "WebTransport needs an https URL, not ${url.protocol.name}" }
    check(engine.config.proxy == null) { "WebTransport needs a direct UDP path to the server; the engine has a proxy" }
    val connection = engine.h3.dedicated(url.host, url.port, engine.config.connectTimeout.inWholeMilliseconds)
    try {
        val host = if (':' in url.host && !url.host.startsWith("[")) "[${url.host}]" else url.host // an IPv6 literal
        val authority = if (url.port == URLProtocol.HTTPS.defaultPort) host else "$host:${url.port}"
        val request = http3Request("CONNECT", authority, url.fullPath.ifEmpty { "/" }) { this.headers = headers }
        return connection.webTransportOwningConnection(request, protocols)
    } catch (e: Throwable) {
        // no session: the connection opened for it goes too
        withContext(NonCancellable) { runCatching { connection.close(Http3ErrorCode.NO_ERROR, "") } }
        throw e
    }
}
