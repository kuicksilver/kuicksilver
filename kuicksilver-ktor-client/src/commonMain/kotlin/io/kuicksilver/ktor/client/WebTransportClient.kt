// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class, io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.http.URLProtocol
import io.ktor.http.Url
import io.ktor.http.fullPath
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.http3.http3Request

/**
 * Opens a WebTransport session (draft-ietf-webtrans-http3-16) to [urlString], an `https` URL. Sessions share the
 * engine's pooled HTTP/3 connection to the URL's host and port with each other and with requests (RFC 9114 section 3.3:
 * one connection per address and port), as long as the server allows it: with WebTransport flow control on both sides
 * (draft-16 section 5.1) a connection carries up to `http3 { settings.webTransportMaxSessions }` sessions (4 by default)
 * and as many as the server accepts (section 5.2: a session it refuses with H3_REQUEST_REJECTED is opened again on
 * another connection to the same server, which the next sessions share too, unless none of this client's sessions was on
 * the refusing connection: that is the server's rate, and the refusal is thrown as
 * [io.kuicksilver.http3.Http3Exception.RequestNotProcessed]); without flow control a connection carries
 * one session, and each further one gets a connection of its own. A pooled connection that is not WebTransport-capable
 * (opened for requests without WebTransport's SETTINGS and `reset_stream_at`) is replaced by one that is, which carries
 * the origin's requests from then on; the old one finishes its requests and closes. A connection stays open while a
 * session or a request uses it, and then idles as any pooled connection does; an extra connection a server's limit
 * made closes with its last session. [protocols] are offered in `WT-Available-Protocols`; [headers] go with the CONNECT
 * (an `origin`, for a server that checks it).
 *
 * The engine's `connectTimeout` bounds the connection setup ([io.ktor.client.network.sockets.ConnectTimeoutException]); then
 * the server's SETTINGS and its answer to the CONNECT are waited for up to ten seconds each. A server without
 * WebTransport fails with [io.kuicksilver.http3.Http3Exception.Settings], a refusal with
 * [io.kuicksilver.http3.Http3Exception.ConnectRejected] (a 429 too: the server's own rate limit, section 5.2, is the
 * application's to handle); there is no fallback to HTTP/1.1 or HTTP/2, which carry no WebTransport here. When the
 * connection is lost, every session on it ends with the connection's reason ([WebTransportSession.closed]). Needs the
 * Kuicksilver engine (IllegalStateException otherwise) and an open client (IllegalStateException after `close()`).
 *
 * Refused with UnsupportedOperationException: under `http3 { discovery = H1Only }`, which turns HTTP/3 off, while
 * `http3 { http3Allowed }` returns false (read once per call; one that throws allows it), and when a proxy applies to the URL (WebTransport runs over UDP, which an HTTP proxy does not carry) unless
 * `http3 { webTransportIgnoresProxy = true }` asks to connect directly. At most `http3 { maxWebTransportSessions }`
 * (64) sessions are open at once on the client; one more fails at once with IllegalStateException.
 *
 * The connection goes straight to the URL's host and port: Alt-Svc is not consulted, and the CONNECT never goes in
 * 0-RTT. The resolved addresses are tried in order within the connect timeout. Closing the client ends the sessions
 * still open with their connections, without a close capsule; `HttpClient.closeHttp3Connections()` sends each open
 * session WT_DRAIN_SESSION and its connection a GOAWAY, asking the server to wind it down. A session still being set up
 * when it runs is drained as soon as it opens, or, when its CONNECT had not gone out yet, the call fails with
 * IllegalStateException naming `closeHttp3Connections()`.
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
    if (engine.config.http3.discovery == Http3DiscoveryMode.H1Only) {
        throw UnsupportedOperationException("WebTransport needs HTTP/3, which http3 { discovery = H1Only } turns off")
    }
    // the kill switch, as for H3Only requests: WebTransport has no TCP fallback, so it fails before any connection
    if (!engine.http3Allowed()) throw UnsupportedOperationException("WebTransport needs HTTP/3, which http3Allowed turns off")
    val viaConnectUdp =
        engine.config.connectUdpProxy
            ?.applies
            ?.invoke(url) == true
    if (viaConnectUdp && !engine.config.http3.webTransportIgnoresConnectUdpProxy) {
        throw UnsupportedOperationException(
            "WebTransport does not go through the CONNECT-UDP proxy that applies to ${url.host}: exempt the host with its " +
                "applies, or set http3 { webTransportIgnoresConnectUdpProxy = true } to connect directly",
        )
    }
    if (!engine.config.http3.webTransportIgnoresProxy && engine.effectiveProxyFor(url) != null) {
        throw UnsupportedOperationException(
            "WebTransport runs over UDP and cannot go through the proxy that applies to ${url.host}: exempt the host from the " +
                "proxy (the proxy's bypass list), configure no proxy for it, or set http3 { webTransportIgnoresProxy = true } " +
                "to connect directly",
        )
    }
    val host = if (':' in url.host && !url.host.startsWith("[")) "[${url.host}]" else url.host // an IPv6 literal
    val authority = if (url.port == URLProtocol.HTTPS.defaultPort) host else "$host:${url.port}"
    val request = http3Request("CONNECT", authority, url.fullPath.ifEmpty { "/" }) { this.headers = headers }
    return engine.h3.webTransport(url, request, protocols, engine.config.connectTimeout.inWholeMilliseconds)
}

/**
 * The proxy that applies to [url], or null for a direct connection: the one a request to [url] would go through, so
 * WebTransport refuses exactly the URLs a request sends through a proxy.
 */
internal suspend fun KuicksilverEngine.effectiveProxyFor(url: Url): ResolvedProxy? = proxyFor(url)
