// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.plugins.HttpTimeoutCapability
import io.ktor.client.plugins.HttpTimeoutConfig
import io.ktor.client.plugins.SocketTimeoutException
import io.ktor.client.request.HttpRequestData
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.availableForRead
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.Source

/** Connect timeout of a request: `HttpTimeout`'s, else the engine's. */
internal fun HttpRequestData.connectTimeoutMillis(config: KuicksilverEngineConfig): Long =
    getCapabilityOrNull(HttpTimeoutCapability)?.connectTimeoutMillis?.takeIf { it != HttpTimeoutConfig.INFINITE_TIMEOUT_MS }
        ?: config.connectTimeout.inWholeMilliseconds

/** Request timeout of a request (`HttpTimeout`'s, which the plugin enforces itself), null for none. */
internal fun HttpRequestData.requestTimeoutMillis(): Long? =
    getCapabilityOrNull(HttpTimeoutCapability)?.requestTimeoutMillis?.takeIf { it != HttpTimeoutConfig.INFINITE_TIMEOUT_MS }

/** Socket (inactivity) timeout of a request, null for none. The request timeout itself belongs to the `HttpTimeout` plugin. */
internal fun HttpRequestData.socketTimeoutMillis(): Long? =
    getCapabilityOrNull(HttpTimeoutCapability)?.socketTimeoutMillis?.takeIf { it != HttpTimeoutConfig.INFINITE_TIMEOUT_MS }

/**
 * The TLS configuration of a connection to [host] with [alpn]: the same trust, pins and identity for HTTP/3 and its
 * HTTP/1.1 fallback (threat-model 3.18); SNI and verification use the origin's host.
 */
internal fun KuicksilverEngineConfig.tlsConfigFor(
    host: String,
    alpn: List<String>,
): TlsConfig =
    tlsConfig(TlsRole.Client) {
        trust = this@tlsConfigFor.trust
        identity = this@tlsConfigFor.identity
        tls()
        // the request decides these: another ALPN fails every handshake, another name verifies the wrong certificate
        this.alpn = alpn
        serverName = host
    }

/**
 * The trust an `https://` proxy gets by default: the origin's base trust without what names the origin. An
 * [TrustConfig.ExpectedName] replaces the origin's reference identifier, so on the proxy hop it would accept the
 * origin's certificate from whoever sits there (RFC 9525 section 6.1: the reference identifier is the name of the
 * service connected to, here the proxy's); a [TrustConfig.Pinned] lists the origin's keys, which the proxy does not
 * hold (curl's `--pinnedpubkey` is not applied to its proxy either). Both are taken off, recursively; the CA set, the
 * platform's store, a custom verifier and TOFU stay as configured.
 */
internal fun proxyTrustOf(trust: TrustConfig): TrustConfig =
    when (trust) {
        is TrustConfig.ExpectedName -> proxyTrustOf(trust.base)
        is TrustConfig.Pinned -> proxyTrustOf(trust.base)
        else -> trust
    }

/**
 * The TLS configuration of a connection to the proxy at [host] (ADR-0023): an `https://` proxy over TCP, or a CONNECT-UDP
 * proxy over QUIC. With
 * [KuicksilverEngineConfig.proxyTls] null: the engine's [KuicksilverEngineConfig.tls] block (versions, groups and the
 * like) over its [KuicksilverEngineConfig.trust], then the resulting trust through [proxyTrustOf], and no client
 * certificate (the origin's identity is not shown to the proxy). With a `proxyTls` block: the trust through
 * [proxyTrustOf] and no identity, then that block, which may replace both. Either way SNI and the reference identifier are
 * the proxy's host and ALPN is [alpn] alone (`http/1.1` over TCP, `h3` to a CONNECT-UDP proxy), set last.
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
internal fun KuicksilverEngineConfig.proxyTlsConfigFor(
    host: String,
    alpn: List<String> = listOf(PROXY_ALPN),
): TlsConfig =
    tlsConfig(TlsRole.Client) {
        val own = this@proxyTlsConfigFor.proxyTls
        if (own == null) {
            trust = this@proxyTlsConfigFor.trust
            tls()
            trust = proxyTrustOf(trust)
            identity = null
        } else {
            trust = proxyTrustOf(this@proxyTlsConfigFor.trust)
            identity = null
            own()
        }
        // HTTP/1.1 to an https:// proxy (CONNECT over HTTP/2, RFC 9113 section 8.5, is not offered: ADR-0023), h3 to a
        // CONNECT-UDP one
        this.alpn = alpn
        serverName = host
    }

internal const val PROXY_ALPN: String = "http/1.1"

/**
 * [delegate] with the request's socket timeout on every wait for data (as the CIO engine's socket timeout): a body that
 * stalls longer than [millis] fails with `SocketTimeoutException`. Reads go straight to [delegate]'s buffer, so wrapping
 * the connection input for one body never reads past it.
 */
@OptIn(InternalAPI::class)
internal class SocketTimeoutChannel(
    private val delegate: ByteReadChannel,
    private val millis: Long,
    private val request: HttpRequestData,
    /** Test hook: runs once a wait for data returned, still inside the socket timeout. */
    private val contentForTest: (suspend () -> Unit)? = null,
) : ByteReadChannel {
    override val closedCause: Throwable? get() = delegate.closedCause
    override val isClosedForRead: Boolean get() = delegate.isClosedForRead
    override val readBuffer: Source get() = delegate.readBuffer

    override suspend fun awaitContent(min: Int): Boolean {
        if (delegate.availableForRead >= min) return true
        // set as the wait returns: data that arrived as the timeout fires is read, though withTimeoutOrNull drops what the
        // wait returned when its timeout lands after it
        var arrived: Boolean? = null
        withTimeoutOrNull(millis) {
            arrived = delegate.awaitContent(min)
            contentForTest?.invoke()
        }
        arrived?.let { return it }
        val timeout = SocketTimeoutException(request, null)
        delegate.cancel(timeout)
        throw timeout
    }

    override fun cancel(cause: Throwable?) {
        delegate.cancel(cause)
    }
}

/** [this] with [request]'s socket timeout, if it has one. */
internal fun ByteReadChannel.withSocketTimeout(request: HttpRequestData): ByteReadChannel =
    request.socketTimeoutMillis()?.let { SocketTimeoutChannel(this, it, request) } ?: this

/**
 * The server answered an HTTP/2 request with HTTP_1_1_REQUIRED (RFC 9113 section 7), on its stream or for the whole
 * connection, after it may have processed it: a request that is not idempotent, or whose body cannot be sent again, is
 * not repeated over HTTP/1.1 by the engine (RFC 9110 section 9.2.2). The route (origin and proxy) now offers only
 * HTTP/1.1 (`FallbackReason.H2Refused`), so the application may send the request again and it goes over HTTP/1.1.
 * [cause][Http11RequiredException.cause] is the `Http2Exception` the server's answer produced.
 */
@io.kuicksilver.annotations.ExperimentalKuicksilverApi
public class Http11RequiredException(
    message: String,
    cause: Throwable? = null,
) : kotlinx.io.IOException(message, cause)

/**
 * The HTTP/3 attempt failed (or the alternative answered 421), or the server did not process an HTTP/2 request (GOAWAY,
 * REFUSED_STREAM) or asked for HTTP/1.1 (HTTP_1_1_REQUIRED), after the request's streamed body was consumed, so the
 * request cannot be repeated over HTTP/1.1 or on a new connection: the application decides whether to retry
 * with a body it can produce again. Bodies from bytes, from a writer or without content are replayed automatically.
 */
public class H3BodyConsumed(
    message: String,
    cause: Throwable? = null,
) : IllegalStateException(message, cause)

/**
 * An HTTP/3 request's connection stalled (docs/guide/ktor.md, "Stalled HTTP/3 connections"; `http3 { stallDetection }`):
 * the path stopped carrying packets — [probeTimeouts] probe timeouts in a row went unanswered (RFC 9002 section 6.2) and
 * nothing came back from the server for [silence], or, while the request waited on a 0-RTT connection, nothing came back
 * at all — as on a network that cuts UDP flows. The engine drained the connection and marked the HTTP/3 alternative broken
 * (RFC 7838 section 2.4). A request that may be repeated (an idempotent method, RFC 9110 section 9.2.2, a body that can be
 * sent again, no response yet) goes over TCP instead and never shows this exception, only `FallbackReason.QuicStalled`;
 * one that may not, and the read of a response body that was under way, wait up to `stallAbandonAfter` for the path to
 * come back and then fail with it, instead of at the connection's idle timeout (RFC 9000 section 10.1). [cause] is what
 * the request itself saw when the connection was closed, if anything.
 */
@io.kuicksilver.annotations.ExperimentalKuicksilverApi
public class QuicStalledException internal constructor(
    internal val stall: io.kuicksilver.ktor.client.h3.Stall,
    cause: Throwable?,
) : kotlinx.io.IOException(stallMessage(stall), cause) {
    /** How long nothing came back from the server when the stall was declared. */
    public val silence: kotlin.time.Duration get() = stall.silence

    /** The probe timeouts in a row without an acknowledgement then (RFC 9002 section 6.2). */
    public val probeTimeouts: Int get() = stall.probeTimeouts
}

private fun stallMessage(s: io.kuicksilver.ktor.client.h3.Stall): String =
    if (s.handshakeComplete) {
        "HTTP/3 connection stalled: no packet from the server for ${s.silence.inWholeMilliseconds} ms after " +
            "${s.probeTimeouts} probe timeouts in a row (UDP is likely cut on the path)"
    } else {
        "HTTP/3 connection stalled: no answer from the server for ${s.silence.inWholeMilliseconds} ms while the request " +
            "waited for the QUIC handshake (UDP is likely blocked on the path)"
    }
