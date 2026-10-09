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
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout
import kotlinx.io.Source

/** Connect timeout of a request: `HttpTimeout`'s, else the engine's. */
internal fun HttpRequestData.connectTimeoutMillis(config: KuicksilverEngineConfig): Long =
    getCapabilityOrNull(HttpTimeoutCapability)?.connectTimeoutMillis?.takeIf { it != HttpTimeoutConfig.INFINITE_TIMEOUT_MS }
        ?: config.connectTimeout.inWholeMilliseconds

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
        this.alpn = alpn
        serverName = host
        trust = this@tlsConfigFor.trust
        identity = this@tlsConfigFor.identity
        tls()
    }

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
) : ByteReadChannel {
    override val closedCause: Throwable? get() = delegate.closedCause
    override val isClosedForRead: Boolean get() = delegate.isClosedForRead
    override val readBuffer: Source get() = delegate.readBuffer

    override suspend fun awaitContent(min: Int): Boolean {
        if (delegate.availableForRead >= min) return true
        return try {
            withTimeout(millis) { delegate.awaitContent(min) }
        } catch (e: TimeoutCancellationException) {
            val timeout = SocketTimeoutException(request, e)
            delegate.cancel(timeout)
            throw timeout
        }
    }

    override fun cancel(cause: Throwable?) {
        delegate.cancel(cause)
    }
}

/** [this] with [request]'s socket timeout, if it has one. */
internal fun ByteReadChannel.withSocketTimeout(request: HttpRequestData): ByteReadChannel =
    request.socketTimeoutMillis()?.let { SocketTimeoutChannel(this, it, request) } ?: this

/**
 * The HTTP/3 attempt failed (or the alternative answered 421) after the request's streamed body was consumed, so the
 * request cannot be repeated over HTTP/1.1 or on a new connection: the application decides whether to retry
 * with a body it can produce again. Bodies from bytes, from a writer or without content are replayed automatically.
 */
public class H3BodyConsumed(
    message: String,
    cause: Throwable? = null,
) : IllegalStateException(message, cause)
