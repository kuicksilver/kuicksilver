// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.HttpClientEngineFactory
import io.ktor.http.cio.HttpHeadersMap
import io.ktor.network.selector.SelectorManager
import io.ktor.utils.io.ByteReadChannel
import io.ktor.websocket.WebSocketSession
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.ktor.network.KtorVersionPolicy
import kotlin.reflect.KClass

/**
 * `HttpClient(Kuicksilver) { engine { ... } }`: HTTP/3 with Alt-Svc discovery and HTTP/1.1 over TLS 1.3 on every platform (docs/guide/ktor.md).
 * Creating the engine fails with [IllegalStateException] when the Ktor on the classpath is not the supported 3.6.x
 * (docs/guide/ktor.md, "Supported Ktor versions").
 *
 * `HttpClient.close()` returns at once and the engine closes its connections once the calls in flight finished.
 * `client.engine.coroutineContext.job.join()` first waits for every call in flight (a response body until it is read or
 * cancelled, a WebSocket or SSE session until it is closed), then for the pools, the UDP endpoints (every QUIC connection
 * on them and its qlog trace) and the selector to be closed. It has no bound of its own: wrap it in `withTimeout` where
 * an open body or session must not hold the exit (docs/guide/client.md, "Closing the client").
 */
public data object Kuicksilver : HttpClientEngineFactory<KuicksilverEngineConfig> {
    /** Creates an engine configured by [block]. */
    @OptIn(InternalKuicksilverApi::class)
    override fun create(block: KuicksilverEngineConfig.() -> Unit): HttpClientEngine {
        KtorVersionPolicy.check(*KTOR_ARTIFACTS.toTypedArray())
        return KuicksilverEngine(KuicksilverEngineConfig().apply(block))
    }
}

/**
 * The Ktor artifacts the client engine depends on beyond public API (docs/ktor-internal-api.md) or vendors code of, each
 * with a class it contains, for the startup version check: the client core and HTTP parser, the sockets (adapted on
 * Native, `kuicksilver-ktor-network`), the I/O channels (`readBuffer`) and the WebSocket session (`RawWebSocket`).
 */
internal val KTOR_ARTIFACTS: List<Pair<String, KClass<*>>> =
    listOf(
        "ktor-client-core" to HttpClient::class,
        "ktor-http-cio" to HttpHeadersMap::class,
        "ktor-network" to SelectorManager::class,
        "ktor-io" to ByteReadChannel::class,
        "ktor-websockets" to WebSocketSession::class,
    )
