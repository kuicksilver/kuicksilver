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
 */
public data object Kuicksilver : HttpClientEngineFactory<KuicksilverEngineConfig> {
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
