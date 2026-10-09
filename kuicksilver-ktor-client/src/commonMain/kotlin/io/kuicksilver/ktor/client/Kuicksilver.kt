// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.HttpClientEngineFactory

/** `HttpClient(Kuicksilver) { engine { ... } }`: HTTP/3 with Alt-Svc discovery and HTTP/1.1 over TLS 1.3 on every platform (docs/guide/ktor.md). */
public data object Kuicksilver : HttpClientEngineFactory<KuicksilverEngineConfig> {
    override fun create(block: KuicksilverEngineConfig.() -> Unit): HttpClientEngine =
        KuicksilverEngine(KuicksilverEngineConfig().apply(block))
}
