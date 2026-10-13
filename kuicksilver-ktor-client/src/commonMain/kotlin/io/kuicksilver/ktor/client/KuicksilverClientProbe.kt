// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.engine.HttpClientEngine
import io.kuicksilver.annotations.InternalKuicksilverApi

/**
 * The client engine's table sizes for the soak harness (`kuicksilver-soak`): idle HTTP/1.1 connections and their keys,
 * cached TLS sessions, the HTTP/3 connection map, broken alternatives and remembered RTTs. The HTTP/3 endpoint's own
 * tables are in `QuicResourceProbe`.
 */
@InternalKuicksilverApi
public object KuicksilverClientProbe {
    /** Sizes of [engine]'s tables; empty when [engine] is not a Kuicksilver engine. */
    public suspend fun snapshot(engine: HttpClientEngine): Map<String, Long> = (engine as? KuicksilverEngine)?.probeSizes() ?: emptyMap()
}
