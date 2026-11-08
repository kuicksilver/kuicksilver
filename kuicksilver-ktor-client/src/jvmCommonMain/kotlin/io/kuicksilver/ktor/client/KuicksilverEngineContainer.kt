// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.HttpClientEngineContainer
import io.ktor.client.engine.HttpClientEngineFactory

/**
 * Lets `HttpClient()` find the engine through ServiceLoader on the JVM. Priority 0.5: below the 1.0 of OkHttp
 * and the platform engines, so the choice stays deterministic when several are on the classpath; above CIO (0.0).
 */
public class KuicksilverEngineContainer : HttpClientEngineContainer {
    /** The factory of the Kuicksilver engine. */
    override val factory: HttpClientEngineFactory<*> = Kuicksilver

    /** 0.5: below OkHttp and the platform engines (1.0), above CIO (0.0). */
    override val priority: Double get() = 0.5

    /** The name of the engine. */
    override fun toString(): String = "Kuicksilver"
}
