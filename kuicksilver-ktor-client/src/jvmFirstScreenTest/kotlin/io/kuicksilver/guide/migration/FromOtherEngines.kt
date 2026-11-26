// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// The client code of docs/guide/migrating-ktor-engines.md, compiled with no opt-in and warnings as errors.
package io.kuicksilver.guide.migration

import io.ktor.client.HttpClient
import io.ktor.client.plugins.HttpTimeout
import io.kuicksilver.ktor.client.Kuicksilver

internal fun swappedClient(): HttpClient {
    // guide:engines:client
    val client =
        HttpClient(Kuicksilver) {
            install(HttpTimeout) { requestTimeoutMillis = 15_000 }
        }
    return client
}
