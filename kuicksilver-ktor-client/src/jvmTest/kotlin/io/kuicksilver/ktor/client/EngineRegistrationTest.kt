// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.HttpClientEngineContainer
import java.util.ServiceLoader
import kotlin.test.Test
import kotlin.test.assertEquals

class EngineRegistrationTest {
    @Test fun serviceLoaderFindsEngine() {
        val containers = ServiceLoader.load(HttpClientEngineContainer::class.java).toList()
        val ours = containers.single { it.factory === Kuicksilver }
        assertEquals(0.5, ours.priority)
        HttpClient().use { assertEquals("Kuicksilver", it.engine.toString()) } // the only engine on this classpath
    }
}
