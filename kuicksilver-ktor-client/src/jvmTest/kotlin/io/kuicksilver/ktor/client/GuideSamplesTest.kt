// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.plugins.HttpTimeout
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TrustConfig
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The client code blocks of docs/guide/ktor.md, kept compiling and running (block markers `guide:ktor:client*`). */
class GuideSamplesTest {
    @Test fun guideHasEveryMarker() {
        val guide =
            generateSequence(File("").absoluteFile) {
                it.parentFile
            }.map { File(it, "docs/guide/ktor.md") }.first { it.exists() }.readText()
        assertTrue("guide:ktor:client" in guide, "marker client")
    }

    @Test fun clientSample() {
        // guide:ktor:client
        val client =
            HttpClient(Kuicksilver) {
                engine {
                    trust =
                        TrustConfig.Pinned(
                            setOf(SpkiSha256.parse("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")),
                            base = TrustConfig.Platform,
                        )
                    http3 { discovery = Http3DiscoveryMode.Auto } // the default: HTTP/1.1 first, HTTP/3 after Alt-Svc
                }
                install(HttpTimeout) {
                    connectTimeoutMillis = 5_000
                    socketTimeoutMillis = 15_000
                }
            }
        client.use {
            val config = it.engine.config as KuicksilverEngineConfig
            assertTrue(config.trust is TrustConfig.Pinned)
            assertEquals(Http3DiscoveryMode.Auto, config.http3.discovery)
        }
    }
}
