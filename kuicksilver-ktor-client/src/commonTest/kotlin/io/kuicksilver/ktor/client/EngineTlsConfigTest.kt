// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.CipherSuites
import io.kuicksilver.tls.TrustConfig
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame

/** How `engine { tls { } }` combines with what the engine sets per request. */
class EngineTlsConfigTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * ALPN and the server name belong to the request (`h3` or `http/1.1`, the URL's host): a `tls {}` block that set them
     * made every HTTP/3 handshake fail on ALPN, or verified the certificate against another name (docs review before 0.2.0).
     */
    @Test fun alpnAndServerNameComeFromTheRequest() {
        val config =
            KuicksilverEngineConfig().apply {
                tls = {
                    alpn = listOf("bogus")
                    serverName = "other.example"
                }
            }
        val tls = config.tlsConfigFor("origin.example", listOf("h3"))
        assertEquals(listOf("h3"), tls.alpn)
        assertEquals("origin.example", tls.serverName)
    }

    /** Everything else the block sets is kept, the engine's trust and identity included when the block replaces them. */
    @Test fun otherSettingsOfTheBlockApply() {
        val anchored = ClientFixtures.trust
        val config =
            KuicksilverEngineConfig().apply {
                trust = TrustConfig.Platform
                tls = {
                    trust = anchored
                    cipherSuites = CipherSuites.Default
                }
            }
        assertSame(anchored, config.tlsConfigFor("origin.example", listOf("http/1.1")).trust)
    }
}
