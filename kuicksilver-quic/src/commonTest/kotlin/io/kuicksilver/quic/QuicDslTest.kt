// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.CipherSuites
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsVersions
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.time.Duration.Companion.seconds

/** QUIC config construction: TLS settings unusable for QUIC fail when the config is built, plus the DSL entry points. */
class QuicDslTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun clientBuildRejectsEmptyAlpn() {
        val tls = CoreFixtures.client { alpn = emptyList() }
        assertFailsWith<TlsException.Config> { QuicClientConfig.Builder(tls).build() }
    }

    @Test fun serverBuildRejectsTls12() {
        val tls = CoreFixtures.server { versions = TlsVersions.Tls12And13 }
        assertFailsWith<TlsException.Config> { QuicServerConfig.Builder(tls).build() }
    }

    @Test fun clientBuildRejectsCcm8() {
        val tls = CoreFixtures.client { cipherSuites = CipherSuites(listOf("TLS_AES_128_CCM_8_SHA256")) }
        assertFailsWith<TlsException.Config> { QuicClientConfig.Builder(tls).build() }
    }

    @Test fun serverBuildRejectsSniSelector() {
        val tls = CoreFixtures.server { sniSelector = { null } }
        assertFailsWith<TlsException.Config> { QuicServerConfig.Builder(tls).build() }
    }

    @Test fun validClientConfigBuilds() {
        assertEquals(
            listOf("hq-interop"),
            QuicClientConfig
                .Builder(CoreFixtures.client())
                .build()
                .tls.alpn,
        )
    }

    @Test fun clientDslAppliesQuicSettings() {
        val config = quicClientConfig(CoreFixtures.client()) { quic = quicConfig { maxIdleTimeout = 5.seconds } }
        assertEquals(5.seconds, config.quic.maxIdleTimeout)
        assertSame(QuicConfig.Default, quicClientConfig(CoreFixtures.client()).quic)
    }

    @Test fun serverDslKeepsTls() {
        val tls = CoreFixtures.server()
        assertSame(tls, quicServerConfig(tls).tls)
    }

    @Test fun endpointDslBuildsServerEndpoint() {
        val config =
            quicEndpointConfig {
                server = quicServerConfig(CoreFixtures.server())
                loops = 1
                maxConnectionsPerIp = 16
            }
        assertNotNull(config.server)
        assertEquals(16, config.maxConnectionsPerIp)
    }

    @Test fun endpointDslValidates() {
        assertFailsWith<IllegalArgumentException> { quicEndpointConfig { connectionIdLength = 3 } }
    }

    @Test fun clientDslRejectsServerTls() {
        assertFailsWith<IllegalArgumentException> { quicClientConfig(CoreFixtures.server()) }
    }
}
