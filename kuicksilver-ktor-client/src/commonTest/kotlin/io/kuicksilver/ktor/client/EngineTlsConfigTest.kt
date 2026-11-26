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
     * ALPN and the server name belong to the request (`h3` or `http/1.1`, the URL's host): the `tls { }` block has neither
     * (a 0.2 block that set them made every HTTP/3 handshake fail on ALPN, or verified the certificate against another name).
     */
    @Test fun alpnAndServerNameComeFromTheRequest() {
        val tls = KuicksilverEngineConfig().tlsConfigFor("origin.example", listOf("h3"), quic = true)
        assertEquals(listOf("h3"), tls.alpn)
        assertEquals("origin.example", tls.serverName)
    }

    /** Every option of the `tls { }` block reaches the connection's TlsConfig. */
    @Test fun everyOptionOfTheBlockApplies() {
        val anchored = ClientFixtures.trust
        val suites = CipherSuites(listOf(CipherSuites.AES_256_GCM))
        val config =
            KuicksilverEngineConfig().apply {
                tls {
                    trust = anchored
                    versions = io.kuicksilver.tls.TlsVersions.Tls12And13
                    cipherSuites = suites
                    revocation = io.kuicksilver.tls.RevocationPolicy.Off
                    certificateCompression = false
                }
            }
        val built = config.tlsConfigFor("origin.example", listOf("http/1.1"), quic = false)
        assertSame(anchored, built.trust)
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls12And13, built.versions)
        assertSame(suites, built.cipherSuites)
        assertEquals(io.kuicksilver.tls.RevocationPolicy.Off, built.revocation)
        assertEquals(false, built.certificateCompression)
    }

    /**
     * QUIC is TLS 1.3 only (RFC 9001 section 4.2; the TLS layer refuses anything else for QUIC): the HTTP/3 configurations,
     * the origin's and a CONNECT-UDP proxy's, take `Tls13` whatever `tls { versions }` says, so `Tls12And13` (the engine's or a
     * proxy block's) never fails an HTTP/3 connection; the TCP ones keep the option.
     */
    @Test fun negative_quicConfigurationsAreTls13Only() {
        val config =
            KuicksilverEngineConfig().apply {
                tls { versions = io.kuicksilver.tls.TlsVersions.Tls12And13 }
                proxies { tls { versions = io.kuicksilver.tls.TlsVersions.Tls12And13 } }
            }
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls13, config.tlsConfigFor("origin.example", listOf("h3"), quic = true).versions)
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls12And13, config.tlsConfigFor("origin.example", listOf("h2"), quic = false).versions)
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls13, config.proxyTlsConfigFor("proxy.example", listOf("h3"), quic = true).versions)
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls12And13, config.proxyTlsConfigFor("proxy.example").versions)
        val inherited = KuicksilverEngineConfig().apply { tls { versions = io.kuicksilver.tls.TlsVersions.Tls12And13 } }
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls13, inherited.proxyTlsConfigFor("proxy.example", listOf("h3"), quic = true).versions)
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls12And13, inherited.proxyTlsConfigFor("proxy.example").versions)
    }
}
