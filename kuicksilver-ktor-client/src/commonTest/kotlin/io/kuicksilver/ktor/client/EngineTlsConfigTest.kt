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
                    versions = io.kuicksilver.tls.TlsVersions.Tls13
                    cipherSuites = suites
                    revocation = io.kuicksilver.tls.RevocationPolicy.Off
                    certificateCompression = false
                }
            }
        val built = config.tlsConfigFor("origin.example", listOf("http/1.1"), quic = false)
        assertSame(anchored, built.trust)
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls13, built.versions)
        assertSame(suites, built.cipherSuites)
        assertEquals(io.kuicksilver.tls.RevocationPolicy.Off, built.revocation)
        assertEquals(false, built.certificateCompression)
    }

    /**
     * QUIC is TLS 1.3 only (RFC 9001 section 4.2; the TLS layer refuses anything else for QUIC): the HTTP/3 configurations,
     * the origin's and a CONNECT-UDP proxy's, take `Tls13` whatever `tls { versions }` says, so the default `Tls12And13` (or
     * a proxy block's) never fails an HTTP/3 connection; the TCP ones keep the option.
     */
    @Test fun negative_quicConfigurationsAreTls13OnlyUnderTheDefault() {
        val config = KuicksilverEngineConfig().apply { proxies { tls { versions = io.kuicksilver.tls.TlsVersions.Tls12And13 } } }
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls12And13, config.tls.versions)
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls13, config.tlsConfigFor("origin.example", listOf("h3"), quic = true).versions)
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls13, config.proxyTlsConfigFor("proxy.example", listOf("h3"), quic = true).versions)
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls12And13, config.proxyTlsConfigFor("proxy.example").versions)
        val inherited = KuicksilverEngineConfig()
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls13, inherited.proxyTlsConfigFor("proxy.example", listOf("h3"), quic = true).versions)
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls12And13, inherited.proxyTlsConfigFor("proxy.example").versions)
    }

    /**
     * The default offers TLS 1.2 next to 1.3 over TCP (and the QUIC side ignores it, RFC 9001 section 4.2); key-exchange groups
     * TLS 1.2 cannot use (no elliptic curve: TLS 1.2 has no hybrid) then fail the engine's creation, with what to change,
     * instead of every request; with `versions = Tls13` the same groups are taken.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun negative_groupsWithoutACurveNeedTls13Only() {
        assertEquals(
            io.kuicksilver.tls.TlsVersions.Tls12And13,
            KuicksilverEngineConfig().tlsConfigFor("origin.example", listOf("h2", "http/1.1"), quic = false).versions,
        )
        val hybridOnly = io.kuicksilver.tls.KeyExchangeGroups(listOf(io.kuicksilver.tls.KeyExchangeGroups.X25519MLKEM768))
        val e =
            kotlin.test.assertFailsWith<IllegalArgumentException> {
                io.ktor.client
                    .HttpClient(Kuicksilver) { engine { tls { keyExchangeGroups = hybridOnly } } }
                    .close()
            }
        kotlin.test.assertTrue("Tls12And13" in e.message.orEmpty() && "tls { }" in e.message.orEmpty(), e.message)
        io.ktor.client
            .HttpClient(Kuicksilver) {
                engine {
                    tls {
                        versions = io.kuicksilver.tls.TlsVersions.Tls13
                        keyExchangeGroups = hybridOnly
                    }
                }
            }.close()
        // with H3Only no TLS goes over TCP: QUIC is TLS 1.3 only, so the same groups are taken under the default
        io.ktor.client
            .HttpClient(Kuicksilver) {
                engine {
                    http3 { discovery = Http3Discovery.H3Only }
                    tls { keyExchangeGroups = hybridOnly }
                }
            }.close()
    }

    /**
     * RFC 9113 section 9.2.2: HTTP/2 over TLS 1.2 needs TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 with P-256, so a client that
     * offers h2 with TLS 1.2 allowed (the default) keeps secp256r1: groups without it fail the engine's creation, naming the
     * option; with `versions = Tls13` or `http2 { enabled = false }` they are taken.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun negative_h2OverTls12NeedsP256() {
        val noP256 =
            io.kuicksilver.tls.KeyExchangeGroups(
                listOf(io.kuicksilver.tls.KeyExchangeGroups.X25519, io.kuicksilver.tls.KeyExchangeGroups.SECP384R1),
            )
        val e =
            kotlin.test.assertFailsWith<IllegalArgumentException> {
                io.ktor.client
                    .HttpClient(Kuicksilver) { engine { tls { keyExchangeGroups = noP256 } } }
                    .close()
            }
        kotlin.test.assertTrue("tls { keyExchangeGroups }" in e.message.orEmpty() && "secp256r1" in e.message.orEmpty(), e.message)
        io.ktor.client
            .HttpClient(Kuicksilver) {
                engine {
                    tls {
                        versions = io.kuicksilver.tls.TlsVersions.Tls13
                        keyExchangeGroups = noP256
                    }
                }
            }.close()
        io.ktor.client
            .HttpClient(Kuicksilver) {
                engine {
                    http2 { enabled = false }
                    tls { keyExchangeGroups = noP256 }
                }
            }.close()
    }

    /**
     * Every refusal of a TLS block happens when the engine is created: a `proxies { tls { } }` block that TLS 1.2 cannot use
     * (key-exchange groups without a curve under its default `Tls12And13`) fails it, naming the block, as the engine's own
     * `tls { }` does; with `versions = Tls13` in it, it is taken.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun negative_proxyTlsBlockIsCheckedWhenTheEngineIsCreated() {
        val hybridOnly = io.kuicksilver.tls.KeyExchangeGroups(listOf(io.kuicksilver.tls.KeyExchangeGroups.X25519MLKEM768))
        val e =
            kotlin.test.assertFailsWith<IllegalArgumentException> {
                io.ktor.client
                    .HttpClient(Kuicksilver) { engine { proxies { tls { keyExchangeGroups = hybridOnly } } } }
                    .close()
            }
        kotlin.test.assertTrue("proxies { tls { } }" in e.message.orEmpty() && "Tls13" in e.message.orEmpty(), e.message)
        io.ktor.client
            .HttpClient(Kuicksilver) {
                engine {
                    proxies {
                        tls {
                            versions = io.kuicksilver.tls.TlsVersions.Tls13
                            keyExchangeGroups = hybridOnly
                        }
                    }
                }
            }.close()
    }
}
