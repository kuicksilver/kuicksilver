// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(DelicateKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.native.KslLoader
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class TrustConfigTest {
    private val pin = SpkiSha256(ByteArray(32) { 1 })
    private val noopVerifier = CertificateVerifier { _, _, _ -> VerifyResult.Accepted(emptyList()) }
    private val store =
        object : TofuStore {
            override suspend fun get(name: String): SpkiSha256? = null

            override suspend fun put(
                name: String,
                pin: SpkiSha256,
            ) {}
        }

    @Test fun pinnedWithTofuIsConfigError() {
        assertFailsWith<TlsException.Config> { TrustConfig.Pinned(setOf(pin), base = TrustConfig.Tofu(store)) }
    }

    @Test fun pinnedWithCustomIsConfigError() {
        assertFailsWith<TlsException.Config> { TrustConfig.Pinned(setOf(pin), base = TrustConfig.Custom(noopVerifier)) }
    }

    @Test fun pinnedNeedsPins() {
        assertFailsWith<IllegalArgumentException> { TrustConfig.Pinned(emptySet()) }
    }

    @Test fun expectedNameNeedsName() {
        assertFailsWith<IllegalArgumentException> { TrustConfig.ExpectedName(" ") }
    }

    @Test fun pinnedOverExpectedNameIsAllowed() {
        val t = TrustConfig.Pinned(setOf(pin), base = TrustConfig.ExpectedName("proxy.internal"))
        assertTrue(t.base is TrustConfig.ExpectedName)
    }

    /** These bases used to build fine and then fail every handshake ("unsupported ExpectedName base"); pins go outside: Pinned(base = ExpectedName(...)). */
    @Test fun expectedNameOverPinnedIsConfigError() {
        val ca = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa)))
        assertFailsWith<TlsException.Config> {
            TrustConfig.ExpectedName(
                "proxy.internal",
                base = TrustConfig.Pinned(setOf(pin), base = ca),
            )
        }
        assertFailsWith<TlsException.Config> { TrustConfig.ExpectedName("proxy.internal", base = TrustConfig.Pinned(setOf(pin))) }
        assertFailsWith<TlsException.Config> { TrustConfig.ExpectedName("proxy.internal", base = TrustConfig.Tofu(store)) }
        TrustConfig.ExpectedName("proxy.internal", base = ca)
        TrustConfig.ExpectedName("proxy.internal")
        TrustConfig.ExpectedName("proxy.internal", base = TrustConfig.Custom(noopVerifier))
    }

    @Test fun anchoredCaNeedsRoots() {
        assertFailsWith<IllegalArgumentException> { TrustConfig.AnchoredCa(emptyList()) }
    }
}

class SpkiSha256Test {
    @Test fun parseOkHttpFormatRoundTrip() {
        val p = SpkiSha256(ByteArray(32) { it.toByte() })
        assertEquals(p, SpkiSha256.parse(p.toString()))
        assertTrue(p.toString().startsWith("sha256/"))
    }

    @Test fun equalsByContent() {
        assertEquals(SpkiSha256(ByteArray(32) { 7 }), SpkiSha256(ByteArray(32) { 7 }))
        assertNotEquals(SpkiSha256(ByteArray(32) { 7 }), SpkiSha256(ByteArray(32) { 8 }))
    }

    @Test fun needs32Bytes() {
        assertFailsWith<IllegalArgumentException> { SpkiSha256(ByteArray(31)) }
    }

    @Test fun matchesOpenSslCli() {
        KslLoader.ensureLoaded()
        assertEquals(SpkiSha256(TestCerts.serverSpkiSha256), Certificate(TestCerts.server).spkiSha256)
    }
}

class HostNameTest {
    @Test fun lowercaseAndTrailingDot() {
        assertEquals("server.test", HostName.normalize("Server.TEST.").value)
    }

    @Test fun negative_nonAsciiHostRejected() {
        assertFailsWith<TlsException.Config> { HostName.normalize("bücher.example") }
    }

    @Test fun ipLiteralsDetected() {
        assertTrue(HostName.normalize("127.0.0.1").isIpLiteral)
        assertTrue(HostName.normalize("[::1]").isIpLiteral)
        assertEquals("::1", HostName.normalize("[::1]").value)
        assertFalse(HostName.normalize("a.b").isIpLiteral)
    }

    @Test fun wildcardNotAllowed() {
        assertFailsWith<TlsException.Config> { HostName.normalize("*.wild.test") }
    }

    @Test fun emptyRejected() {
        assertFailsWith<TlsException.Config> { HostName.normalize("") }
    }
}

class CertificateTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun parsesSanAndValidity() {
        val c = Certificate(TestCerts.server)
        assertEquals(listOf("server.test", "*.wild.test"), c.dnsNames)
        assertEquals(2, c.ipAddresses.size)
        assertContentEquals(byteArrayOf(127, 0, 0, 1), c.ipAddresses[0])
        assertTrue(c.notAfterEpochSeconds - c.notBeforeEpochSeconds > 99L * 365 * 86400, "100-year validity")
        assertTrue(Certificate(TestCerts.expired).notAfterEpochSeconds < 1_000_000_000L)
    }

    @Test fun cnOnlyHasNoNames() {
        val c = Certificate(TestCerts.serverCnOnly)
        assertTrue(c.dnsNames.isEmpty() && c.ipAddresses.isEmpty())
    }

    @Test fun garbageIsConfigError() {
        assertFailsWith<TlsException.Config> { Certificate(byteArrayOf(1, 2, 3)).dnsNames }
    }
}

class TlsConfigTest {
    @Test fun quicRequiresTls13Only() {
        val c =
            tlsConfig(TlsRole.Client) {
                versions = TlsVersions.Tls12And13
                alpn = listOf("h3")
            }
        assertFailsWith<TlsException.Config> { c.validateFor(quic = true) }
    }

    @Test fun ccm8RejectedInQuic() {
        val c =
            tlsConfig(TlsRole.Client) {
                cipherSuites = CipherSuites(listOf("TLS_AES_128_CCM_8_SHA256"))
                alpn =
                    listOf("h3")
            }
        ; assertFailsWith<TlsException.Config> { c.validateFor(quic = true) }
        c.validateFor(quic = false)
    }

    @Test fun emptyAlpnInQuicIsConfigError() {
        assertFailsWith<TlsException.Config> { tlsConfig(TlsRole.Client) { }.validateFor(quic = true) }
    }

    @Test fun serverPauseModesRejected() {
        KslLoader.ensureLoaded()
        val id = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
        for (t in listOf(TrustConfig.Platform, TrustConfig.Custom { _, _, _ -> VerifyResult.Accepted(emptyList()) })) {
            assertFailsWith<TlsException.Config> {
                tlsConfig(TlsRole.Server) {
                    identity =
                        id
                    ; clientAuth = ClientAuth.Required
                    trust = t
                }
            }
        }
        tlsConfig(TlsRole.Server) {
            identity = id
            clientAuth = ClientAuth.Required
            trust =
                TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa)))
        }
        tlsConfig(TlsRole.Server) {
            identity = id
            clientAuth = ClientAuth.Required
            trust =
                TrustConfig.Pinned(setOf(id.chain[0].spkiSha256), base = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa))))
        }
    }

    @Test fun serverNeedsIdentityOrSelector() {
        assertFailsWith<TlsException.Config> { tlsConfig(TlsRole.Server) { } }
    }

    @Test fun sessionTicketLimits() {
        assertFailsWith<TlsException.Config> { SessionTicketConfig(rotateEvery = kotlin.time.Duration.parse("8d")) }
        assertFailsWith<TlsException.Config> {
            SessionTicketConfig(rotateEvery = kotlin.time.Duration.parse("1d"), ticketLifetime = kotlin.time.Duration.parse("13h"))
        }
        assertFailsWith<TlsException.Config> { SessionTicketConfig(keys = listOf(ByteArray(10))) }
    }

    @Test fun clientServerNameIsValidated() {
        assertFailsWith<TlsException.Config> { tlsConfig(TlsRole.Client) { serverName = "bad host" } }
    }
}

class TlsIdentityTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun fromDerZeroesKeyAndKeepsChain() {
        val key = TestCerts.serverKey.copyOf()
        val id = TlsIdentity.fromDer(listOf(TestCerts.server), key)
        assertTrue(
            key.all {
                it ==
                    0.toByte()
            },
        )
        assertEquals(1, id.chain.size)
        id.close()
        assertTrue(id.isClosed)
        assertFailsWith<IllegalStateException> { id.withKey { } }
        id.close() // idempotent
    }

    @Test fun keyMismatchRejected() {
        assertFailsWith<TlsException.Config> { TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.clientKey.copyOf()) }
    }

    @Test fun emptyChainRejected() {
        assertFailsWith<TlsException.Config> { TlsIdentity.fromDer(emptyList(), TestCerts.serverKey.copyOf()) }
    }

    @Test fun fromPemRoundTrip() {
        val pem =
            TestCerts.toPem("CERTIFICATE", TestCerts.server) + TestCerts.toPem("CERTIFICATE", TestCerts.testCa)
        val key = TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey).toCharArray()
        val id = TlsIdentity.fromPem(pem, key)
        assertEquals(2, id.chain.size)
        assertTrue(key.all { it == '\u0000' })
        assertFailsWith<TlsException.Config> {
            TlsIdentity.fromPem(pem, TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey).toCharArray(), password = "x".toCharArray())
        }
    }
}
