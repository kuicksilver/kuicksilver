// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.runBlocking
import java.io.File
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** TrustConfig.Platform on the JVM: the default trust manager, pointed at a keystore holding the test CA via javax.net.ssl.trustStore. */
class PlatformTrustJvmTest {
    companion object {
        private val trustStore: File by lazy {
            val ks = KeyStore.getInstance("PKCS12")
            ks.load(null, null)
            ks.setCertificateEntry("test-ca", CertificateFactory.getInstance("X.509").generateCertificate(TestCerts.testCa.inputStream()))
            File.createTempFile("kuicksilver-trust", ".p12").also { f ->
                f.deleteOnExit()
                f.outputStream().use { ks.store(it, "changeit".toCharArray()) }
            }
        }
    }

    @BeforeTest fun setUp() {
        KslLoader.ensureLoaded()
        System.setProperty("javax.net.ssl.trustStore", trustStore.path)
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit")
        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12")
    }

    private fun handshake(
        client: TlsConfig,
        chain: List<ByteArray> = listOf(TestCerts.server),
        key: ByteArray = TestCerts.serverKey,
    ): Pair<Pump, DriveResult> {
        val p = Pump(KslQuicCrypto.newSession(client), KslQuicCrypto.newSession(Fixtures.server(chain, key)))
        p.c.setTransportParameters(Fixtures.tp)
        p.s.setTransportParameters(Fixtures.tp)
        val (rc, _) = p.run { want -> runBlocking { p.c.verifyPeer(want.chain) } }
        return p to rc
    }

    @Test fun platformAcceptsTrustStoreRoot() {
        val (p, _) = handshake(Fixtures.client(TrustConfig.Platform))
        try {
            assertTrue(p.cs.done && p.ss.done)
        } finally {
            p.close()
        }
    }

    @Test fun platformRejectsUnknownCaWithAlert48() {
        val (p, rc) = handshake(Fixtures.client(TrustConfig.Platform), listOf(TestCerts.serverOtherCa), TestCerts.serverOtherCaKey)
        try {
            val f = assertIs<DriveResult.Failed>(rc)
            assertEquals(48, f.alert)
            assertIs<VerifyReason.UnknownIssuer>((f.exception as TlsException.Verify).reason)
        } finally {
            p.close()
        }
    }

    @Test fun platformWithPinMismatchIsRejected() {
        val (p, rc) =
            handshake(
                Fixtures.client(TrustConfig.Pinned(setOf(Certificate(TestCerts.proxy).spkiSha256), base = TrustConfig.Platform)),
            )
        try {
            val f = assertIs<DriveResult.Failed>(rc)
            assertEquals(42, f.alert)
            assertIs<VerifyReason.PinMismatch>((f.exception as TlsException.Verify).reason)
        } finally {
            p.close()
        }
    }

    @Test fun negative_pinNotInValidatedChain() {
        // the server appends an unrelated certificate: it is presented, but no PKIX path to the trust store runs through it
        val pin =
            TrustConfig.Pinned(
                setOf(Certificate(TestCerts.proxy).spkiSha256),
                scope = PinScope.AnyInValidatedChain,
                base = TrustConfig.Platform,
            )
        val (p, rc) = handshake(Fixtures.client(pin), chain = listOf(TestCerts.server, TestCerts.proxy))
        try {
            val f = assertIs<DriveResult.Failed>(rc)
            assertIs<VerifyReason.PinMismatch>((f.exception as TlsException.Verify).reason)
        } finally {
            p.close()
        }
        val caPin =
            TrustConfig.Pinned(
                setOf(Certificate(TestCerts.testCa).spkiSha256),
                scope = PinScope.AnyInValidatedChain,
                base = TrustConfig.Platform,
            )
        val (p2, _) = handshake(Fixtures.client(caPin))
        try {
            assertTrue(p2.cs.done, "the anchor is part of the validated chain")
        } finally {
            p2.close()
        }
    }

    @Test fun platformNameMismatchIsRejectedByKsl() {
        val (p, rc) = handshake(Fixtures.client(TrustConfig.Platform, name = "wrong.test"))
        try {
            assertEquals(42, assertIs<DriveResult.Failed>(rc).alert)
        } finally {
            p.close()
        }
    }

    @Test fun fromTrustManagerStillChecksName() {
        val tm =
            object : X509TrustManager { // accepts everything: a typical "insecure" manager from old code
                override fun checkClientTrusted(
                    chain: Array<out X509Certificate>?,
                    authType: String?,
                ) {}

                override fun checkServerTrusted(
                    chain: Array<out X509Certificate>?,
                    authType: String?,
                ) {}

                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
        val (p1, _) = handshake(Fixtures.client(TrustConfig.fromTrustManager(tm)))
        try {
            assertTrue(p1.cs.done)
        } finally {
            p1.close()
        }
        val (p2, rc) = handshake(Fixtures.client(TrustConfig.fromTrustManager(tm), name = "wrong.test"))
        try {
            assertEquals(42, assertIs<DriveResult.Failed>(rc).alert)
        } finally {
            p2.close()
        }
    }
}
