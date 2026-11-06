// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.runBlocking
import java.io.File
import java.security.KeyStore
import java.security.cert.CertificateFactory
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * T.5b on the JVM: under [TrustConfig.Platform] the default trust manager decides (here pointed at a keystore of test roots
 * through `javax.net.ssl.trustStore`), and the security level holds on the path the decision rests on, rebuilt with the
 * JDK's PKIX builder, not on every certificate the peer sent. The JDK itself accepts a SHA-1-signed or 1024-bit intermediate
 * under a root outside its `cacerts` (`jdk.certpath.disabledAlgorithms` restricts SHA-1 to `jdkCA` anchors), so these
 * refusals are `ksl`'s.
 */
class PlatformBuiltPathJvmTest {
    private val saved = PROPERTIES.associateWith { System.getProperty(it) }

    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @AfterTest fun restore() {
        for ((k, v) in saved) if (v == null) System.clearProperty(k) else System.setProperty(k, v)
    }

    /** The default trust manager trusts exactly [roots] from now on. */
    private fun trust(vararg roots: ByteArray) {
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        val cf = CertificateFactory.getInstance("X.509")
        roots.forEachIndexed { i, r -> ks.setCertificateEntry("root-$i", cf.generateCertificate(r.inputStream())) }
        val f = File.createTempFile("kuicksilver-built-path", ".p12")
        f.deleteOnExit()
        f.outputStream().use { ks.store(it, "changeit".toCharArray()) }
        System.setProperty("javax.net.ssl.trustStore", f.path)
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit")
        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12")
    }

    /** A handshake whose pause runs the session's own trust: the real platform verifier, then the level on its path. */
    private fun handshake(
        trust: TrustConfig,
        chain: List<ByteArray>,
        key: ByteArray,
    ): WeakOutcome = weakHandshake(Fixtures.client(trust), chain, key) { s, presented -> runBlocking { s.verifyPeer(presented) } }

    private fun refused(
        o: WeakOutcome,
        reason: VerifyReason,
    ) {
        val f = assertIs<DriveResult.Failed>(o.result, "refused")
        assertEquals(42, f.alert)
        assertEquals(reason, assertIs<TlsException.Verify>(f.exception).reason)
    }

    private val crossPresented = listOf(WeakCerts.leafViaCrossMid, WeakCerts.crossMid, WeakCerts.crossRootBySha1)

    /** L <- I <- R with an extra SHA-1 cross-certificate X for R: the JDK's path ends at R, so X does not count. */
    @Test fun platformAcceptsAWeakCrossCertificateOffItsPath() {
        trust(WeakCerts.crossRoot)
        val v =
            runBlocking {
                PlatformVerifier.evaluate(crossPresented.map(::Certificate), HostName.normalize("server.test"), TlsRole.Client)
            }
        val path = assertNotNull(v.builtPath, "the JDK's path is rebuilt").map { it.encoded.toList() }
        assertEquals(listOf(WeakCerts.leafViaCrossMid, WeakCerts.crossMid, WeakCerts.crossRoot).map { it.toList() }, path)
        val o = handshake(TrustConfig.Platform, crossPresented, WeakCerts.leafViaCrossMidKey)
        assertTrue(o.paused && o.done, "${(o.result as? DriveResult.Failed)?.exception}")
    }

    /** The same chain under a Custom verifier that trusts it: the presented chain counts, X with it. */
    @Test fun negative_customRefusesTheWeakCrossCertificate() {
        trust(WeakCerts.crossRoot)
        refused(
            handshake(TrustConfig.fromTrustManager(JvmTrust.defaultTrustManager()), crossPresented, WeakCerts.leafViaCrossMidKey),
            VerifyReason.WeakSignature,
        )
    }

    /** A weak intermediate on the JDK's path is refused after the platform's yes. */
    @Test fun negative_platformRefusesAWeakIntermediateOnItsPath() {
        trust(WeakCerts.weakRoot)
        val sha1 = handshake(TrustConfig.Platform, listOf(WeakCerts.leafViaSha1, WeakCerts.midSha1), WeakCerts.leafViaSha1Key)
        assertTrue(sha1.paused, "the JDK was asked")
        refused(sha1, VerifyReason.WeakSignature)
        refused(
            handshake(TrustConfig.Platform, listOf(WeakCerts.leafViaRsa1024, WeakCerts.midRsa1024), WeakCerts.leafViaRsa1024Key),
            VerifyReason.WeakKey,
        )
        refused(handshake(TrustConfig.Platform, listOf(WeakCerts.leafRsa1024), WeakCerts.leafRsa1024Key), VerifyReason.WeakKey)
    }

    /** A SHA-1-signed intermediate the trust store holds is the anchor: its signature is not checked. */
    @Test fun platformDoesNotCheckItsAnchorsSignature() {
        trust(WeakCerts.midSha1)
        val o = handshake(TrustConfig.Platform, listOf(WeakCerts.leafViaSha1, WeakCerts.midSha1), WeakCerts.leafViaSha1Key)
        assertTrue(o.paused && o.done, "${(o.result as? DriveResult.Failed)?.exception}")
    }

    /**
     * RFC 9846 section 4.5.1.3: the JDK refuses an MD5-signed leaf and a P-192 intermediate itself (its algorithm
     * constraints), with no reason of its own for it; the refusal is still bad_certificate with the weak reason.
     */
    @Test fun negative_jdkRefusalOfAWeakChainIsBadCertificate() {
        trust(WeakCerts.rsaRoot, WeakCerts.weakRoot)
        val md5 = handshake(TrustConfig.Platform, listOf(WeakCerts.leafMd5), WeakCerts.leafMd5Key)
        assertTrue(md5.paused)
        refused(md5, VerifyReason.WeakSignature)
        refused(
            handshake(TrustConfig.Platform, listOf(WeakCerts.leafViaP192, WeakCerts.midP192), WeakCerts.leafViaP192Key),
            VerifyReason.WeakKey,
        )
    }

    /** The anchor's key counts: a 1024-bit root in the trust store is refused. */
    @Test fun negative_platformChecksItsAnchorsKey() {
        trust(WeakCerts.rsa1024Root)
        refused(
            handshake(TrustConfig.Platform, listOf(WeakCerts.leafUnderRsa1024Root), WeakCerts.leafUnderRsa1024RootKey),
            VerifyReason.WeakKey,
        )
    }

    private companion object {
        val PROPERTIES = listOf("javax.net.ssl.trustStore", "javax.net.ssl.trustStorePassword", "javax.net.ssl.trustStoreType")
    }
}
