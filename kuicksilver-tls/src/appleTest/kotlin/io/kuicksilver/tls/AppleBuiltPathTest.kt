// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.runBlocking
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * T.5b on Apple: under [TrustConfig.Platform] SecTrust decides, and the security level holds on the chain it built
 * (`SecTrustCopyCertificateChain`), not on every certificate the peer sent. The cross-certificate root is trusted the way a
 * configuration profile installs one ([PlatformVerifier.extraAnchorsForTest]); the leaf lives 800 days, so the evaluation
 * runs at a fixed date inside it.
 */
class AppleBuiltPathTest {
    @BeforeTest fun setUp() {
        KslLoader.ensureLoaded()
        PlatformVerifier.extraAnchorsForTest = listOf(WeakCerts.crossRoot)
        PlatformVerifier.verifyDateForTest = WeakCerts.crossVerifyAt
    }

    @AfterTest fun tearDown() {
        PlatformVerifier.extraAnchorsForTest = emptyList()
        PlatformVerifier.verifyDateForTest = null
    }

    private val presented = listOf(WeakCerts.leafViaCrossMid800d, WeakCerts.crossMid, WeakCerts.crossRootBySha1)

    /** L <- I <- R with an extra SHA-1 cross-certificate X for R: SecTrust's chain ends at R, so X does not count. */
    @Test fun platformAcceptsAWeakCrossCertificateOffItsPath() {
        val v =
            runBlocking {
                PlatformVerifier.evaluate(presented.map(::Certificate), HostName.normalize("server.test"), TlsRole.Client)
            }
        assertIs<VerifyResult.Accepted>(v.result, "SecTrust accepts the chain under its anchor")
        val path = assertNotNull(v.builtPath, "SecTrust's chain is read").map { it.encoded.toList() }
        assertEquals(listOf(WeakCerts.leafViaCrossMid800d, WeakCerts.crossMid, WeakCerts.crossRoot).map { it.toList() }, path)
        val o =
            weakHandshake(Fixtures.client(TrustConfig.Platform), presented, WeakCerts.leafViaCrossMid800dKey) { s, chain ->
                runBlocking { s.verifyPeer(chain) }
            }
        assertTrue(o.paused && o.done, "${(o.result as? DriveResult.Failed)?.exception}")
    }

    /**
     * RFC 9846 section 4.5.1.3: SecTrust refuses SHA-1- and MD5-signed certificates itself, reporting only that the chain is
     * not trusted; the refusal is still bad_certificate with the weak reason.
     */
    @Test fun negative_secTrustRefusalOfAWeakChainIsBadCertificate() {
        PlatformVerifier.extraAnchorsForTest = listOf(WeakCerts.rsaRoot, WeakCerts.weakRoot)
        for ((chain, key) in listOf(
            listOf(WeakCerts.leafMd5) to WeakCerts.leafMd5Key,
            listOf(WeakCerts.leafViaSha1, WeakCerts.midSha1) to WeakCerts.leafViaSha1Key,
        )) {
            val o = weakHandshake(Fixtures.client(TrustConfig.Platform), chain, key) { s, c -> runBlocking { s.verifyPeer(c) } }
            assertTrue(o.paused)
            val f = assertIs<DriveResult.Failed>(o.result)
            assertEquals(42, f.alert)
            assertEquals(VerifyReason.WeakSignature, assertIs<TlsException.Verify>(f.exception).reason)
        }
    }

    /** The same chain under a Custom verifier that trusts it: the presented chain counts, X with it. */
    @Test fun negative_customRefusesTheWeakCrossCertificate() {
        val o =
            weakHandshake(
                Fixtures.client(TrustConfig.Custom { c, _, _ -> VerifyResult.Accepted(c) }),
                presented,
                WeakCerts.leafViaCrossMid800dKey,
            )
        val f = assertIs<DriveResult.Failed>(o.result)
        assertEquals(42, f.alert)
        assertEquals(VerifyReason.WeakSignature, assertIs<TlsException.Verify>(f.exception).reason)
    }
}
