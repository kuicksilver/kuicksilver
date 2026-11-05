// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslEvent
import io.kuicksilver.native.KslLoader
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * OpenSSL security level 2 (112 bits) on the peer's chain under every trust (T.5): under [TrustConfig.Platform] the JDK,
 * Android and Windows verifiers accept 1024-bit RSA, so `ksl` checks the chain the peer sent before the platform is asked,
 * with the same verdicts as OpenSSL's own path ([TrustConfig.AnchoredCa]). The certificates come from
 * `tools/certs/gen-weak-certs.sh`.
 */
class ChainSecurityLevelTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private class Outcome(
        val result: DriveResult,
        val paused: Boolean,
        val done: Boolean,
    )

    private val weakRoot = Certificate(WeakCerts.weakRoot)

    /**
     * A handshake of a real client session against a raw `ksl` server at security level 0 (at the default level 2 OpenSSL
     * refuses to load a weak key as its own identity). A pause is answered with the platform's yes, so that only `ksl`'s
     * own checks can refuse the chain.
     */
    private fun handshake(
        client: TlsConfig,
        chain: List<ByteArray>,
        key: ByteArray,
    ): Outcome {
        val sc = Ksl.ctxNew(KslConst.SERVER)
        var s = 0L
        val c = KslQuicCrypto.newSession(client)
        val keys = ArrayList<Long>()
        val protectors = ArrayList<PacketProtector>()
        try {
            Ksl.ctxSetAlpn(sc, byteArrayOf(2, 'h'.code.toByte(), '3'.code.toByte()))
            Ksl.ctxSetCiphers(sc, null, "@SECLEVEL=0:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256")
            Ksl.ctxSetIdentity(sc, chain, key.copyOf())
            s = Ksl.sslNew(sc, KslConst.MODE_QUIC)
            Ksl.quicSetTransportParams(s, Fixtures.tp)
            c.setTransportParameters(Fixtures.tp)
            val ev = KslEvent()
            var paused = false
            var clientDone = false
            var serverDone = false
            var last: DriveResult = DriveResult.WantRead
            repeat(40) {
                last = c.drive()
                val want = last
                if (want is DriveResult.WantVerify) {
                    paused = true
                    c.resumeVerify(VerifyResult.Accepted(want.chain))
                    last = c.drive()
                }
                while (true) {
                    when (val e = c.nextEvent() ?: break) {
                        is TlsEvent.CryptoData -> {
                            Ksl.quicProvide(s, e.level.ksl, e.data, 0, e.data.size)
                        }

                        is TlsEvent.Keys -> {
                            protectors += e.protector
                        }

                        TlsEvent.HandshakeDone -> {
                            clientDone = true
                        }

                        else -> {}
                    }
                }
                if (last is DriveResult.Failed) return Outcome(last, paused, false)
                Ksl.drive(s)
                while (Ksl.quicNextEvent(s, ev)) {
                    when (ev.type) {
                        KslConst.EV_CRYPTO_SEND -> c.provide(EncryptionLevel.entries.first { it.ksl == ev.level }, ev.payload)
                        KslConst.EV_KEY -> keys += ev.key
                        KslConst.EV_HANDSHAKE_DONE -> serverDone = true
                    }
                }
                if (clientDone && serverDone) return Outcome(last, paused, true)
            }
            return Outcome(last, paused, clientDone && serverDone)
        } finally {
            protectors.forEach { it.close() }
            keys.forEach(Ksl::keyFree)
            c.close()
            if (s != 0L) Ksl.sslFree(s)
            Ksl.ctxFree(sc)
        }
    }

    private fun refused(
        o: Outcome,
        reason: VerifyReason,
    ) {
        val f = assertIs<DriveResult.Failed>(o.result, "the chain is refused")
        assertEquals(42, f.alert, "bad_certificate, as OpenSSL sends for a chain below its security level")
        assertEquals(reason, assertIs<TlsException.Verify>(f.exception).reason)
        assertEquals(42, reason.alertCode)
        assertFalse(o.paused, "refused before the platform or the application is asked")
    }

    private val platformPauses get() = !platformTrustViaOpenSsl

    private fun platform() = Fixtures.client(TrustConfig.Platform)

    private fun anchored(root: Certificate = weakRoot) = Fixtures.client(TrustConfig.AnchoredCa(listOf(root)))

    @Test fun negative_platformRefusesA1024BitRsaLeaf() {
        if (!platformPauses) return // Linux: OpenSSL's own level 2 (negative_anchoredRefusesTheSameChains)
        refused(handshake(platform(), listOf(WeakCerts.leafRsa1024), WeakCerts.leafRsa1024Key), VerifyReason.WeakKey)
    }

    @Test fun negative_platformRefusesA1024BitRsaIntermediate() {
        if (!platformPauses) return
        refused(
            handshake(platform(), listOf(WeakCerts.leafViaRsa1024, WeakCerts.midRsa1024), WeakCerts.leafViaRsa1024Key),
            VerifyReason.WeakKey,
        )
    }

    @Test fun negative_platformRefusesASmallEcIntermediate() {
        if (!platformPauses) return
        refused(handshake(platform(), listOf(WeakCerts.leafViaP192, WeakCerts.midP192), WeakCerts.leafViaP192Key), VerifyReason.WeakKey)
    }

    @Test fun negative_platformRefusesASha1SignedIntermediate() {
        if (!platformPauses) return
        refused(
            handshake(platform(), listOf(WeakCerts.leafViaSha1, WeakCerts.midSha1), WeakCerts.leafViaSha1Key),
            VerifyReason.WeakSignature,
        )
    }

    /** RFC 9846 section 4.5.1.3: a certificate the endpoint would validate with an MD5 signature MUST be refused with bad_certificate. */
    @Test fun negative_platformRefusesAnMd5SignedLeaf() {
        if (!platformPauses) return
        refused(handshake(platform(), listOf(WeakCerts.leafMd5), WeakCerts.leafMd5Key), VerifyReason.WeakSignature)
    }

    @Test fun platformAsksThePlatformAbout2048BitRsaAndP256() {
        if (!platformPauses) return
        for ((chain, key) in listOf(
            listOf(WeakCerts.leafRsa2048) to WeakCerts.leafRsa2048Key,
            listOf(WeakCerts.leafP256) to WeakCerts.leafP256Key,
            listOf(WeakCerts.leafViaP224, WeakCerts.midP224) to WeakCerts.leafViaP224Key,
        )) {
            val o = handshake(platform(), chain, key)
            assertTrue(o.paused, "the chain reaches the platform verifier")
            assertTrue(o.done, "accepted once the platform says yes: ${(o.result as? DriveResult.Failed)?.exception}")
        }
    }

    /** RFC 9846 section 4.5.1.3: "endpoints can accept these algorithms for certificates that are self-signed or are trust anchors". */
    @Test fun platformAcceptsASha1SelfSignedRootSentAlong() {
        if (!platformPauses) return
        val o = handshake(platform(), listOf(WeakCerts.leafUnderSha1Root, WeakCerts.sha1Root), WeakCerts.leafUnderSha1RootKey)
        assertTrue(o.paused && o.done)
    }

    /** A Custom verifier is not asked about a weak chain either: the level holds under every trust. */
    @Test fun negative_customVerifierIsNotAskedAboutAWeakChain() {
        var asked = 0
        val custom =
            TrustConfig.Custom(
                CertificateVerifier { chain, _, _ ->
                    asked++
                    VerifyResult.Accepted(chain)
                },
            )
        val o = handshake(Fixtures.client(custom), listOf(WeakCerts.leafRsa1024), WeakCerts.leafRsa1024Key)
        val f = assertIs<DriveResult.Failed>(o.result)
        assertEquals(VerifyReason.WeakKey, assertIs<TlsException.Verify>(f.exception).reason)
        assertEquals(0, asked)
    }

    /** OpenSSL's own path (AnchoredCa, Linux Platform) refuses the same chains, now with the same typed reasons. */
    @Test fun negative_anchoredRefusesTheSameChains() {
        val cases =
            listOf(
                Triple(listOf(WeakCerts.leafRsa1024), WeakCerts.leafRsa1024Key, VerifyReason.WeakKey),
                Triple(listOf(WeakCerts.leafViaRsa1024, WeakCerts.midRsa1024), WeakCerts.leafViaRsa1024Key, VerifyReason.WeakKey),
                Triple(listOf(WeakCerts.leafViaP192, WeakCerts.midP192), WeakCerts.leafViaP192Key, VerifyReason.WeakKey),
                Triple(listOf(WeakCerts.leafViaSha1, WeakCerts.midSha1), WeakCerts.leafViaSha1Key, VerifyReason.WeakSignature),
                Triple(listOf(WeakCerts.leafSha1), WeakCerts.leafSha1Key, VerifyReason.WeakSignature),
            )
        for ((chain, key, reason) in cases) refused(handshake(anchored(), chain, key), reason)
        assertTrue(handshake(anchored(), listOf(WeakCerts.leafRsa2048), WeakCerts.leafRsa2048Key).done)
    }

    @Test fun weakReasonsPrintTheirName() {
        assertEquals("certificate verification failed: WeakKey", TlsException.Verify(VerifyReason.WeakKey, emptyList()).message)
        assertEquals("certificate verification failed: WeakSignature", TlsException.Verify(VerifyReason.WeakSignature, emptyList()).message)
    }
}
