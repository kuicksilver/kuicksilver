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
import io.kuicksilver.native.KslException
import io.kuicksilver.native.KslLoader
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * OpenSSL security level 2 (112 bits) on the peer's chain under every trust (T.5, T.5b): under [TrustConfig.Platform] the
 * JDK, Android and Windows verifiers accept 1024-bit RSA, so after the platform's yes the path it built is held to the level
 * as OpenSSL holds its own ([TrustConfig.AnchoredCa]; the anchor's signature exempt, its key not); under `Custom` and `Tofu`
 * `ksl` checks the chain the peer sent before the application is asked. The Platform cases here stand a platform in that says
 * yes with a given path ([platformBuilt]); the JVM and Apple tests run the real verifiers. The certificates come from
 * `tools/certs/gen-weak-certs.sh`.
 */
class ChainSecurityLevelTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val weakRoot = Certificate(WeakCerts.weakRoot)

    private fun handshake(
        client: TlsConfig,
        chain: List<ByteArray>,
        key: ByteArray,
        verdict: (QuicTlsSession, List<Certificate>) -> VerifyResult = { _, presented -> VerifyResult.Accepted(presented) },
    ): WeakOutcome = weakHandshake(client, chain, key, verdict)

    private fun refused(
        o: WeakOutcome,
        reason: VerifyReason,
        afterThePlatform: Boolean = false,
    ) {
        val f = assertIs<DriveResult.Failed>(o.result, "the chain is refused")
        assertEquals(42, f.alert, "bad_certificate, as OpenSSL sends for a chain below its security level")
        assertEquals(reason, assertIs<TlsException.Verify>(f.exception).reason)
        assertEquals(42, reason.alertCode)
        if (afterThePlatform) {
            assertTrue(o.paused, "the platform is asked first; its path is checked after its yes")
        } else {
            assertFalse(o.paused, "refused before the application is asked")
        }
    }

    private val platformPauses get() = !platformTrustViaOpenSsl

    private fun platform(trust: TrustConfig = TrustConfig.Platform) = Fixtures.client(trust)

    /**
     * The verdict of a session under [config] whose platform verifier says yes and built [path] (leaf first, its anchor last;
     * null: the platform did not say which path it took), through the same [Verification] a real pause runs.
     */
    private fun platformBuilt(
        path: List<ByteArray>?,
        config: TlsConfig = platform(),
    ): (QuicTlsSession, List<Certificate>) -> VerifyResult =
        { _, presented ->
            val built = path?.map(::Certificate)
            val v = Verification(config) { _, _, _ -> PlatformVerdict(VerifyResult.Accepted(built ?: presented), built) }
            immediate { v.verify(presented, HostName.normalize("server.test")) }
        }

    private fun refusedOnItsPath(
        chain: List<ByteArray>,
        key: ByteArray,
        path: List<ByteArray>,
        reason: VerifyReason,
    ) = refused(handshake(platform(), chain, key, platformBuilt(path)), reason, afterThePlatform = true)

    private fun anchored(root: Certificate = weakRoot) = Fixtures.client(TrustConfig.AnchoredCa(listOf(root)))

    @Test fun negative_platformRefusesA1024BitRsaLeaf() {
        if (!platformPauses) return // Linux: OpenSSL's own level 2 (negative_anchoredRefusesTheSameChains)
        refusedOnItsPath(
            listOf(WeakCerts.leafRsa1024),
            WeakCerts.leafRsa1024Key,
            listOf(WeakCerts.leafRsa1024, WeakCerts.weakRoot),
            VerifyReason.WeakKey,
        )
    }

    @Test fun negative_platformRefusesA1024BitRsaIntermediate() {
        if (!platformPauses) return
        val chain = listOf(WeakCerts.leafViaRsa1024, WeakCerts.midRsa1024)
        refusedOnItsPath(chain, WeakCerts.leafViaRsa1024Key, chain + WeakCerts.weakRoot, VerifyReason.WeakKey)
    }

    @Test fun negative_platformRefusesASmallEcIntermediate() {
        if (!platformPauses) return
        val chain = listOf(WeakCerts.leafViaP192, WeakCerts.midP192)
        refusedOnItsPath(chain, WeakCerts.leafViaP192Key, chain + WeakCerts.weakRoot, VerifyReason.WeakKey)
    }

    @Test fun negative_platformRefusesASha1SignedIntermediate() {
        if (!platformPauses) return
        val chain = listOf(WeakCerts.leafViaSha1, WeakCerts.midSha1)
        refusedOnItsPath(chain, WeakCerts.leafViaSha1Key, chain + WeakCerts.weakRoot, VerifyReason.WeakSignature)
    }

    /** RFC 9846 section 4.5.1.3: a certificate the endpoint would validate with an MD5 signature MUST be refused with bad_certificate. */
    @Test fun negative_platformRefusesAnMd5SignedLeaf() {
        if (!platformPauses) return
        refusedOnItsPath(
            listOf(WeakCerts.leafMd5),
            WeakCerts.leafMd5Key,
            listOf(WeakCerts.leafMd5, WeakCerts.rsaRoot),
            VerifyReason.WeakSignature,
        )
    }

    @Test fun platformAcceptsPaths2048BitRsaAndP256() {
        if (!platformPauses) return
        for ((chain, key) in listOf(
            listOf(WeakCerts.leafRsa2048) to WeakCerts.leafRsa2048Key,
            listOf(WeakCerts.leafP256) to WeakCerts.leafP256Key,
            listOf(WeakCerts.leafViaP224, WeakCerts.midP224) to WeakCerts.leafViaP224Key,
        )) {
            val o = handshake(platform(), chain, key, platformBuilt(chain + WeakCerts.weakRoot))
            assertTrue(o.paused, "the chain reaches the platform verifier")
            assertTrue(o.done, "accepted once the platform says yes: ${(o.result as? DriveResult.Failed)?.exception}")
        }
    }

    /** RFC 9846 section 4.5.1.3: "endpoints can accept these algorithms for certificates that are self-signed or are trust anchors". */
    @Test fun platformAcceptsASha1SelfSignedRootAsItsAnchor() {
        if (!platformPauses) return
        val chain = listOf(WeakCerts.leafUnderSha1Root, WeakCerts.sha1Root)
        val o = handshake(platform(), chain, WeakCerts.leafUnderSha1RootKey, platformBuilt(chain))
        assertTrue(o.paused && o.done)
    }

    /**
     * T.5b: L <- I <- R and an extra cross-certificate X (R's name and key, signed with SHA-1 by another root) sent along. A
     * platform anchored at R builds L, I, R: X is not on its path and does not count, as on OpenSSL's own path.
     */
    @Test fun platformAcceptsAWeakCrossCertificateOffItsPath() {
        if (!platformPauses) return
        val o = handshake(platform(), crossPresented, WeakCerts.leafViaCrossMidKey, platformBuilt(crossBuilt))
        assertTrue(o.paused && o.done, "${(o.result as? DriveResult.Failed)?.exception}")
    }

    /** The same chain under `Custom`: the presented chain counts, X with it, and the verifier is not asked. */
    @Test fun negative_customRefusesTheWeakCrossCertificateItWasSent() {
        var asked = 0
        val custom =
            TrustConfig.Custom(
                CertificateVerifier { chain, _, _ ->
                    asked++
                    VerifyResult.Accepted(chain)
                },
            )
        refused(handshake(Fixtures.client(custom), crossPresented, WeakCerts.leafViaCrossMidKey), VerifyReason.WeakSignature)
        assertEquals(0, asked)
    }

    /** A platform that does not say which path it took: the presented chain counts, X with it (stricter, never weaker). */
    @Test fun negative_platformWithoutItsPathHoldsThePresentedChain() {
        if (!platformPauses) return
        refused(
            handshake(platform(), crossPresented, WeakCerts.leafViaCrossMidKey, platformBuilt(null)),
            VerifyReason.WeakSignature,
            afterThePlatform = true,
        )
    }

    /** Pinned and ExpectedName over Platform hold the platform's path too, before the pins are compared. */
    @Test fun negative_pinnedAndExpectedNameOverPlatformCheckItsPath() {
        if (!platformPauses) return
        val chain = listOf(WeakCerts.leafViaSha1, WeakCerts.midSha1)
        val leafPin = Certificate(WeakCerts.leafViaSha1).spkiSha256
        for (trust in listOf(
            TrustConfig.Pinned(setOf(leafPin)),
            TrustConfig.ExpectedName("server.test"),
        )) {
            val config = platform(trust)
            refused(
                handshake(config, chain, WeakCerts.leafViaSha1Key, platformBuilt(chain + WeakCerts.weakRoot, config)),
                VerifyReason.WeakSignature,
                afterThePlatform = true,
            )
            val ok = handshake(config, crossPresented, WeakCerts.leafViaCrossMidKey, platformBuilt(crossBuilt, config))
            if (trust is TrustConfig.Pinned) {
                // the cross chain's leaf is not pinned: refused by the pins, not by the level
                val f = assertIs<DriveResult.Failed>(ok.result)
                assertIs<VerifyReason.PinMismatch>(assertIs<TlsException.Verify>(f.exception).reason)
            } else {
                assertTrue(ok.paused && ok.done, "${(ok.result as? DriveResult.Failed)?.exception}")
            }
        }
    }

    /**
     * The anchor begins the path: its signature is not checked even when it is not self-signed (x509_vfy.c check_auth_level),
     * here a SHA-1-signed intermediate the platform trusts as its anchor; the same chain under `Custom` is refused.
     */
    @Test fun platformDoesNotCheckItsAnchorsSignature() {
        if (!platformPauses) return
        val chain = listOf(WeakCerts.leafViaSha1, WeakCerts.midSha1)
        val o = handshake(platform(), chain, WeakCerts.leafViaSha1Key, platformBuilt(chain))
        assertTrue(o.paused && o.done, "${(o.result as? DriveResult.Failed)?.exception}")
        refused(
            handshake(
                Fixtures.client(
                    TrustConfig.Custom {
                        c,
                        _,
                        _,
                        ->
                        VerifyResult.Accepted(c)
                    },
                ),
                chain,
                WeakCerts.leafViaSha1Key,
            ),
            VerifyReason.WeakSignature,
        )
    }

    /** The anchor's key counts: a 1024-bit root the platform trusts is refused. */
    @Test fun negative_platformChecksItsAnchorsKey() {
        if (!platformPauses) return
        val chain = listOf(WeakCerts.leafUnderRsa1024Root, WeakCerts.rsa1024Root)
        refusedOnItsPath(listOf(WeakCerts.leafUnderRsa1024Root), WeakCerts.leafUnderRsa1024RootKey, chain, VerifyReason.WeakKey)
    }

    /** Generic alerts: handshake_failure on the wire, the reason kept. */
    @Test fun negative_platformPathWithGenericAlertsSendsHandshakeFailure() {
        if (!platformPauses) return
        val config = Fixtures.client(TrustConfig.Platform) { genericAlerts = true }
        val chain = listOf(WeakCerts.leafViaRsa1024, WeakCerts.midRsa1024)
        val o = handshake(config, chain, WeakCerts.leafViaRsa1024Key, platformBuilt(chain + WeakCerts.weakRoot, config))
        val f = assertIs<DriveResult.Failed>(o.result)
        assertEquals(40, f.alert)
        assertEquals(VerifyReason.WeakKey, assertIs<TlsException.Verify>(f.exception).reason)
    }

    private val crossPresented get() = listOf(WeakCerts.leafViaCrossMid, WeakCerts.crossMid, WeakCerts.crossRootBySha1)
    private val crossBuilt get() = listOf(WeakCerts.leafViaCrossMid, WeakCerts.crossMid, WeakCerts.crossRoot)

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

    /**
     * Runs [block] to its end in the caller's thread; for verifiers that never suspend (Tofu with [MemoryTofu]), so the
     * handshake can take their verdict at the pause.
     */
    private fun <T> immediate(block: suspend () -> T): T {
        var result: Result<T>? = null
        block.startCoroutine(Continuation(EmptyCoroutineContext) { result = it })
        return (result ?: error("the verifier suspended")).getOrThrow()
    }

    /** A [TofuStore] in memory whose calls never suspend. */
    private class MemoryTofu : TofuStore {
        val pins = HashMap<String, SpkiSha256>()

        override suspend fun get(name: String): SpkiSha256? = pins[name]

        override suspend fun put(
            name: String,
            pin: SpkiSha256,
        ) {
            pins[name] = pin
        }
    }

    private fun tofuVerdict(): (QuicTlsSession, List<Certificate>) -> VerifyResult =
        { s, presented -> immediate { s.verifyPeer(presented) } }

    /**
     * OpenSSL flags a self-issued certificate without key identifiers as self-signed without checking its signature: not an
     * anchor in the walk over a presented chain (`Custom`, `Tofu`, a platform that did not say its path).
     */
    @Test fun negative_presentedSelfIssuedMd5LeafIsRefused() {
        refused(
            handshake(
                Fixtures.client(TrustConfig.Custom { c, _, _ -> VerifyResult.Accepted(c) }),
                listOf(WeakCerts.leafSelfIssuedMd5),
                WeakCerts.leafSelfIssuedMd5Key,
            ),
            VerifyReason.WeakSignature,
        )
    }

    @Test fun negative_presentedSelfIssuedSha1IntermediateIsRefused() {
        refused(
            handshake(
                Fixtures.client(TrustConfig.Custom { c, _, _ -> VerifyResult.Accepted(c) }),
                listOf(WeakCerts.leafViaSelfIssuedSha1, WeakCerts.midSelfIssuedSha1),
                WeakCerts.leafViaSelfIssuedSha1Key,
            ),
            VerifyReason.WeakSignature,
        )
    }

    /** Tofu meets a self-signed 1024-bit key at first contact: refused, and no pin is stored for it. */
    @Test fun negative_tofuRefusesAWeakSelfSignedKeyAtFirstContact() {
        val store = MemoryTofu()
        val o =
            handshake(
                Fixtures.client(TrustConfig.Tofu(store)),
                listOf(WeakCerts.selfSignedRsa1024),
                WeakCerts.selfSignedRsa1024Key,
                tofuVerdict(),
            )
        refused(o, VerifyReason.WeakKey)
        assertTrue(store.pins.isEmpty(), "no pin stored for a refused key")
    }

    /** A self-signed P-256 certificate signed with SHA-1: its own signature is not checked, so Tofu takes it and pins it. */
    @Test fun tofuAcceptsASha1SelfSignedLeafWithAStrongKey() {
        val store = MemoryTofu()
        val o =
            handshake(
                Fixtures.client(TrustConfig.Tofu(store)),
                listOf(WeakCerts.selfSignedSha1),
                WeakCerts.selfSignedSha1Key,
                tofuVerdict(),
            )
        assertTrue(o.paused && o.done, "${(o.result as? DriveResult.Failed)?.exception}")
        assertEquals(setOf("server.test"), store.pins.keys)
    }

    /**
     * A decoy (the intermediate's subject, no key identifiers, self-signed with a strong key) does not hide the real issuer
     * from the walk over a presented chain.
     */
    @Test fun negative_customChecksTheIntermediateBehindADecoy() {
        val custom = Fixtures.client(TrustConfig.Custom { c, _, _ -> VerifyResult.Accepted(c) })
        refused(
            handshake(custom, listOf(WeakCerts.leafViaSha1, WeakCerts.decoySha1, WeakCerts.midSha1), WeakCerts.leafViaSha1Key),
            VerifyReason.WeakSignature,
        )
        refused(
            handshake(
                custom,
                listOf(WeakCerts.leafViaRsa1024, WeakCerts.decoyRsa1024, WeakCerts.midRsa1024),
                WeakCerts.leafViaRsa1024Key,
            ),
            VerifyReason.WeakKey,
        )
    }

    /** RFC 9325 section 4.5: an identity signed with SHA-1 or MD5 is refused when it is made, for a server and a client alike. */
    @Test fun negative_identitySignedWithSha1OrMd5IsRefused() {
        for ((chain, key) in listOf(
            listOf(WeakCerts.leafMd5) to WeakCerts.leafMd5Key,
            listOf(WeakCerts.leafSha1) to WeakCerts.leafSha1Key,
            listOf(WeakCerts.leafViaSha1, WeakCerts.midSha1) to WeakCerts.leafViaSha1Key,
        )) {
            val e = assertFailsWith<TlsException.Config> { TlsIdentity.fromDer(chain, key.copyOf()) }
            assertTrue(e.message!!.contains("SHA-1 or MD5"), e.message)
        }
        TlsIdentity.fromDer(listOf(WeakCerts.leafUnderSha1Root, WeakCerts.sha1Root), WeakCerts.leafUnderSha1RootKey.copyOf()).close()
    }

    /**
     * A chain past the walk's bounds (101 certificates, 2n + 2 signature checks) is refused with CERT_CHAIN_TOO_LONG, which
     * libssl sends as unknown_ca: the exception names the same alert. The chains themselves are built in C
     * (`chain_security_bounds`); this pins the mapping of what `ksl` reports.
     */
    @Test fun negative_chainTooLongIsUnknownIssuerWithItsAlert() {
        val (e, alert) = KslException.Internal(0, 48 or (22 shl 16), "chain too long").toTlsFailure(emptyList())
        assertEquals(48, alert)
        val reason = assertIs<TlsException.Verify>(e).reason
        assertEquals(VerifyReason.UnknownIssuer, reason)
        assertEquals(48, reason.alertCode)
    }

    @Test fun weakReasonsPrintTheirName() {
        assertEquals("certificate verification failed: WeakKey", TlsException.Verify(VerifyReason.WeakKey, emptyList()).message)
        assertEquals("certificate verification failed: WeakSignature", TlsException.Verify(VerifyReason.WeakSignature, emptyList()).message)
    }
}
