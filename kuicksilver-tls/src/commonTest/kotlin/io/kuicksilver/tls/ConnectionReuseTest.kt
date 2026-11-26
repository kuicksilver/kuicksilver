// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(DelicateKuicksilverApi::class, InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.runBlocking
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * [verifyForReuse]: the certificate check of connection coalescing (RFC 9113 section 9.1.1: "The certificate presented by
 * the server MUST satisfy any checks that the client would perform when forming a new TLS connection for the host in the
 * URI"; RFC 9114 section 3.3). The chain is the test server's (`server.test`, `*.wild.test`, 127.0.0.1, ::1), checked for
 * other hosts under each kind of trust, as a connection to that host would check it.
 */
class ConnectionReuseTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val ca = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
    private val server = listOf(Certificate(TestCerts.server))

    private fun check(
        host: String,
        trust: TrustConfig = ca,
        chain: List<Certificate> = server,
    ): VerifyResult = runBlocking { Fixtures.client(trust, host).verifyForReuse(chain) }

    private fun reason(r: VerifyResult): VerifyReason = assertIs<VerifyResult.Rejected>(r).reason

    @Test fun everyNameTheCertificateCoversIsAccepted() {
        for (host in listOf("server.test", "a.wild.test", "B.Wild.Test", "127.0.0.1", "::1")) {
            assertIs<VerifyResult.Accepted>(check(host), host)
        }
    }

    /**
     * RFC 9525 section 6.3: the wildcard stands for exactly one label, never for none or two, and only as the whole left-most
     * label; a name the SAN does not list is not covered, whatever the chain's trust.
     */
    @Test fun negative_aNameTheCertificateDoesNotCoverIsRefused() {
        for (host in listOf("other.test", "wild.test", "a.b.wild.test", "server.test.evil", "127.0.0.2", "::2")) {
            assertIs<VerifyReason.HostnameMismatch>(reason(check(host)), host)
        }
        val partial = listOf(Certificate(TestCerts.serverPartialWildcard))
        assertIs<VerifyReason.HostnameMismatch>(reason(check("foo.wild.test", chain = partial)))
    }

    /** Validity is checked now, not at the handshake: an expired certificate covers no further origin. */
    @Test fun negative_anExpiredCertificateIsRefused() {
        assertEquals(VerifyReason.Expired, reason(check("server.test", chain = listOf(Certificate(TestCerts.expired)))))
        assertEquals(VerifyReason.NotYetValid, reason(check("server.test", chain = listOf(Certificate(TestCerts.notYetValid)))))
    }

    @Test fun negative_aChainTheTrustDoesNotAnchorIsRefused() {
        assertEquals(VerifyReason.UnknownIssuer, reason(check("server.test", chain = listOf(Certificate(TestCerts.serverOtherCa)))))
    }

    /** ADR-0011: pins hold for a coalesced origin as for a new connection to it. */
    @Test fun pinsHoldOnTheValidatedChain() {
        val good = TrustConfig.Pinned(setOf(server[0].spkiSha256), base = ca)
        assertIs<VerifyResult.Accepted>(check("a.wild.test", good))
        val other = TrustConfig.Pinned(setOf(Certificate(TestCerts.serverOtherKey).spkiSha256), base = ca)
        assertIs<VerifyReason.PinMismatch>(reason(check("a.wild.test", other)))
        // the CA's key, in the validated chain only when the scope allows it
        val caPin = setOf(Fixtures.testCa.spkiSha256)
        assertIs<VerifyResult.Accepted>(check("a.wild.test", TrustConfig.Pinned(caPin, PinScope.AnyInValidatedChain, ca)))
        assertIs<VerifyReason.PinMismatch>(reason(check("a.wild.test", TrustConfig.Pinned(caPin, PinScope.Leaf, ca))))
    }

    /** TOFU remembers a key per name from a handshake with that name: never a first contact from another origin's connection. */
    @Test fun negative_tofuNeverAcceptsAnotherOriginsConnection() {
        val store =
            object : TofuStore {
                override suspend fun get(name: String): SpkiSha256? = server[0].spkiSha256

                override suspend fun put(
                    name: String,
                    pin: SpkiSha256,
                ) = error("nothing is stored for a coalesced origin")
            }
        assertIs<VerifyReason.Custom>(reason(check("a.wild.test", TrustConfig.Tofu(store))))
    }

    /**
     * RFC 9110 section 4.3.4: a client "might be specially configured to accept an alternative form of server identity";
     * with an ExpectedName a new connection to any host checks that name, so the reuse check does too.
     */
    @Test fun anExpectedNameReplacesTheHost() {
        assertIs<VerifyResult.Accepted>(check("other.test", TrustConfig.ExpectedName("server.test", ca)))
        assertIs<VerifyReason.HostnameMismatch>(reason(check("server.test", TrustConfig.ExpectedName("other.test", ca))))
    }

    /** A custom verifier is asked about the new host, and the shared matcher still runs after its yes (ADR-0011 rule 4). */
    @Test fun aCustomVerifierIsAskedForTheNewHostAndTheNameIsStillMatched() {
        val asked = ArrayList<String?>()
        val custom =
            TrustConfig.Custom { chain, name, _ ->
                asked += name
                VerifyResult.Accepted(chain)
            }
        assertIs<VerifyResult.Accepted>(check("b.wild.test", custom))
        assertIs<VerifyReason.HostnameMismatch>(reason(check("other.test", custom)))
        assertEquals(listOf<String?>("b.wild.test", "other.test"), asked)
        val no = TrustConfig.Custom { _, _, _ -> VerifyResult.Rejected(VerifyReason.Revoked) }
        assertEquals(VerifyReason.Revoked, reason(check("b.wild.test", no)))
    }

    /**
     * The platform's verifier is asked about the new host (Android's per-domain configuration, say, may differ from the
     * first). Skipped on Linux Native, where `Platform` is OpenSSL with the system store inside `ksl`
     * ([platformTrustViaOpenSsl]): there is no platform verifier to ask, and the OpenSSL path is the one the AnchoredCa tests
     * above take.
     */
    @Test fun thePlatformVerifierIsAskedForTheNewHost() {
        if (platformTrustViaOpenSsl) return
        val asked = ArrayList<String>()
        platformForTest = { chain, host, _, _ ->
            asked += host.value
            if (host.value == "pinned.wild.test") {
                PlatformVerdict(VerifyResult.Rejected(VerifyReason.PinMismatch(emptyList())), null)
            } else {
                PlatformVerdict(VerifyResult.Accepted(chain), chain)
            }
        }
        try {
            assertIs<VerifyResult.Accepted>(check("a.wild.test", TrustConfig.Platform))
            assertIs<VerifyReason.PinMismatch>(reason(check("pinned.wild.test", TrustConfig.Platform)))
            // a platform that says yes to a name the certificate does not carry is overruled by the shared matcher
            assertIs<VerifyReason.HostnameMismatch>(reason(check("other.test", TrustConfig.Platform)))
            assertEquals(listOf("a.wild.test", "pinned.wild.test", "other.test"), asked)
        } finally {
            platformForTest = null
        }
    }

    /**
     * RFC 9849 section 10.7: a name the path does not see (the connection's ECH was accepted, or a new connection to the host
     * would offer ECH) is verified without network requests about it, as in a handshake with ECH; any other is verified as a
     * handshake would. Skipped on Linux Native, as the test above.
     */
    @Test fun aHiddenNameIsVerifiedOffline() {
        if (platformTrustViaOpenSsl) return
        val offline = ArrayList<Boolean>()
        platformForTest = { chain, _, _, o ->
            offline += o
            PlatformVerdict(VerifyResult.Accepted(chain), chain)
        }
        try {
            val config = Fixtures.client(TrustConfig.Platform, "b.wild.test")
            assertIs<VerifyResult.Accepted>(runBlocking { config.verifyForReuse(server, hiddenName = true) })
            assertIs<VerifyResult.Accepted>(runBlocking { config.verifyForReuse(server) })
            assertEquals(listOf(true, false), offline)
        } finally {
            platformForTest = null
        }
    }

    /**
     * The staple holds a coalesced origin as it holds a resumption (`cachedStapleStillFresh`): under RequireStapled a
     * connection without one covers no further origin, and a staple past its nextUpdate (RFC 6960 section 4.2.2.1) covers
     * none under any policy but Off.
     */
    @Test fun negative_aMissingOrStaleStapleIsRefused() {
        val now = nowSeconds()

        fun check(
            policy: RevocationPolicy,
            until: Long,
        ) = runBlocking { Fixtures.client(ca, "a.wild.test") { revocation = policy }.verifyForReuse(server, until) }
        assertEquals(VerifyReason.UnknownRevocationStatus, reason(check(RevocationPolicy.RequireStapled, 0)))
        assertIs<VerifyResult.Accepted>(check(RevocationPolicy.RequireStapled, now + 3600))
        assertEquals(VerifyReason.UnknownRevocationStatus, reason(check(RevocationPolicy.RequireStapled, now - 1)))
        assertIs<VerifyResult.Accepted>(check(RevocationPolicy.StapledIfPresent, 0))
        assertEquals(VerifyReason.UnknownRevocationStatus, reason(check(RevocationPolicy.StapledIfPresent, now - 1)))
        assertIs<VerifyResult.Accepted>(check(RevocationPolicy.Off, 0))
        assertIs<VerifyResult.Accepted>(check(RevocationPolicy.Off, now - 1))
    }

    /** RFC 7633 section 4.3.3: a must-staple leaf needs its staple, for a coalesced origin too, unless the policy is Off. */
    @Test fun negative_aMustStapleLeafWithoutItsStapleIsRefused() {
        val leaf = Certificate(RevocationCerts.rvLeafMustStaple)
        assertTrue(leaf.mustStaple)
        assertFalse(Certificate(RevocationCerts.rvLeaf).mustStaple)
        assertFalse(server[0].mustStaple)
        val chain = listOf(leaf, Certificate(RevocationCerts.rvMid))
        val rv = TrustConfig.AnchoredCa(listOf(Certificate(RevocationCerts.rvRoot)))

        fun check(
            policy: RevocationPolicy,
            until: Long,
        ) = runBlocking { Fixtures.client(rv, "server.test") { revocation = policy }.verifyForReuse(chain, until) }
        assertEquals(VerifyReason.UnknownRevocationStatus, reason(check(RevocationPolicy.StapledIfPresent, 0)))
        assertIs<VerifyResult.Accepted>(check(RevocationPolicy.StapledIfPresent, nowSeconds() + 3600))
        assertIs<VerifyResult.Accepted>(check(RevocationPolicy.Off, 0))
    }

    @Test fun negative_noChainOrAServerConfigurationIsRefused() {
        assertEquals(VerifyReason.NoCertificate, reason(check("server.test", chain = emptyList())))
        assertFailsWith<IllegalArgumentException> { runBlocking { Fixtures.server().verifyForReuse(server) } }
    }
}
