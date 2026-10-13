// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.runBlocking
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * CryptoAPI through [PlatformVerifier] and [WindowsTrust]: the test CA is not in the Windows root store, so the platform rejects
 * it as an unknown issuer; with the test CA as the engine's exclusive root (`hExclusiveRoot`) the same chains are accepted and
 * every other check (name, validity, EKU, issuer) still applies.
 */
class WindowsTrustTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val testCa = Certificate(TestCerts.testCa)
    private val server = Certificate(TestCerts.server)
    private val serverName = HostName.normalize("server.test")

    private fun anchored(
        vararg chain: ByteArray,
        host: String = "server.test",
        role: TlsRole = TlsRole.Client,
    ): VerifyResult = WindowsTrust.verify(chain.map(::Certificate), HostName.normalize(host), role, exclusiveRoots = listOf(testCa))

    private fun reasonOf(r: VerifyResult): VerifyReason = assertIs<VerifyResult.Rejected>(r, "expected a rejection").reason

    @Test fun negative_platformRejectsTheTestCaAsUnknownIssuer() {
        val r = runBlocking { PlatformVerifier.verify(listOf(server, testCa), serverName, TlsRole.Client) }
        assertIs<VerifyReason.UnknownIssuer>(reasonOf(r))
    }

    @Test fun anchoredTestRootAcceptsAndReturnsTheValidatedChain() {
        val r = assertIs<VerifyResult.Accepted>(anchored(TestCerts.server))
        assertEquals(listOf(server.spkiSha256, testCa.spkiSha256), r.validatedChain.map { it.spkiSha256 }, "leaf first, anchor last")
    }

    @Test fun intermediateFromThePresentedChainIsUsed() {
        val r = assertIs<VerifyResult.Accepted>(anchored(TestCerts.serverViaIntermediate, TestCerts.intermediate))
        assertEquals(3, r.validatedChain.size)
        assertEquals(Certificate(TestCerts.intermediate).spkiSha256, r.validatedChain[1].spkiSha256)
    }

    @Test fun unrelatedPresentedCertificatesStayOutOfTheValidatedChain() {
        val r = assertIs<VerifyResult.Accepted>(anchored(TestCerts.server, TestCerts.otherCa))
        assertTrue(
            r.validatedChain.none {
                it.spkiSha256 == Certificate(TestCerts.otherCa).spkiSha256
            },
            "pins must not match a merely presented cert",
        )
    }

    @Test fun negative_nameMismatch() {
        val reason = assertIs<VerifyReason.HostnameMismatch>(reasonOf(anchored(TestCerts.server, host = "other.test")))
        assertEquals("other.test", reason.expected)
        assertTrue("server.test" in reason.presented)
    }

    @Test fun wildcardAndIpLiteralMatch() {
        assertIs<VerifyResult.Accepted>(anchored(TestCerts.server, host = "a.wild.test"))
        assertIs<VerifyResult.Accepted>(anchored(TestCerts.server, host = "127.0.0.1"))
    }

    @Test fun negative_expired() = assertIs<VerifyReason.Expired>(reasonOf(anchored(TestCerts.expired))).let {}

    @Test fun negative_notYetValid() = assertIs<VerifyReason.NotYetValid>(reasonOf(anchored(TestCerts.notYetValid))).let {}

    @Test fun negative_otherIssuer() = assertIs<VerifyReason.UnknownIssuer>(reasonOf(anchored(TestCerts.serverOtherCa))).let {}

    @Test fun negative_clientAuthOnlyLeafIsNoServer() =
        assertIs<VerifyReason.InvalidPurpose>(reasonOf(anchored(TestCerts.serverClientEku))).let {
        }

    @Test fun leafWithoutEkuServesAnyPurpose() = assertIs<VerifyResult.Accepted>(anchored(TestCerts.serverNoEku)).let {}

    @Test fun clientCertificatesAreCheckedForClientAuth() {
        assertIs<VerifyResult.Accepted>(anchored(TestCerts.client, role = TlsRole.Server))
        assertIs<VerifyReason.InvalidPurpose>(reasonOf(anchored(TestCerts.server, role = TlsRole.Server)))
    }

    @Test fun negative_garbageIsBadEncoding() {
        val r = WindowsTrust.verify(listOf(Certificate(byteArrayOf(0x30, 0x03, 1, 2, 3))), serverName, TlsRole.Client, listOf(testCa))
        assertIs<VerifyReason.BadEncoding>(reasonOf(r))
    }

    /** ADR-0011: a pin is checked in addition to the base trust, so a matching pin never rescues a chain Windows rejects. */
    @Test fun negative_pinDoesNotOverrideAPlatformRejection() {
        val config =
            tlsConfig(TlsRole.Client) {
                serverName = "server.test"
                trust = TrustConfig.Pinned(setOf(server.spkiSha256), base = TrustConfig.ExpectedName("server.test"))
            }
        val r = runBlocking { Verification(config).verify(listOf(server, testCa), serverName) }
        assertIs<VerifyReason.UnknownIssuer>(reasonOf(r))
    }

    @Test fun platformPauseThroughTheQuicSessionFailsWithAlert48() {
        val p = Pump(KslQuicCrypto.newSession(Fixtures.client(TrustConfig.Platform)), KslQuicCrypto.newSession(Fixtures.server()))
        p.c.setTransportParameters(Fixtures.tp)
        p.s.setTransportParameters(Fixtures.tp)
        try {
            val (rc, _) = p.run { want -> runBlocking { p.c.verifyPeer(want.chain) } }
            assertEquals(48, assertIs<DriveResult.Failed>(rc).alert)
        } finally {
            p.close()
        }
    }
}
