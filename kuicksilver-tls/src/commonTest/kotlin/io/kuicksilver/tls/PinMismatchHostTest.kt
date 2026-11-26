// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.native.KslLoader
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * The host a [VerifyReason.PinMismatch] names is the reference identifier the certificate was checked against, normalized,
 * on every path: under an `ExpectedName` it is that name, not the server name sent as SNI.
 */
class PinMismatchHostTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val chain = listOf(Certificate(TestCerts.server), Certificate(TestCerts.testCa))
    private val wrong = setOf(SpkiSha256(ByteArray(32) { 7 }))
    private val ca = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa)))

    private fun hostOf(
        trust: TrustConfig,
        serverName: String,
    ): String? {
        val config =
            tlsConfig(TlsRole.Client) {
                this.trust = trust
                this.serverName = serverName
            }
        val r = assertIs<VerifyResult.Rejected>(Verification(config).pinCheck(chain))
        return assertIs<VerifyReason.PinMismatch>(r.reason).host
    }

    @Test fun theSniOverrideIsNotTheHostUnderExpectedName() {
        assertEquals("server.test", hostOf(TrustConfig.Pinned(wrong, base = TrustConfig.ExpectedName("Server.Test.", ca)), "sni.example"))
    }

    @Test fun withoutExpectedNameItIsTheNormalizedServerName() {
        assertEquals("server.test", hostOf(TrustConfig.Pinned(wrong, base = ca), "SERVER.test."))
    }
}
