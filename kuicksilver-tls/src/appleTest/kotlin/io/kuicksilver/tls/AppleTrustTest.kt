// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.runBlocking
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertIs

/** SecTrust through the pipeline: our test CA is not in the system keychain, so the platform must reject it as an unknown issuer. */
class AppleTrustTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun platformRejectsUnknownCa() {
        val r =
            runBlocking {
                PlatformVerifier.verify(
                    listOf(Certificate(TestCerts.server), Certificate(TestCerts.testCa)),
                    HostName.normalize("server.test"),
                    TlsRole.Client,
                )
            }
        val rej = assertIs<VerifyResult.Rejected>(r)
        kotlin.test.assertTrue(rej.reason is VerifyReason.UnknownIssuer, "reason: ${rej.reason}")
    }

    @Test fun platformPauseThroughTheQuicSessionFailsWithAlert48() {
        val p = Pump(KslQuicCrypto.newSession(Fixtures.client(TrustConfig.Platform)), KslQuicCrypto.newSession(Fixtures.server()))
        p.c.setTransportParameters(Fixtures.tp)
        p.s.setTransportParameters(Fixtures.tp)
        try {
            val (rc, _) =
                p.run { want ->
                    runBlocking { p.c.verifyPeer(want.chain) }
                }
            val f = assertIs<DriveResult.Failed>(rc)
            kotlin.test.assertEquals(48, f.alert)
        } finally {
            p.close()
        }
    }
}
