// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.tls

import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import kotlinx.coroutines.runBlocking
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.writeString
import platform.posix.getenv
import platform.posix.getpid
import platform.posix.setenv
import platform.posix.unlink
import platform.posix.unsetenv
import kotlin.io.encoding.Base64
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * RFC 9849 section 10.7 on Linux Native, where `TrustConfig.Platform` is OpenSSL inside `ksl` with the system store
 * ([platformTrustViaOpenSsl]), the counterpart of `EchTest.platformVerifierIsOfflineForAHiddenName` (the platforms whose
 * verifier is asked offline): no handshake pauses for a platform verifier, so nothing outside `ksl` is asked, for a name ECH
 * hid or any other, and OpenSSL's chain verification makes no network request (no OCSP, CRL or AIA retrieval: revocation
 * is stapled OCSP and configured CRLs only). The store is the test CA, through `SSL_CERT_FILE`, so the outcomes are the same
 * as where a platform verifier says yes: accepted, a rejection authenticated for the `public_name` (section 6.1.7, with the
 * server's retry configurations), GREASE.
 */
class EchPlatformTrustLinuxTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        runBlocking { SessionCache.Default.clear() }
    }

    private fun listOf(pem: String): EchConfigList =
        EchConfigList.parseBase64(
            pem
                .substringAfter("-----BEGIN ECHCONFIG-----")
                .substringBefore("-----END ECHCONFIG-----")
                .lines()
                .joinToString(""),
        )

    private fun <T> withStore(
        caPem: String,
        block: () -> T,
    ): T {
        val file = "/tmp/ksl-ech-store-${getpid()}.pem"
        SystemFileSystem.sink(Path(file)).buffered().use { it.writeString(caPem) }
        val saved = kotlin.collections.listOf("SSL_CERT_FILE", "SSL_CERT_DIR").associateWith { getenv(it)?.toKString() }
        setenv("SSL_CERT_FILE", file, 1)
        unsetenv("SSL_CERT_DIR")
        try {
            return block()
        } finally {
            saved.forEach { (k, v) -> if (v == null) unsetenv(k) else setenv(k, v, 1) }
            unlink(file)
        }
    }

    @Test fun platformTrustAsksNoVerifierAndAuthenticatesTheRejection() {
        assertTrue(platformTrustViaOpenSsl)
        assertEquals(KslConst.VERIFY_OPENSSL, KslContext.verifyModeFor(Fixtures.client(trust = TrustConfig.Platform)))
        val listA = listOf(EchTestKeys.A)
        val listB = listOf(EchTestKeys.B)
        val body = Base64.encode(TestCerts.testCa).chunked(64).joinToString("\n")
        val ca = "-----BEGIN CERTIFICATE-----\n$body\n-----END CERTIFICATE-----\n"
        val asked = ArrayList<String>()
        platformForTest = { chain, host, _, _ ->
            asked += host.value
            PlatformVerdict(VerifyResult.Accepted(chain), chain)
        }
        try {
            withStore(ca) {
                fun run(
                    list: EchConfigList?,
                    key: String,
                ): Pump {
                    val c = KslQuicCrypto.newSession(Fixtures.client(trust = TrustConfig.Platform) { echConfigList = list })
                    val s = KslQuicCrypto.newSession(Fixtures.server { echKeys = EchServerKeys(kotlin.collections.listOf(EchKey(key))) })
                    c.setTransportParameters(Fixtures.tp)
                    s.setTransportParameters(Fixtures.tp)
                    val p = Pump(c, s)
                    p.run(onVerify = { error("Linux Native: Platform trust never pauses for a verifier") })
                    p.close()
                    return p
                }
                val accepted = run(listA, EchTestKeys.A)
                assertEquals(EchStatus.Accepted, accepted.c.echStatus)
                assertTrue(accepted.cs.done, "the hidden name's certificate is verified by OpenSSL against the store")
                val rejected = run(listA, EchTestKeys.B)
                assertEquals(EchStatus.Rejected, rejected.c.echStatus)
                val failed = assertIs<DriveResult.Failed>(rejected.cs.last)
                assertEquals(listB, assertIs<TlsException.EchRejected>(failed.exception).retryConfigs)
                val grease = run(null, EchTestKeys.A)
                assertEquals(EchStatus.Grease, grease.c.echStatus)
                assertTrue(grease.cs.done)
            }
            assertEquals(emptyList(), asked, "no platform verifier is asked on Linux Native")
        } finally {
            platformForTest = null
        }
    }
}
