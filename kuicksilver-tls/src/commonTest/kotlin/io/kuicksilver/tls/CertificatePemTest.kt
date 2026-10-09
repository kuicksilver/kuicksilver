// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.native.KslLoader
import kotlin.io.encoding.Base64
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class CertificatePemTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun pem(
        type: String,
        der: ByteArray,
        eol: String = "\n",
    ): String = "-----BEGIN $type-----$eol" + Base64.encode(der).chunked(64).joinToString(eol) + "$eol-----END $type-----$eol"

    @Test fun parsePemReturnsBlocksInOrder() {
        val parsed = Certificate.parsePem(pem("CERTIFICATE", TestCerts.server) + pem("CERTIFICATE", TestCerts.testCa))
        assertEquals(2, parsed.size)
        assertContentEquals(TestCerts.server, parsed[0].der)
        assertContentEquals(TestCerts.testCa, parsed[1].der)
    }

    @Test fun parsePemSkipsOtherBlocksAndCrlf() {
        val text =
            "subject=CN = server.test\r\n" + pem("CERTIFICATE", TestCerts.server, "\r\n") + "# comment\r\n" +
                pem("PRIVATE KEY", TestCerts.serverKey, "\r\n") + pem("CERTIFICATE", TestCerts.testCa, "\r\n")
        val parsed = Certificate.parsePem(text)
        assertEquals(listOf(Certificate(TestCerts.server), Certificate(TestCerts.testCa)), parsed)
    }

    @Test fun parsePemWithoutCertificatesFails() {
        assertFailsWith<TlsException.Config> { Certificate.parsePem("") }
        assertFailsWith<TlsException.Config> { Certificate.parsePem(pem("PRIVATE KEY", TestCerts.serverKey)) }
    }

    @Test fun parsePemRejectsMalformedDer() {
        assertFailsWith<TlsException.Config> { Certificate.parsePem(pem("CERTIFICATE", byteArrayOf(1, 2, 3, 4, 5))) }
        // well-formed TLV, too few certificate fields: still a Config error, not IndexOutOfBounds
        assertFailsWith<TlsException.Config> { Certificate.parsePem(pem("CERTIFICATE", byteArrayOf(0x30, 4, 0x30, 2, 5, 0))) }
    }

    @Test fun parsedRootWorksAsAnchoredCa() {
        val trust = TrustConfig.AnchoredCa(Certificate.parsePem(pem("CERTIFICATE", TestCerts.testCa)))
        assertEquals(Certificate(TestCerts.testCa), trust.roots.single())
    }
}
