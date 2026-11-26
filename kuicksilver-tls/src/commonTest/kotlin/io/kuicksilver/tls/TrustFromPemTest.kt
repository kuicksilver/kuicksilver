// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.native.KslLoader
import kotlinx.io.IOException
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.files.SystemTemporaryDirectory
import kotlinx.io.writeString
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** `TrustConfig.fromPem` and `fromPemFile`: "trust my own CA" with the server's PEM reader and messages that say what was wrong. */
class TrustFromPemTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val ca = TestCerts.toPem("CERTIFICATE", TestCerts.testCa)
    private val otherCa = TestCerts.toPem("CERTIFICATE", TestCerts.otherCa)
    private val key = TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey)

    private fun file(text: String): Path {
        val p = Path(SystemTemporaryDirectory, "ksl-ca-${Random.nextLong().toULong()}.pem")
        SystemFileSystem.sink(p).buffered().use { it.writeString(text) }
        return p
    }

    private inline fun <T> withFile(
        text: String,
        block: (String) -> T,
    ): T {
        val p = file(text)
        try {
            return block(p.toString())
        } finally {
            SystemFileSystem.delete(p, mustExist = false)
        }
    }

    @Test fun oneCaBecomesTheOnlyRoot() {
        val t = TrustConfig.fromPem(ca)
        assertEquals(listOf(Certificate(TestCerts.testCa)), t.roots)
    }

    @Test fun everyCertificateIsARootAndCrlfAndCommentsAreFine() {
        // openssl's `-text` output and Windows line ends; a comment that merely mentions a private key is no key
        val text = "# our private key stays on the server\r\nsubject=CN = Kuicksilver Test CA\r\n" + ca.replace("\n", "\r\n") + otherCa
        val t = TrustConfig.fromPem(text)
        assertEquals(listOf(Certificate(TestCerts.testCa), Certificate(TestCerts.otherCa)), t.roots)
    }

    @Test fun noCertificateSaysWhatWasFound() {
        val empty = assertFailsWith<TlsException.Config> { TrustConfig.fromPem("") }
        assertContains(empty.message!!, "holds no certificate")
        assertContains(empty.message!!, "no PEM block at all")
        val crl = assertFailsWith<TlsException.Config> { TrustConfig.fromPem("-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n") }
        assertContains(crl.message!!, "only \"X509 CRL\" blocks")
        // a DER file read as text, or a key in another format, is "no certificate" too
        assertFailsWith<TlsException.Config> { TrustConfig.fromPem("MIIBqjCCAVCgAwIBAgIU") }
    }

    @Test fun negative_aKeyInsteadOfACertificateIsRefused() {
        val e = assertFailsWith<TlsException.Config> { TrustConfig.fromPem(key) }
        assertContains(e.message!!, "holds a private key")
        // next to the CA too: a key file concatenated by mistake is refused whole, not silently skipped
        val both = assertFailsWith<TlsException.Config> { TrustConfig.fromPem(ca + key) }
        assertContains(both.message!!, "holds a private key")
        val legacy = "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"
        assertContains(assertFailsWith<TlsException.Config> { TrustConfig.fromPem(ca + legacy) }.message!!, "private key")
    }

    @Test fun negative_anEncryptedBlockIsRefusedAsSuch() {
        val pkcs8 = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"
        assertContains(assertFailsWith<TlsException.Config> { TrustConfig.fromPem(pkcs8) }.message!!, "encrypted PEM block")
        val legacy =
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n" +
                "-----END RSA PRIVATE KEY-----\n"
        assertContains(assertFailsWith<TlsException.Config> { TrustConfig.fromPem(ca + legacy) }.message!!, "encrypted PEM block")
    }

    @Test fun aDamagedCertificateIsRefused() {
        val bad = "-----BEGIN CERTIFICATE-----\nAQIDBAU=\n-----END CERTIFICATE-----\n"
        assertFailsWith<TlsException.Config> { TrustConfig.fromPem(bad) }
        assertFailsWith<TlsException.Config> { TrustConfig.fromPem("-----BEGIN CERTIFICATE-----\nAAAA\n") }
    }

    @Test fun theMessagesNeverQuoteTheText() {
        val secret = "-----BEGIN PRIVATE KEY-----\nU0VDUkVUU0VDUkVU\n-----END PRIVATE KEY-----\n"
        val e = assertFailsWith<TlsException.Config> { TrustConfig.fromPem(secret) }
        assertFalse("U0VDUkVU" in e.message!!)
    }

    @Test fun fromPemFileReadsTheFile() {
        withFile(ca + otherCa) { path ->
            assertEquals(2, TrustConfig.fromPemFile(path).roots.size)
        }
    }

    @Test fun fromPemFileNamesTheFileWithoutACertificate() {
        withFile("-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n") { path ->
            val e = assertFailsWith<TlsException.Config> { TrustConfig.fromPemFile(path) }
            assertContains(e.message!!, path)
            assertContains(e.message!!, "holds no certificate")
        }
        withFile("") { path -> assertContains(assertFailsWith<TlsException.Config> { TrustConfig.fromPemFile(path) }.message!!, path) }
    }

    /** L7: a file without any PEM block (a DER certificate or key) is refused on the raw characters, before a String of it. */
    @Test fun negative_fromPemFileRefusesAFileWithoutAPemBlock() {
        val p = Path(SystemTemporaryDirectory, "ksl-ca-${Random.nextLong().toULong()}.der")
        SystemFileSystem.sink(p).buffered().use { it.write(TestCerts.serverKey) }
        try {
            val e = assertFailsWith<TlsException.Config> { TrustConfig.fromPemFile(p.toString()) }
            assertEquals("$p holds no certificate (-----BEGIN CERTIFICATE-----): no PEM block at all", e.message)
        } finally {
            SystemFileSystem.delete(p, mustExist = false)
        }
    }

    /** L2: the one-argument PinMismatch of 0.2 still builds, without a host; the two-argument one names it. */
    @Test fun pinMismatchKeepsItsOneArgumentConstructor() {
        assertEquals(null, VerifyReason.PinMismatch(emptyList()).host)
        assertEquals("PinMismatch(host=a.test, chain=[])", VerifyReason.PinMismatch(emptyList(), "a.test").toString())
    }

    @Test fun negative_fromPemFileRefusesAKeyFile() {
        withFile(key) { path ->
            val e = assertFailsWith<IOException> { TrustConfig.fromPemFile(path) }
            assertEquals("$path contains a private key; it must hold CA certificates only", e.message)
        }
        withFile(ca + "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n") { path ->
            val e = assertFailsWith<IOException> { TrustConfig.fromPemFile(path) }
            assertEquals("$path contains an encrypted private key; it must hold CA certificates only", e.message)
        }
    }

    @Test fun fromPemFileRefusesAFileOverOneMebibyteAndAMissingOne() {
        withFile(ca + "#".repeat(MAX_PEM_FILE_BYTES.toInt())) { path ->
            val e = assertFailsWith<IOException> { TrustConfig.fromPemFile(path) }
            assertTrue(e.message!!.contains("larger than"), e.message)
        }
        // exactly the cap is read
        val pad = MAX_PEM_FILE_BYTES.toInt() - ca.length
        withFile(ca + "#".repeat(pad)) { path -> assertEquals(1, TrustConfig.fromPemFile(path).roots.size) }
        val missing = Path(SystemTemporaryDirectory, "ksl-no-such-ca-${Random.nextLong().toULong()}.pem").toString()
        assertFailsWith<IOException> { TrustConfig.fromPemFile(missing) }
    }
}
