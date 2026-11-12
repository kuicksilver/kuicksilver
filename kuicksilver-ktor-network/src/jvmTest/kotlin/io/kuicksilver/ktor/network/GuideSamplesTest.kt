// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(DelicateKuicksilverApi::class, io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.CertificateRevocationList
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.OcspStapling
import io.kuicksilver.tls.PinScope
import io.kuicksilver.tls.RevocationPolicy
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TestCerts
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.keylogFile
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.io.File
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The code blocks of docs/guide/tls.md, kept compiling and running (block markers `guide:tls:*`). */
class GuideSamplesTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val rootCertificate = Certificate(TestCerts.testCa)
    private val chainPem = TestCerts.toPem("CERTIFICATE", TestCerts.server)
    private val keyPem = TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey)

    @Test fun availabilitySample() {
        var fellBack = false

        fun fallBackToTcp() {
            fellBack = true
        }
        // guide:tls:availability
        if (!KslLoader.isAvailable()) fallBackToTcp() // never throws; the outcome is cached for the process
        kotlin.test.assertFalse(fellBack, "the JVM test host has the native library")
    }

    @Test fun clientConfigSample() {
        // guide:tls:client-config
        val client =
            tlsConfig(TlsRole.Client) {
                serverName = "server.test" // SNI and the name the certificate must match
                alpn = listOf("h2", "http/1.1")
                trust = TrustConfig.Platform // the OS trust store (JDK, Android NSC, SecTrust, Windows)
            }
        assertEquals(TlsRole.Client, client.role)
    }

    @Test fun serverConfigSample() {
        // guide:tls:server-config
        val identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray()) // the key array is zeroed after import
        val server =
            tlsConfig(TlsRole.Server) {
                alpn = listOf("http/1.1")
                this.identity = identity
            }
        assertEquals(1, server.identity!!.chain.size)
    }

    @Test fun trustSample() {
        // guide:tls:trust
        val pinned =
            TrustConfig.Pinned(
                pins = setOf(SpkiSha256.parse("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")),
                scope = PinScope.Leaf,
                base = TrustConfig.AnchoredCa(listOf(rootCertificate)), // or Platform
            )
        assertTrue(pinned.base is TrustConfig.AnchoredCa)
    }

    @Test fun pemRootsSample() {
        val caPem = TestCerts.toPem("CERTIFICATE", TestCerts.testCa) // the content of ca.pem
        // guide:tls:pem-roots
        val roots = Certificate.parsePem(caPem) // every CERTIFICATE block, in order; TlsException.Config if none
        val trust = TrustConfig.AnchoredCa(roots)
        assertEquals(rootCertificate, trust.roots.single())
    }

    @Test fun revocationSample() {
        val roots = listOf(rootCertificate)
        // a CRL that revokes nothing (crl-root.der of tools/certs/gen-revocation-certs.sh)
        val crlPem = "-----BEGIN X509 CRL-----\n$CRL_ROOT_B64\n-----END X509 CRL-----\n"
        val ocspResponseDer = byteArrayOf(0x30, 0x03, 0x0a, 0x01, 0x03) // stands in for the CA responder's answer
        val serverIdentity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
        // guide:tls:revocation
        val crls = CertificateRevocationList.parsePem(crlPem)
        val client =
            tlsConfig(TlsRole.Client) {
                serverName = "api.example.com"
                trust = TrustConfig.AnchoredCa(roots, crls)
                revocation = RevocationPolicy.StapledIfPresent // the default
            }
        val stapling = OcspStapling(ocspResponseDer) // later: stapling.update(fresher)
        val server =
            tlsConfig(TlsRole.Server) {
                identity = serverIdentity // leaf and its issuer
                ocspStapling = stapling
            }
        assertEquals(RevocationPolicy.StapledIfPresent, client.revocation)
        assertTrue(server.ocspStapling === stapling)
        serverIdentity.close()
    }

    @Test fun clientCaRotationSample() {
        val caBundlePem = TestCerts.toPem("CERTIFICATE", TestCerts.testCa)
        val renewedBundlePem = TestCerts.toPem("CERTIFICATE", TestCerts.otherCa)
        val serverIdentity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
        // guide:tls:client-ca-rotation
        val clientCa = TrustConfig.reloadable(TrustConfig.AnchoredCa(Certificate.parsePem(caBundlePem)))
        val mtlsServer =
            tlsConfig(TlsRole.Server) {
                alpn = listOf("h3")
                identity = serverIdentity
                clientAuth = ClientAuth.Required
                trust = clientCa
            }
        clientCa.reload(TrustConfig.AnchoredCa(Certificate.parsePem(renewedBundlePem)))
        assertEquals(Certificate(TestCerts.otherCa), clientCa.current.roots.single())
        assertTrue(mtlsServer.trust === clientCa)
        serverIdentity.close()
    }

    @Test fun socketSample(): Unit =
        runBlocking {
            val srv =
                LoopbackServer.start { s ->
                    val r = s.openReadChannel()
                    val w = s.openWriteChannel(autoFlush = true)
                    r.readLine(LineEnding.Lenient)
                    w.writeStringUtf8("HTTP/1.1 204 No Content\r\n\r\n")
                    w.flush()
                }
            try {
                val client = clientConfig()
                // guide:tls:socket
                val selector = SelectorManager(Dispatchers.IO)
                val socket = aSocket(selector).tcp().connect("127.0.0.1", srv.port).tls(client)
                val write = socket.openWriteChannel(autoFlush = true)
                val read = socket.openReadChannel()
                write.writeStringUtf8("GET / HTTP/1.1\r\nHost: server.test\r\n\r\n")
                val status = withTimeout(10.seconds) { read.readLine(LineEnding.Lenient) }
                socket.close() // sends close_notify, then closes the TCP socket
                assertEquals("HTTP/1.1 204 No Content", status)
                selector.close()
            } finally {
                srv.close()
            }
        }

    @Test fun keylogSample() {
        val path =
            File
                .createTempFile("kuicksilver-keys", ".txt")
                .also {
                    it.delete()
                    it.deleteOnExit()
                }.path
        if (System.getProperty("os.name").orEmpty().startsWith("Windows")) {
            // documented in docs/guide/tls.md (Key logging): without POSIX permissions nothing can vouch for the file, so the
            // sample's call is refused there rather than writing secrets into an unchecked file
            val e = assertFailsWith<IllegalArgumentException> { keylogFile(path) }
            assertTrue("POSIX" in e.message.orEmpty(), e.message)
            return
        }
        // guide:tls:keylog
        val debugClient =
            tlsConfig(TlsRole.Client) {
                serverName = "server.test"
                keylog = keylogFile(path) // @DelicateKuicksilverApi
            }
        assertTrue(debugClient.keylog != null)
    }
}

/** crl-root.der of tools/certs/gen-revocation-certs.sh, base64. */
private val CRL_ROOT_B64 =
    listOf(
        "MIHIMG8CAQEwCgYIKoZIzj0EAwIwLjEsMCoGA1UEAwwjS3VpY2tzaWx2ZXIgUmV2b2NhdGlvbiBUZXN0IHJ2LXJvb3QXDTI2MTEx",
        "MjA3NTQyMFoYDzIxMjYxMDE5MDc1NDIwWqAOMAwwCgYDVR0UBAMCAQMwCgYIKoZIzj0EAwIDSQAwRgIhAKWPX9i+e8gKemU/6m5v",
        "ho/JCLQLdf7lYEnkKyT52ouPAiEAx3Q4brUP7KeYcjO7ikNe8v5kKK2O/ZlMPsXE5VF5fFM=",
    ).joinToString("")
