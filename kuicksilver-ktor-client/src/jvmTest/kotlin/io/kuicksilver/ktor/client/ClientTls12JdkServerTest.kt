// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsVersion
import io.kuicksilver.tls.TlsVersions
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyReason
import java.io.ByteArrayInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.KeyFactory
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.concurrent.thread
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The client's default TLS versions (0.3.0: TLS 1.3, or 1.2 with a server without 1.3) against servers that are not ours:
 * the JDK's TLS over a plain HTTP/1.1 responder, limited to the protocol versions and cipher suites each test names. A
 * TLS 1.2-only server is served, under the fixed profile alone (ECDHE with AEAD suites, RFC 9325; RFC 10015): a server that
 * offers only CBC, static RSA or finite-field DHE suites gets no handshake, while a JDK client shows that it would have
 * served each of them. Pins hold over TLS 1.2 as over 1.3.
 */
class ClientTls12JdkServerTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A JDK TLS server on 127.0.0.1 answering `ok` over HTTP/1.1; [handshakes] collects the outcome of each handshake. */
    private class JdkServer(
        val socket: SSLServerSocket,
        val handshakes: java.util.concurrent.LinkedBlockingQueue<Result<String>>,
    ) : AutoCloseable {
        val port: Int get() = socket.localPort

        /** The outcome of the next handshake, in the order they ended (waits for it, bounded). */
        fun next(): Result<String> = assertNotNull(handshakes.poll(10, java.util.concurrent.TimeUnit.SECONDS), "no handshake ended")

        override fun close() = socket.close()
    }

    private fun ecKey() = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(TestCerts.serverKey))

    private fun rsaKey() = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(RsaTestCert.key))

    private fun cert(der: ByteArray) =
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate

    private fun serverContext(rsa: Boolean): SSLContext {
        val ks = KeyStore.getInstance("PKCS12").apply { load(null, null) }
        if (rsa) {
            ks.setKeyEntry("k", rsaKey(), CharArray(0), arrayOf(cert(RsaTestCert.leaf)))
        } else {
            ks.setKeyEntry("k", ecKey(), CharArray(0), arrayOf(cert(TestCerts.server)))
        }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, CharArray(0)) }
        return SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
    }

    private fun jdkServer(
        protocols: Array<String>,
        suites: Array<String>? = null,
        rsa: Boolean = false,
    ): JdkServer {
        val ss = serverContext(rsa).serverSocketFactory.createServerSocket(0, 50, InetAddress.getByName("127.0.0.1")) as SSLServerSocket
        ss.enabledProtocols = protocols
        if (suites != null) ss.enabledCipherSuites = suites
        ss.sslParameters = ss.sslParameters.apply { applicationProtocols = arrayOf("http/1.1") }
        val handshakes = java.util.concurrent.LinkedBlockingQueue<Result<String>>()
        thread(isDaemon = true, name = "jdk-tls-server") {
            while (!ss.isClosed) {
                val s = runCatching { ss.accept() as SSLSocket }.getOrNull() ?: break
                thread(isDaemon = true) {
                    s.use {
                        val r =
                            runCatching {
                                s.startHandshake()
                                "${s.session.protocol} ${s.session.cipherSuite}"
                            }
                        handshakes += r
                        if (r.isSuccess) {
                            runCatching {
                                val input = s.inputStream
                                var last = 0
                                var seen = 0
                                // the request head, up to its empty line
                                while (seen < 4) {
                                    val b = input.read()
                                    if (b < 0) break
                                    seen = if ((b == '\r'.code && seen % 2 == 0) || (b == '\n'.code && seen % 2 == 1)) seen + 1 else 0
                                    last = b
                                }
                                check(last == '\n'.code)
                                s.outputStream.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".toByteArray())
                                s.outputStream.flush()
                            }
                        }
                    }
                }
            }
        }
        return JdkServer(ss, handshakes)
    }

    /** A JDK client handshake with [suite] over TLS 1.2, trusting anything: whether the server can serve that suite at all. */
    private fun jdkClientCanUse(
        port: Int,
        suite: String,
    ): Boolean {
        val trustAll =
            object : X509TrustManager {
                override fun checkClientTrusted(
                    chain: Array<out X509Certificate>?,
                    authType: String?,
                ) = Unit

                override fun checkServerTrusted(
                    chain: Array<out X509Certificate>?,
                    authType: String?,
                ) = Unit

                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
        val ctx = SSLContext.getInstance("TLS").apply { init(null, arrayOf<TrustManager>(trustAll), null) }
        return runCatching {
            (ctx.socketFactory.createSocket() as SSLSocket).use { s ->
                s.connect(InetSocketAddress("127.0.0.1", port), 5_000)
                s.soTimeout = 5_000
                s.enabledProtocols = arrayOf("TLSv1.2")
                s.enabledCipherSuites = arrayOf(suite)
                s.startHandshake()
                s.session.cipherSuite == suite
            }
        }.getOrDefault(false)
    }

    private fun diagnosticsOf(r: io.ktor.client.statement.HttpResponse): TcpConnectionSnapshot =
        assertIs<TcpConnectionSnapshot>(assertNotNull(r.kuicksilverDiagnostics).connection)

    /**
     * The default client is served by a server that has TLS 1.2 alone, over an ECDHE + AEAD suite of the profile, and the call's
     * diagnostics say TLS 1.2; with a TLS 1.3 server it is TLS 1.3. `versions = Tls13` (the opt-in) refuses the 1.2 server.
     */
    @Test fun defaultClientIsServedByATls12OnlyServer() =
        clientTest {
            jdkServer(arrayOf("TLSv1.2")).use { n ->
                testClient().use { c ->
                    val r = c.get("https://127.0.0.1:${n.port}/")
                    assertEquals("ok", r.bodyAsText())
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                    val d = diagnosticsOf(r)
                    assertEquals(TlsVersion.Tls12, d.tlsVersion)
                    assertTrue("tls=Tls12" in d.toString(), "$d")
                }
                val served = n.next().getOrThrow()
                assertTrue(
                    served.startsWith("TLSv1.2 TLS_ECDHE_ECDSA_WITH_") &&
                        listOf("_GCM_SHA256", "_GCM_SHA384", "_CHACHA20_POLY1305_SHA256").any { served.endsWith(it) },
                    served,
                )
                testClient(engine = { tls { versions = TlsVersions.Tls13 } }).use { c ->
                    val e = assertFailsWith<Throwable> { c.get("https://127.0.0.1:${n.port}/") }
                    val alert = generateSequence(e) { it.cause }.filterIsInstance<TlsException.AlertReceived>().firstOrNull()
                    assertEquals("protocol_version", alert?.description, "$e")
                }
            }
            jdkServer(arrayOf("TLSv1.3", "TLSv1.2")).use { n ->
                testClient().use { c ->
                    val r = c.get("https://127.0.0.1:${n.port}/")
                    assertEquals("ok", r.bodyAsText())
                    assertEquals(TlsVersion.Tls13, diagnosticsOf(r).tlsVersion)
                }
            }
        }

    /**
     * Self-attack, RFC 9325 section 4.1 and RFC 10015: TLS 1.2 servers that offer only CBC suites (with SHA-1 and SHA-2 MACs),
     * static RSA key exchange or finite-field DHE (with AES-GCM, so the AEAD alone does not decide). A JDK client gets each one
     * served (the control: the server really would), the default client gets no handshake: it never offers them. The same
     * server with an ECDHE + AEAD suite serves the client.
     */
    @Test fun negative_tls12ServerWithOnlyWeakSuitesIsRefused() =
        clientTest {
            val weak =
                listOf(
                    false to "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                    false to "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                    true to "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                    true to "TLS_RSA_WITH_AES_128_GCM_SHA256",
                    true to "TLS_RSA_WITH_AES_256_CBC_SHA256",
                    true to "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                )
            for ((rsa, suite) in weak) {
                jdkServer(arrayOf("TLSv1.2"), arrayOf(suite), rsa).use { n ->
                    assertTrue(jdkClientCanUse(n.port, suite), "control: the JDK server serves $suite")
                    assertTrue(n.next().isSuccess, "$suite: the control's handshake")
                    testClient().use { c ->
                        val e = assertFailsWith<Throwable>(suite) { c.get("https://127.0.0.1:${n.port}/") }
                        val alert = generateSequence(e) { it.cause }.filterIsInstance<TlsException.AlertReceived>().firstOrNull()
                        assertEquals("handshake_failure", alert?.description, "$suite: $e")
                    }
                    val ours = n.next()
                    assertTrue(ours.isFailure, "$suite: our client's handshake failed on the server too: $ours")
                }
            }
            jdkServer(arrayOf("TLSv1.2"), arrayOf("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")).use { n ->
                testClient().use { c -> assertEquals("ok", c.get("https://127.0.0.1:${n.port}/").bodyAsText()) }
                assertEquals("TLSv1.2 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", n.next().getOrThrow())
            }
        }

    /** Pins (RFC 7469 style, [TrustConfig.Pinned]) hold over TLS 1.2: a key that is not pinned fails, the pinned one passes. */
    @Test fun negative_pinsHoldOverTls12() =
        clientTest {
            jdkServer(arrayOf("TLSv1.2")).use { n ->
                val spki = SpkiSha256(MessageDigest.getInstance("SHA-256").digest(cert(TestCerts.server).publicKey.encoded))
                val other = SpkiSha256(ByteArray(32) { 7 })
                testClient(engine = { tls { trust = TrustConfig.Pinned(setOf(other), base = ClientFixtures.trust) } }).use { c ->
                    val e = assertFailsWith<Throwable> { c.get("https://127.0.0.1:${n.port}/") }
                    val v = generateSequence(e) { it.cause }.filterIsInstance<TlsException.Verify>().firstOrNull()
                    assertIs<VerifyReason.PinMismatch>(v?.reason, "$e")
                }
                testClient(engine = { tls { trust = TrustConfig.Pinned(setOf(spki), base = ClientFixtures.trust) } }).use { c ->
                    val r = c.get("https://127.0.0.1:${n.port}/")
                    assertEquals("ok", r.bodyAsText())
                    assertEquals(TlsVersion.Tls12, diagnosticsOf(r).tlsVersion)
                }
            }
        }
}
