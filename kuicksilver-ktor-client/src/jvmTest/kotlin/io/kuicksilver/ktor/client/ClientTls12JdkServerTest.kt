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
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.charset.Charset
import java.security.KeyFactory
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Security
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
import kotlin.system.exitProcess
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

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

    private fun jdkServer(
        protocols: Array<String>,
        suites: Array<String>? = null,
        rsa: Boolean = false,
    ): JdkServer {
        val ss = jdkServerContext(rsa).serverSocketFactory.createServerSocket(0, 50, InetAddress.getByName("127.0.0.1")) as SSLServerSocket
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

    /**
     * A JDK TLS 1.2 server that offers only [suite], in a JVM of its own ([WeakTls12ServerMain]): the JDK's
     * `jdk.tls.disabledAlgorithms` is read once, when its TLS classes load, and newer JDKs list weak suites there (JDK 25 and
     * Temurin 21.0.13 list `TLS_RSA_*`), so only a fresh JVM that sets its own list first serves each weak suite on every JDK.
     */
    private class ForkedWeakServer(
        val suite: String,
        rsa: Boolean,
    ) : AutoCloseable {
        private val argFile = File.createTempFile("tls12-weak-server", ".args")
        private val process: Process
        private val lines = java.util.concurrent.LinkedBlockingQueue<String>()
        private val output = StringBuffer()

        init {
            val javaBin = File(System.getProperty("java.home"), "bin/java").path
            val cp = System.getProperty("java.class.path").replace("\\", "\\\\").replace("\"", "\\\"")
            val charset =
                System.getProperty("native.encoding")?.let { runCatching { Charset.forName(it) }.getOrNull() } ?: Charset.defaultCharset()
            // the JDK's TLS and the test certificates only: no native library, no flags of the test JVM
            val cmd = listOf(javaBin, "-Xmx64m", "@${argFile.path}", WeakTls12ServerMain::class.java.name, suite, rsa.toString())
            // the argument file goes in close(), once the server JVM (whose launcher reads it as it starts) ended; here only
            // when there is no such JVM
            process =
                try {
                    argFile.writeText("-cp\n\"$cp\"\n", charset)
                    ProcessBuilder(cmd).redirectErrorStream(true).start()
                } catch (e: Throwable) {
                    if (!argFile.delete()) argFile.deleteOnExit()
                    throw e
                }
            thread(isDaemon = true, name = "tls12-weak-server-out") {
                process.inputStream.bufferedReader().forEachLine {
                    output.append(it).append('\n')
                    lines += it
                }
            }
        }

        /** The next line the server JVM printed that starts with [prefix], without it (waits for it, bounded). */
        fun next(prefix: String): String {
            while (true) {
                val l =
                    lines.poll(30, java.util.concurrent.TimeUnit.SECONDS) ?: fail("$suite: no `$prefix` line from the server JVM:\n$output")
                if (l.startsWith(prefix)) return l.removePrefix(prefix)
            }
        }

        override fun close() {
            process.destroyForcibly()
            process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS)
            if (!argFile.delete()) argFile.deleteOnExit()
        }
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
     * served (the control: the server really would, under a policy of the server's own JVM that leaves them enabled on every
     * JDK), the default client gets no handshake: it never offers them. The same server with an ECDHE + AEAD suite serves the
     * client.
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
                ForkedWeakServer(suite, rsa).use { n ->
                    assertEquals("OK TLSv1.2 $suite", n.next("CONTROL "), "control: the JDK server serves $suite")
                    val port = n.next("PORT ").toInt()
                    testClient().use { c ->
                        val e = assertFailsWith<Throwable>(suite) { c.get("https://127.0.0.1:$port/") }
                        val alert = generateSequence(e) { it.cause }.filterIsInstance<TlsException.AlertReceived>().firstOrNull()
                        assertEquals("handshake_failure", alert?.description, "$suite: $e")
                    }
                    val ours = n.next("HANDSHAKE ")
                    assertTrue(ours.startsWith("FAIL"), "$suite: our client's handshake failed on the server too: $ours")
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
                val spki = SpkiSha256(MessageDigest.getInstance("SHA-256").digest(jdkCert(TestCerts.server).publicKey.encoded))
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

private fun jdkCert(der: ByteArray) =
    CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate

/** A JDK server context with the test EC identity (TestCerts.server) or, with [rsa], the RSA 2048 one (RsaTestCert). */
private fun jdkServerContext(rsa: Boolean): SSLContext {
    val ks = KeyStore.getInstance("PKCS12").apply { load(null, null) }
    if (rsa) {
        val key = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(RsaTestCert.key))
        ks.setKeyEntry("k", key, CharArray(0), arrayOf(jdkCert(RsaTestCert.leaf)))
    } else {
        val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(TestCerts.serverKey))
        ks.setKeyEntry("k", key, CharArray(0), arrayOf(jdkCert(TestCerts.server)))
    }
    val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, CharArray(0)) }
    return SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
}

/**
 * The forked JVM of [ClientTls12JdkServerTest.negative_tls12ServerWithOnlyWeakSuitesIsRefused]: a JDK TLS 1.2 server on
 * 127.0.0.1 that offers only the suite of its first argument (with the RSA identity when the second is `true`). It first sets
 * `jdk.tls.disabledAlgorithms` to the JDK 21.0.5 list, which leaves CBC, static RSA and finite-field DHE suites enabled, before
 * any TLS class loads; then a JDK client of its own, trusting anything and offering only that suite, shows that the server serves
 * it (`CONTROL OK <protocol> <suite>`, or `CONTROL FAIL <reason>`). It prints `PORT <port>`, then the outcome of the next handshake
 * (`HANDSHAKE OK ...` or `HANDSHAKE FAIL <reason>`), and ends.
 */
internal object WeakTls12ServerMain {
    @JvmStatic fun main(args: Array<String>) {
        Security.setProperty(
            "jdk.tls.disabledAlgorithms",
            "SSLv3, TLSv1, TLSv1.1, DTLSv1.0, RC4, DES, MD5withRSA, DH keySize < 1024, EC keySize < 224, 3DES_EDE_CBC, anon, NULL, ECDH",
        )
        val suite = args[0]
        val ss =
            jdkServerContext(
                args[1].toBoolean(),
            ).serverSocketFactory.createServerSocket(0, 50, InetAddress.getByName("127.0.0.1")) as SSLServerSocket
        ss.soTimeout = 30_000
        ss.enabledProtocols = arrayOf("TLSv1.2")
        ss.enabledCipherSuites = arrayOf(suite)

        fun handshake(): String =
            runCatching {
                (ss.accept() as SSLSocket).use { s ->
                    s.soTimeout = 10_000
                    s.startHandshake()
                    "OK ${s.session.protocol} ${s.session.cipherSuite}"
                }
            }.getOrElse { "FAIL $it" }
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
        var served: String? = null
        val acceptor = thread(name = "control-accept") { served = handshake() }
        val control =
            runCatching {
                (ctx.socketFactory.createSocket() as SSLSocket).use { s ->
                    s.connect(InetSocketAddress("127.0.0.1", ss.localPort), 10_000)
                    s.soTimeout = 10_000
                    s.enabledProtocols = arrayOf("TLSv1.2")
                    s.enabledCipherSuites = arrayOf(suite)
                    s.startHandshake()
                    "OK ${s.session.protocol} ${s.session.cipherSuite}"
                }
            }.getOrElse { "FAIL $it" }
        acceptor.join()
        println("CONTROL ${if (served?.startsWith("OK") == true) control else "FAIL server side: $served (client side: $control)"}")
        println("PORT ${ss.localPort}")
        println("HANDSHAKE ${handshake()}")
        System.out.flush()
        ss.close()
        exitProcess(0)
    }
}
