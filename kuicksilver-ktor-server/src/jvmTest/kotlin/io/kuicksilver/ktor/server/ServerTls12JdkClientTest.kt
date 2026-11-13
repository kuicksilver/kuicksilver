// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.TlsVersions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.File
import java.net.InetAddress
import java.net.Socket
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager
import javax.net.ssl.X509TrustManager
import kotlin.system.exitProcess
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * TLS 1.2 on a TLS connector against the JDK's own TLS 1.2 client (RFC 9325 section 3.1.1: "Implementations MUST support TLS
 * 1.2"): served only with `versions = TlsVersions.Tls12And13`, under the RFC 9325 profile.
 */
class ServerTls12JdkClientTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val get = "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n"

    /** A JDK TLS 1.2 socket to [port] offering [alpn] and, when given, only [suites] in that order; the handshake is done. */
    private fun jdkTls12(
        port: Int,
        alpn: String,
        suites: List<String>? = null,
    ): SSLSocket {
        val s = jdkContext().socketFactory.createSocket(InetAddress.getLoopbackAddress(), port) as SSLSocket
        s.soTimeout = 20_000
        s.sslParameters =
            s.sslParameters.apply {
                protocols = arrayOf("TLSv1.2")
                applicationProtocols = arrayOf(alpn)
                serverNames = listOf(javax.net.ssl.SNIHostName("server.test"))
                if (suites != null) cipherSuites = suites.toTypedArray()
            }
        try {
            s.startHandshake()
        } catch (e: Throwable) {
            s.close()
            throw e
        }
        return s
    }

    private fun SSLSocket.http(request: String): String {
        outputStream.write(request.encodeToByteArray())
        outputStream.flush()
        return inputStream.readBytes().decodeToString()
    }

    @Test fun jdkTls12ClientOverHttp11() =
        serverTest {
            val (server, port) =
                tlsServer(configure = { http3 = false }, connector = { versions = TlsVersions.Tls12And13 }) {
                    routing { get("/") { call.respondText("jdk ${call.request.httpVersion}") } }
                }
            try {
                withContext(Dispatchers.IO) {
                    // RFC 9325 section 4.2.1: AES-128 offered first, AES-256 too: the server prefers the stronger suite
                    jdkTls12(
                        port,
                        "http/1.1",
                        listOf("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
                    ).use { s ->
                        assertEquals("TLSv1.2", s.session.protocol)
                        assertEquals("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", s.session.cipherSuite)
                        assertEquals("http/1.1", s.applicationProtocol)
                        val resp = s.http(get)
                        assertTrue(resp.startsWith("HTTP/1.1 200") && resp.endsWith("jdk HTTP/1.1"), resp)
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 9846 section 4.1.3: "If negotiating TLS 1.2, TLS 1.3 servers MUST set the last 8 bytes of their Random value to the
     * bytes: 44 4F 57 4E 47 52 44 01", so a client with TLS 1.3 detects an attacker who removed it from its offer.
     */
    @Test fun tls12ServerHelloCarriesTheDowngradeSentinel() =
        serverTest {
            val (server, port) =
                tlsServer(configure = { http3 = false }, connector = { versions = TlsVersions.Tls12And13 }) {
                    routing { get("/") { call.respondText("ok") } }
                }
            try {
                val fromServer = withContext(Dispatchers.IO) { relayed(port) { relay -> jdkTls12(relay, "http/1.1").close() } }
                // record header (5), handshake header (4: type 2, ServerHello), legacy_version (2), random (32)
                assertEquals(22, fromServer[0].toInt(), "a handshake record first")
                assertEquals(2, fromServer[5].toInt(), "a ServerHello")
                assertEquals(listOf<Byte>(3, 3), fromServer.copyOfRange(9, 11).toList(), "TLS 1.2")
                assertEquals(
                    "444f574e47524401",
                    fromServer.copyOfRange(35, 43).joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') },
                )
            } finally {
                server.stop(100, 500)
            }
        }

    /** The default connector refuses the JDK's TLS 1.2 client with protocol_version (RFC 9846 appendix E.2). */
    @Test fun negative_defaultConnectorRefusesJdkTls12() =
        serverTest {
            val (server, port) = tlsServer(configure = { http3 = false }) { routing { get("/") { call.respondText("no") } } }
            try {
                val e = withContext(Dispatchers.IO) { assertFailsWith<SSLHandshakeException> { jdkTls12(port, "http/1.1").close() } }
                assertContains(e.message.orEmpty(), "protocol_version")
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 9325 section 4.1 (no static RSA: "Implementations SHOULD NOT negotiate cipher suites based on RSA key transport"),
     * section 4.2 (CBC "SHOULD NOT be used unless the encrypt_then_mac extension [RFC7366] is also successfully negotiated";
     * ksl offers no CBC at all) and RFC 10015 (ECDHE only in TLS 1.2): a client that offers nothing else is refused.
     */
    @Test fun negative_cbcSha1AndStaticRsaOnlyClientsRefused() =
        serverTest {
            val (server, port) =
                tlsServer(configure = { http3 = false }, connector = { versions = TlsVersions.Tls12And13 }) {
                    routing { get("/") { call.respondText("ok") } }
                }
            try {
                withContext(Dispatchers.IO) {
                    jdkTls12(port, "http/1.1").use { assertTrue(it.http(get).endsWith("ok"), "control: the JDK's default suites") }
                    val refused =
                        listOf(
                            listOf("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"),
                            listOf("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
                            listOf("TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384"),
                        )
                    for (suites in refused) {
                        val supported = jdkContext().supportedSSLParameters.cipherSuites.toSet()
                        val offered = suites.filter { it in supported }
                        if (offered.isEmpty()) continue // a JDK that dropped them all cannot offer them
                        val e = assertFailsWith<SSLHandshakeException>("$offered") { jdkTls12(port, "http/1.1", offered).close() }
                        assertContains(e.message.orEmpty(), "handshake_failure", message = "$offered")
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** HTTP/2 over TLS 1.2 (RFC 9113 section 9.2) with the JDK's HttpClient capped at TLS 1.2. */
    @Test fun jdkTls12ClientOverH2() =
        serverTest {
            val (server, port) =
                tlsServer(configure = {
                    http3 = false
                    http2 = true
                }, connector = { versions = TlsVersions.Tls12And13 }) {
                    routing { get("/") { call.respondText("h2 ${call.request.httpVersion}") } }
                }
            try {
                val client =
                    HttpClient
                        .newBuilder()
                        .version(HttpClient.Version.HTTP_2)
                        .sslContext(jdkContext())
                        .sslParameters(
                            javax.net.ssl
                                .SSLParameters()
                                .apply { protocols = arrayOf("TLSv1.2") },
                        ).connectTimeout(java.time.Duration.ofSeconds(10))
                        .build()
                val r =
                    withContext(Dispatchers.IO) {
                        client.send(HttpRequest.newBuilder(URI("https://127.0.0.1:$port/")).build(), HttpResponse.BodyHandlers.ofString())
                    }
                assertEquals(HttpClient.Version.HTTP_2, r.version())
                assertEquals("h2 HTTP/2", r.body())
                assertEquals("TLSv1.2", r.sslSession().get().protocol)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 9113 section 9.2.1: "A deployment of HTTP/2 over TLS 1.2 MUST disable renegotiation. An endpoint MUST treat a TLS
     * renegotiation as a connection error (Section 5.4.1) of type PROTOCOL_ERROR." The JDK client renegotiates once the
     * connection's SETTINGS are exchanged; the server refuses (a no_renegotiation warning) and ends the connection with a
     * GOAWAY. The JDK client gives up at the warning (as OpenSSL's would) and never reads the GOAWAY, so the test looks at the
     * records the server sent, through a relay: TLS 1.2 record types travel in the clear, and after the warning comes an
     * application_data record (the GOAWAY, which carries the reason as debug data), then close_notify. Taken for a lost
     * connection, the GOAWAY would be INTERNAL_ERROR without debug data.
     */
    @Test fun negative_renegotiationOnH2EndsWithGoaway() =
        serverTest {
            val (server, port) =
                tlsServer(configure = {
                    http3 = false
                    http2 = true
                    altSvc = false
                }, connector = { versions = TlsVersions.Tls12And13 }) { routing { get("/") { call.respondText("h2") } } }
            try {
                val fromServer = withContext(Dispatchers.IO) { relayed(port) { relay -> renegotiateAfterSettings(relay) } }
                val records = records(fromServer)
                val types = records.map { it.first }
                val firstData = types.indexOf(23)
                val warning = types.withIndex().firstOrNull { it.index > firstData && it.value == 21 }?.index
                assertTrue(firstData >= 0 && warning != null, "no alert after the handshake: $records")
                assertEquals(listOf(23, 21), types.drop(warning + 1).take(2), "after the warning: the GOAWAY, then close_notify ($records)")
                // a lost connection gets GOAWAY INTERNAL_ERROR without debug data: 17 bytes, 41 in an AES-GCM record (8-byte
                // explicit nonce, 16-byte tag); the connection error carries its reason, the renegotiation, as debug data
                assertTrue(records[warning + 1].second > 41, "the GOAWAY carries no reason, as for a lost connection: $records")
            } finally {
                server.stop(100, 500)
            }
        }

    /** A JDK TLS 1.2 `h2` connection through [relay]: the preface, SETTINGS both ways, then a renegotiation; the client's failure is expected. */
    private fun renegotiateAfterSettings(relay: Int) {
        jdkTls12(relay, "h2").use { s ->
            assertEquals("h2", s.applicationProtocol)
            val out = s.outputStream
            out.write("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".encodeToByteArray())
            out.write(byteArrayOf(0, 0, 0, 4, 0, 0, 0, 0, 0)) // SETTINGS, empty
            out.flush()
            val input = DataInputStream(s.inputStream)
            // the server's SETTINGS and its ACK of ours: nothing more is due from it before the renegotiation
            var acked = false
            var settings = false
            while (!(acked && settings)) {
                val (type, flags) = readFrame(input).let { it.first to it.third }
                if (type == 4 && flags and 1 == 1) {
                    acked = true
                } else if (type == 4) {
                    settings = true
                }
            }
            out.write(byteArrayOf(0, 0, 0, 4, 1, 0, 0, 0, 0)) // SETTINGS ACK
            out.flush()
            s.startHandshake() // TLS 1.2 established: a renegotiation ClientHello
            val e = assertFailsWith<SSLHandshakeException> { while (true) readFrame(input) }
            assertContains(e.message.orEmpty(), "no_renegotiation")
        }
    }

    /**
     * Runs [client] against a loopback relay to [port] and returns every byte the server sent, until it closed. The relay
     * keeps reading the server after the client gave up.
     */
    private fun relayed(
        port: Int,
        client: (Int) -> Unit,
    ): ByteArray {
        val listener = java.net.ServerSocket(0, 1, InetAddress.getLoopbackAddress())
        val captured = java.io.ByteArrayOutputStream()
        val done = java.util.concurrent.CountDownLatch(1)
        val relay =
            Thread {
                runCatching {
                    listener.accept().use { c ->
                        Socket(InetAddress.getLoopbackAddress(), port).use { up ->
                            val toServer =
                                Thread {
                                    runCatching { c.getInputStream().copyTo(up.getOutputStream()) }
                                    runCatching { up.shutdownOutput() }
                                }.apply { isDaemon = true }
                            toServer.start()
                            val buf = ByteArray(16 * 1024)
                            val upIn = up.getInputStream()
                            up.soTimeout = 20_000
                            while (true) {
                                val n = runCatching { upIn.read(buf) }.getOrDefault(-1)
                                if (n < 0) break
                                synchronized(captured) { captured.write(buf, 0, n) }
                                runCatching { c.getOutputStream().write(buf, 0, n) }
                            }
                        }
                    }
                }
                done.countDown()
            }.apply { isDaemon = true }
        relay.start()
        try {
            client(listener.localPort)
            assertTrue(done.await(20, TimeUnit.SECONDS), "the server did not close the connection within 20 s")
        } finally {
            listener.close()
        }
        return synchronized(captured) { captured.toByteArray() }
    }

    /** The content type and length of each TLS record in [bytes] (RFC 5246 section 6.2.1: type, version, 16-bit length). */
    private fun records(bytes: ByteArray): List<Pair<Int, Int>> {
        val out = ArrayList<Pair<Int, Int>>()
        var i = 0
        while (i + 5 <= bytes.size) {
            val length = ((bytes[i + 3].toInt() and 0xff) shl 8) or (bytes[i + 4].toInt() and 0xff)
            out += (bytes[i].toInt() and 0xff) to length
            i += 5 + length
        }
        return out
    }

    /** One HTTP/2 frame: its type, payload and flags. */
    private fun readFrame(input: DataInputStream): Triple<Int, ByteArray, Int> {
        val head = ByteArray(9)
        input.readFully(head)
        val length = ((head[0].toInt() and 0xff) shl 16) or ((head[1].toInt() and 0xff) shl 8) or (head[2].toInt() and 0xff)
        val payload = ByteArray(length)
        input.readFully(payload)
        return Triple(head[3].toInt() and 0xff, payload, head[4].toInt() and 0xff)
    }

    /**
     * RFC 9325 section 3.5: "TLS 1.2 implementations MUST support the extended_master_secret extension defined in [RFC7627]";
     * RFC 7627 section 5.2: "If the server receives a ClientHello without the extension, it SHOULD abort the handshake if it does
     * not wish to interoperate with legacy clients." The JDK client leaves the extension out only when
     * `jdk.tls.useExtendedMasterSecret` is false when its TLS classes load, so it runs in a JVM of its own.
     */
    @Test fun negative_jdkTls12ClientWithoutEmsRefused() =
        serverTest {
            val (server, port) =
                tlsServer(configure = { http3 = false }, connector = { versions = TlsVersions.Tls12And13 }) {
                    routing { get("/") { call.respondText("ems") } }
                }
            try {
                withContext(Dispatchers.IO) {
                    assertEquals("OK TLSv1.2", forkedProbe(port, ems = true), "control: with Extended Master Secret")
                    val refused = forkedProbe(port, ems = false)
                    assertTrue(refused.startsWith("FAIL") && "handshake_failure" in refused, refused)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Runs [Tls12ProbeMain] in a JVM of its own; returns the last line it printed. */
    private fun forkedProbe(
        port: Int,
        ems: Boolean,
    ): String {
        val javaBin = File(System.getProperty("java.home"), "bin/java").path
        val argFile = File.createTempFile("tls12-probe", ".args")
        try {
            val cp = System.getProperty("java.class.path").replace("\\", "\\\\").replace("\"", "\\\"")
            val charset =
                System.getProperty("native.encoding")?.let {
                    runCatching {
                        java.nio.charset.Charset
                            .forName(it)
                    }.getOrNull()
                }
                    ?: java.nio.charset.Charset
                        .defaultCharset()
            argFile.writeText("-cp\n\"$cp\"\n", charset)
            // the probe uses the JDK's TLS and the test certificates only: no native library, no flags of the test JVM
            val cmd =
                listOf(javaBin, "-Xmx64m", "-Djdk.tls.useExtendedMasterSecret=$ems", "@${argFile.path}") +
                    Tls12ProbeMain::class.java.name + port.toString()
            val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText()
            if (!p.waitFor(60, TimeUnit.SECONDS)) {
                p.destroyForcibly()
                fail("the probe JVM did not end:\n$out")
            }
            return out.trim().lines().last()
        } finally {
            if (!argFile.delete()) argFile.deleteOnExit()
        }
    }
}

/** The test CA as the JDK's trust, with the host name left out (the connection goes to 127.0.0.1). */
internal fun jdkContext(): SSLContext {
    val ca = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(TestCerts.testCa)) as X509Certificate
    val ks =
        KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            setCertificateEntry("ca", ca)
        }
    val chain =
        TrustManagerFactory
            .getInstance(TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(ks) }
            .trustManagers
            .filterIsInstance<X509TrustManager>()
            .first()
    val tm =
        object : X509ExtendedTrustManager() {
            override fun checkServerTrusted(
                c: Array<X509Certificate>,
                a: String,
            ) = chain.checkServerTrusted(c, a)

            override fun checkServerTrusted(
                c: Array<X509Certificate>,
                a: String,
                s: Socket?,
            ) = chain.checkServerTrusted(c, a)

            override fun checkServerTrusted(
                c: Array<X509Certificate>,
                a: String,
                e: SSLEngine?,
            ) = chain.checkServerTrusted(c, a)

            override fun checkClientTrusted(
                c: Array<X509Certificate>,
                a: String,
            ) = error("client side only")

            override fun checkClientTrusted(
                c: Array<X509Certificate>,
                a: String,
                s: Socket?,
            ) = error("client side only")

            override fun checkClientTrusted(
                c: Array<X509Certificate>,
                a: String,
                e: SSLEngine?,
            ) = error("client side only")

            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf(ca)
        }
    return SSLContext.getInstance("TLS").apply { init(null, arrayOf(tm), null) }
}

/**
 * The forked JVM of [ServerTls12JdkClientTest.negative_jdkTls12ClientWithoutEmsRefused]: a TLS 1.2 handshake with the port of
 * its argument; prints `OK <protocol>` or `FAIL <reason>`.
 */
object Tls12ProbeMain {
    @JvmStatic fun main(args: Array<String>) {
        val line =
            runCatching {
                (jdkContext().socketFactory.createSocket(InetAddress.getLoopbackAddress(), args[0].toInt()) as SSLSocket).use { s ->
                    s.soTimeout = 20_000
                    s.sslParameters = s.sslParameters.apply { protocols = arrayOf("TLSv1.2") }
                    s.startHandshake()
                    "OK ${s.session.protocol}"
                }
            }.getOrElse { "FAIL $it" }
        println(line)
        exitProcess(0)
    }
}
