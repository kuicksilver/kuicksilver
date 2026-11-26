// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class) // the client's http2 {} and hardDelay

package io.kuicksilver.sample.http3

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.engine.EmbeddedServer
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.ktor.server.EngineMain
import io.kuicksilver.ktor.server.KuicksilverApplicationEngine
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue
import kotlin.time.Duration

/**
 * The sample as it ships: `EngineMain` with its `application.conf` (the test only points the TLS keys at its own PEM
 * files and binds 127.0.0.1 on a free port), and the Kuicksilver Ktor client against it.
 */
class Http3ServerTest {
    private class Running(
        val server: EmbeddedServer<KuicksilverApplicationEngine, KuicksilverApplicationEngine.Configuration>,
        val port: Int,
        /** The test's PEM files, deleted with the server. */
        val dir: File,
    ) : AutoCloseable {
        val url = "https://127.0.0.1:$port/"

        override fun close() {
            server.stop(100, 2_000)
            dir.deleteRecursively()
        }
    }

    /** The server from `application.conf`, with [overrides] as `-P:` arguments, as a deployment passes them. */
    private fun start(vararg overrides: String): Running {
        val dir = createTempDirectory("http3-server-test").toFile()
        val chain = File(dir, "chain.pem").apply { writeText(TestCerts.chainPem) }
        val key = File(dir, "key.pem").apply { writeText(TestCerts.keyPem) }
        val args =
            arrayOf("-host=127.0.0.1", "-port=0", "-P:kuicksilver.tls.certificateChain=$chain", "-P:kuicksilver.tls.privateKey=$key") +
                overrides.map { "-P:$it" }
        val server =
            try {
                EngineMain.createServer(args).start(wait = false)
            } catch (e: Throwable) {
                dir.deleteRecursively()
                throw e
            }
        return Running(server, runBlocking { server.engine.resolvedConnectors().first().port }, dir)
    }

    private fun client(
        discovery: Http3DiscoveryMode,
        http2: Boolean = true,
    ) = HttpClient(Kuicksilver) {
        engine {
            trust = TrustConfig.AnchoredCa(Certificate.parsePem(TestCerts.caPem))
            http2 { enabled = http2 }
            http3 {
                this.discovery = discovery
                // the second request waits for QUIC instead of racing it against the open HTTP/2 connection, which on a
                // network where QUIC was never seen gets a 10 ms head start only (docs/guide/ktor.md, "Racing and fallback")
                hardDelay = Duration.INFINITE
            }
        }
    }

    private suspend fun HttpResponse.line() = bodyAsText().trim()

    /** What a browser does: HTTP/2 over TCP first, `Alt-Svc` in the answer, then HTTP/3 over UDP on the same port. */
    @Test fun altSvcLeadsTheClientToHttp3() =
        start().use { s ->
            runBlocking {
                client(Http3DiscoveryMode.Auto).use { c ->
                    val first = c.get(s.url)
                    assertEquals(HttpProtocolVersion.HTTP_2_0, first.version)
                    assertEquals("h3=\":${s.port}\"; ma=86400", first.headers["Alt-Svc"])
                    assertEquals("Hello over HTTP/2 from 127.0.0.1", first.line())
                    val second = c.get(s.url)
                    assertEquals(HttpProtocolVersion.HTTP_3_0, second.version)
                    assertEquals("Hello over HTTP/3 from 127.0.0.1", second.line())
                }
            }
        }

    /** `curl --http3-only`: HTTP/3 by prior knowledge, no TCP at all. */
    @Test fun http3OnlyClient() =
        start().use { s ->
            runBlocking {
                client(Http3DiscoveryMode.H3Only).use { c ->
                    val r = c.get(s.url)
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertEquals("Hello over HTTP/3 from 127.0.0.1", r.line())
                }
            }
        }

    /** A client without HTTP/2 or HTTP/3 (an old HTTP stack) is served HTTP/1.1 on the same port, and told about HTTP/3. */
    @Test fun http11FallbackOnTheSamePort() =
        start().use { s ->
            runBlocking {
                client(Http3DiscoveryMode.H1Only, http2 = false).use { c ->
                    val r = c.get(s.url)
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                    assertEquals("h3=\":${s.port}\"; ma=86400", r.headers["Alt-Svc"])
                    assertEquals("Hello over HTTP/1.1 from 127.0.0.1", r.line())
                }
            }
        }

    /**
     * Behind HAProxy (`send-proxy-v2`) or nginx (`proxy_protocol on`): the TCP connection starts with the PROXY header, before
     * TLS, and the application sees the client it names. `ALT_SVC=false` as the README says for a proxy that does not
     * forward UDP.
     */
    @Test fun proxyProtocolNamesTheClient() =
        start("kuicksilver.proxyProtocol.trustedSources=127.0.0.1/32", "kuicksilver.altSvc=false").use { s ->
            val raw = Socket()
            raw.connect(InetSocketAddress("127.0.0.1", s.port), 10_000)
            raw.soTimeout = 10_000
            raw.getOutputStream().write("PROXY TCP4 203.0.113.7 127.0.0.1 51234 ${s.port}\r\n".toByteArray())
            val tls = trustingTestCa().socketFactory.createSocket(raw, "localhost", s.port, true) as SSLSocket
            tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" } // check the name, as any client
            tls.use {
                it.outputStream.write("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".toByteArray())
                val response = it.inputStream.readBytes().decodeToString()
                assertEquals("HTTP/1.1 200 OK", response.lineSequence().first())
                assertEquals("Hello over HTTP/1.1 from 203.0.113.7", response.substringAfter("\r\n\r\n").trim())
                assertEquals(null, Regex("(?im)^alt-svc:").find(response)?.value)
            }
        }

    /** With the PROXY protocol on, a TCP client that sends no header is refused: nobody chooses their own address. */
    @Test fun negative_proxyProtocolRefusesAClientWithoutHeader() =
        start("kuicksilver.proxyProtocol.trustedSources=127.0.0.1/32", "kuicksilver.altSvc=false").use { s ->
            runBlocking {
                client(Http3DiscoveryMode.H1Only).use { c ->
                    // reset at accept, before TLS: the client's read fails with "Connection reset" (closed, on some systems)
                    val e = assertFails { c.get(s.url) }
                    val chain = generateSequence(e) { it.cause }.toList()
                    val resetOrClosed = Regex("reset|closed", RegexOption.IGNORE_CASE)
                    assertTrue(
                        chain.any { it is IOException && resetOrClosed.containsMatchIn(it.message.orEmpty()) },
                        "not a reset or closed connection: ${chain.joinToString(" <- ") { "${it::class.simpleName}: ${it.message}" }}",
                    )
                }
                // HTTP/3 takes no header (UDP): it still works, and reports the UDP peer
                client(Http3DiscoveryMode.H3Only).use { c -> assertEquals("Hello over HTTP/3 from 127.0.0.1", c.get(s.url).line()) }
            }
        }

    private fun trustingTestCa(): SSLContext {
        val ca = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(TestCerts.caPem.toByteArray()))
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null); setCertificateEntry("ca", ca) }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
        return SSLContext.getInstance("TLSv1.3").apply { init(null, tmf.trustManagers, null) }
    }
}
