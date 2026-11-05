// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.server.request.httpVersion
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.net.Socket
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Duration
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager
import javax.net.ssl.X509TrustManager
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The server's HTTP/2 against a client that is not ours: the JDK's `java.net.http.HttpClient` (HTTP/2 over TLS with ALPN,
 * its own HPACK, flow control and stream handling). The test certificate names `server.test`, so the trust manager checks
 * the chain against the test CA and leaves the name out (the connection goes to 127.0.0.1).
 */
class ServerH2JdkClientTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun jdkClient(): HttpClient {
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
        val ctx = SSLContext.getInstance("TLSv1.3").apply { init(null, arrayOf(tm), null) }
        return HttpClient
            .newBuilder()
            .version(HttpClient.Version.HTTP_2)
            .sslContext(ctx)
            .connectTimeout(Duration.ofSeconds(10))
            .build()
    }

    @Test fun jdkClientOverH2() =
        serverTest {
            val (server, port) =
                tlsServer(configure = {
                    http2 = true
                    http3 = false
                }) {
                    routing {
                        get("/hello") { call.respondText("hello ${call.request.httpVersion}") }
                        post("/echo") { call.respondText(call.receiveText().reversed()) }
                    }
                }
            try {
                val c = jdkClient()
                val base = "https://127.0.0.1:$port"
                withContext(Dispatchers.IO) {
                    val get = c.send(HttpRequest.newBuilder(URI("$base/hello")).build(), HttpResponse.BodyHandlers.ofString())
                    assertEquals(HttpClient.Version.HTTP_2, get.version())
                    assertEquals(200, get.statusCode())
                    assertEquals("hello HTTP/2", get.body())
                    val body = "x".repeat(200_000) + "y"
                    val post =
                        c.send(
                            HttpRequest.newBuilder(URI("$base/echo")).POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                            HttpResponse.BodyHandlers.ofString(),
                        )
                    assertEquals(HttpClient.Version.HTTP_2, post.version())
                    assertEquals(body.reversed(), post.body())
                    // many requests at once share the connection (multiplexed streams)
                    coroutineScope {
                        (1..50)
                            .map {
                                async {
                                    c.send(HttpRequest.newBuilder(URI("$base/hello")).build(), HttpResponse.BodyHandlers.ofString()).body()
                                }
                            }.awaitAll()
                            .forEach { assertEquals("hello HTTP/2", it) }
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** The 431 the connection makes itself for a field section above the limit carries Date (RFC 9110 section 6.6.1). */
    @Test fun oversizedFieldSectionGets431WithDate() =
        serverTest {
            val (server, port) =
                tlsServer(configure = {
                    http2 = true
                    http3 = false
                    http2Settings = io.kuicksilver.http2.Http2Settings(maxHeaderListSize = 1024)
                }) { routing { get("/") { call.respondText("never") } } }
            try {
                val r =
                    withContext(Dispatchers.IO) {
                        jdkClient().send(
                            HttpRequest.newBuilder(URI("https://127.0.0.1:$port/")).header("x-big", "a".repeat(1500)).build(),
                            HttpResponse.BodyHandlers.ofString(),
                        )
                    }
                assertEquals(HttpClient.Version.HTTP_2, r.version())
                assertEquals(431, r.statusCode())
                kotlin.test.assertTrue(r.headers().firstValue("date").isPresent, "${r.headers().map()}")
            } finally {
                server.stop(100, 500)
            }
        }
}
