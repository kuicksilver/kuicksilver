// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.ktor.server

import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * HTTP/2 is on by default on the TLS connectors since 0.3.0 (ADR-0026): ALPN offers `h2`, then `http/1.1`, and the server's
 * order wins (RFC 7301 section 3.2); `http2 { enabled = false }` keeps `http/1.1` alone.
 */
class ServerDefaultAlpnJvmTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Only ALPN is looked at: the handshake's certificate is accepted whatever it is. */
    private val anyCertificate =
        object : X509TrustManager {
            override fun checkClientTrusted(
                chain: Array<X509Certificate>,
                authType: String,
            ) {}

            override fun checkServerTrusted(
                chain: Array<X509Certificate>,
                authType: String,
            ) {}

            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }

    private suspend fun alpnOf(
        port: Int,
        offered: List<String>,
    ): String? =
        withContext(Dispatchers.IO) {
            val ctx = SSLContext.getInstance("TLSv1.3").apply { init(null, arrayOf(anyCertificate), null) }
            (ctx.socketFactory.createSocket("127.0.0.1", port) as SSLSocket).use { s ->
                s.sslParameters =
                    s.sslParameters.apply {
                        applicationProtocols = offered.toTypedArray()
                        serverNames = listOf(SNIHostName("server.test"))
                    }
                s.startHandshake()
                s.applicationProtocol
            }
        }

    @Test fun defaultTlsConnectorNegotiatesH2() =
        serverTest {
            val (server, port) =
                tlsServer(configure = { http3 { enabled = false } }) {
                    routing { get("/") { call.respondText("ok") } }
                }
            try {
                assertEquals("h2", alpnOf(port, listOf("h2", "http/1.1")))
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun alpnOrderIsH2ThenHttp11() =
        serverTest {
            val (server, port) =
                tlsServer(configure = { http3 { enabled = false } }) {
                    routing { get("/") { call.respondText("ok") } }
                }
            try {
                assertEquals("h2", alpnOf(port, listOf("http/1.1", "h2")), "the server's order wins")
                assertEquals("http/1.1", alpnOf(port, listOf("http/1.1")))
            } finally {
                server.stop(100, 500)
            }
            val (off, offPort) =
                tlsServer(configure = {
                    http3 { enabled = false }
                    http2 { enabled = false }
                }) {
                    routing { get("/") { call.respondText("ok") } }
                }
            try {
                assertEquals("http/1.1", alpnOf(offPort, listOf("h2", "http/1.1")), "HTTP/2 turned off")
            } finally {
                off.stop(100, 500)
            }
        }
}
