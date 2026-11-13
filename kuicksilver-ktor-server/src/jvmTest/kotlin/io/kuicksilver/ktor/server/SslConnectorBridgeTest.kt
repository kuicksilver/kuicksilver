// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.sslConnector
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsVersions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.security.KeyFactory
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocket
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Ktor's `sslConnector { keyStore }` works unchanged with the Kuicksilver engine on the JVM. */
class SslConnectorBridgeTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun keyStore(): KeyStore {
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(TestCerts.server.inputStream())
        val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(TestCerts.serverKey))
        return KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setKeyEntry("server", key, "pw".toCharArray(), arrayOf(cert))
        }
    }

    @Test fun keyStoreTranslatesToIdentity() =
        serverTest {
            val ks = keyStore()
            val server =
                embeddedServer(Kuicksilver, configure = {
                    sslConnector(ks, "server", { "pw".toCharArray() }, { "pw".toCharArray() }) {
                        host =
                            "127.0.0.1"
                        ; port = 0
                    }
                }) {
                    routing { get("/") { call.respondText("from keystore") } }
                }
            server.startSuspend(false)
            try {
                val resp =
                    rawHttp(
                        server.engine
                            .resolvedConnectors()
                            .first()
                            .port,
                        "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n",
                    )
                assertTrue(resp.endsWith("from keystore"), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    /** Ktor's `enabledProtocols` choose the TLS versions; TLS 1.0, 1.1 and TLS 1.2 without 1.3 are refused (RFC 9325 section 3.1.1). */
    @Test fun enabledProtocolsMapToVersions() {
        assertEquals(TlsVersions.Tls13, sslVersions(null))
        assertEquals(TlsVersions.Tls13, sslVersions(listOf("TLSv1.3")))
        assertEquals(TlsVersions.Tls12And13, sslVersions(listOf("TLSv1.3", "TLSv1.2")))
        for (refused in listOf(listOf("TLSv1.2"), listOf("TLSv1.1", "TLSv1.2", "TLSv1.3"), listOf("TLSv1"), emptyList())) {
            assertFailsWith<TlsException.Config>("negative: $refused") { sslVersions(refused) }
        }
    }

    /** `enabledProtocols = listOf("TLSv1.2", "TLSv1.3")` on Ktor's sslConnector serves the JDK's TLS 1.2 client; without it, not. */
    @Test fun enabledProtocolsWithTls12ServeTls12Clients() =
        serverTest {
            val ks = keyStore()
            val servers =
                listOf(listOf("TLSv1.2", "TLSv1.3"), null).map { protocols ->
                    embeddedServer(Kuicksilver, configure = {
                        http3 = false
                        sslConnector(ks, "server", { "pw".toCharArray() }, { "pw".toCharArray() }) {
                            host = "127.0.0.1"
                            port = 0
                            enabledProtocols = protocols
                        }
                    }) { routing { get("/") { call.respondText("tls12 via keystore") } } }
                }
            servers.forEach { it.startSuspend(false) }
            try {
                val (allowed, default) =
                    servers.map {
                        it.engine
                            .resolvedConnectors()
                            .first()
                            .port
                    }
                withContext(Dispatchers.IO) {
                    tls12Handshake(allowed).use { assertEquals("TLSv1.2", it.session.protocol) }
                    val e = assertFailsWith<SSLHandshakeException> { tls12Handshake(default).close() }
                    assertContains(e.message.orEmpty(), "protocol_version")
                }
            } finally {
                servers.forEach { it.stop(100, 500) }
            }
        }

    private fun tls12Handshake(port: Int): SSLSocket =
        (jdkContext().socketFactory.createSocket(InetAddress.getLoopbackAddress(), port) as SSLSocket).apply {
            soTimeout = 20_000
            sslParameters = sslParameters.apply { protocols = arrayOf("TLSv1.2") }
            try {
                startHandshake()
            } catch (e: Throwable) {
                close()
                throw e
            }
        }
}
