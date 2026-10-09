// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.sslConnector
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import java.security.KeyFactory
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import kotlin.test.BeforeTest
import kotlin.test.Test
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
}
