// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.Application
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.ktor.network.tls
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsIdentity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import java.io.File
import java.nio.file.Files
import java.security.KeyFactory
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

/** Module loaded by name from the configuration (`ktor.application.modules`). */
fun Application.engineMainTestModule() {
    routing { get("/") { call.respondText("engine main") } }
}

class EngineMainTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val module = "io.kuicksilver.ktor.server.EngineMainTestKt.engineMainTestModule"
    private val dir: File = Files.createTempDirectory("kuicksilver-engine-main").toFile().also { it.deleteOnExit() }
    private val get = "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n"

    @Test fun startsFromConfigWithPemKeys() =
        serverTest {
            val chain = File(dir, "chain.pem").apply { writeText(TestCerts.toPem("CERTIFICATE", TestCerts.server)) }
            val key = File(dir, "key.pem").apply { writeText(TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey)) }
            val server =
                EngineMain.createServer(
                    arrayOf(
                        "-host=127.0.0.1",
                        "-port=0",
                        "-P:ktor.application.modules.size=1",
                        "-P:ktor.application.modules.0=$module",
                        "-P:kuicksilver.tls.certificateChain=${chain.path}",
                        "-P:kuicksilver.tls.privateKey=${key.path}",
                        "-P:kuicksilver.altSvc=false",
                    ),
                )
            server.startSuspend(false)
            try {
                assertEquals(false, server.engine.configuration.altSvc)
                val resp =
                    rawHttp(
                        server.engine
                            .resolvedConnectors()
                            .first()
                            .port,
                        get,
                    )
                assertTrue(resp.endsWith("engine main") && !resp.contains("Alt-Svc"), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun ktorSslKeysOnJvm() =
        serverTest {
            val cert = CertificateFactory.getInstance("X.509").generateCertificate(TestCerts.server.inputStream())
            val pk = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(TestCerts.serverKey))
            val ksFile = File(dir, "server.p12")
            KeyStore.getInstance("PKCS12").apply {
                load(null, null)
                setKeyEntry("mykey", pk, "pw".toCharArray(), arrayOf(cert))
                ksFile.outputStream().use { store(it, "pw".toCharArray()) }
            }
            val server =
                EngineMain.createServer(
                    arrayOf(
                        "-host=127.0.0.1",
                        "-sslPort=0",
                        "-sslKeyStore=${ksFile.path}",
                        "-P:ktor.application.modules.size=1",
                        "-P:ktor.application.modules.0=$module",
                        "-P:ktor.security.ssl.keyStorePassword=pw",
                        "-P:ktor.security.ssl.privateKeyPassword=pw",
                    ),
                )
            server.startSuspend(false)
            try {
                assertTrue(
                    rawHttp(
                        server.engine
                            .resolvedConnectors()
                            .first()
                            .port,
                        get,
                    ).endsWith("engine main"),
                )
            } finally {
                server.stop(100, 500)
            }
        }

    /** `kuicksilver.http2` turns HTTP/2 on (it is off by default, 0.3.0). */
    @Test fun http2Key() {
        fun http2(vararg extra: String): Boolean {
            val server = EngineMain.createServer(arrayOf("-host=127.0.0.1", "-port=0", *extra))
            @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
            return server.engine.configuration.http2
        }
        assertEquals(false, http2())
        assertEquals(true, http2("-P:kuicksilver.http2=true"))
        assertFailsWith<IllegalArgumentException> { http2("-P:kuicksilver.http2=yes") }
    }

    @Test fun reloadIntervalKeyParsed() {
        assertEquals(30.seconds, EngineMain.parseReloadInterval("30s"))
        assertEquals(1.hours, EngineMain.parseReloadInterval("1h"))
        assertEquals(1.hours, EngineMain.parseReloadInterval("PT1H"))
        assertNull(EngineMain.parseReloadInterval("0"), "0 turns polling off")
        assertNull(EngineMain.parseReloadInterval(null))
        assertFailsWith<IllegalArgumentException> { EngineMain.parseReloadInterval("soon") }
        assertFailsWith<IllegalArgumentException>("busy polling is refused") { EngineMain.parseReloadInterval("500ms") }
        assertFailsWith<IllegalArgumentException> { EngineMain.parseReloadInterval("-1h") }
    }

    @Test fun negative_reloadIntervalWithoutPemFilesRefused() {
        val e =
            assertFailsWith<IllegalArgumentException> {
                EngineMain
                    .createServer(
                        arrayOf(
                            "-host=127.0.0.1",
                            "-port=0",
                            "-P:ktor.application.modules.size=1",
                            "-P:ktor.application.modules.0=$module",
                            "-P:kuicksilver.tls.reloadInterval=30s",
                        ),
                    ).engine
            }
        assertTrue("reloadInterval" in e.message.orEmpty(), e.message)
    }

    /** With reloading, a chain file that also holds the key (a combined PEM) is refused at startup as the watcher would refuse it. */
    @Test fun negative_combinedPemRefusedAtStartupWithReloadInterval() {
        val pem = TestCerts.toPem("CERTIFICATE", TestCerts.server) + TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey)
        val chain = File(dir, "combined.pem").apply { writeText(pem) }
        val key = File(dir, "combined-key.pem").apply { writeText(TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey)) }

        fun args(reload: Boolean) =
            arrayOf(
                "-host=127.0.0.1",
                "-port=0",
                "-P:ktor.application.modules.size=1",
                "-P:ktor.application.modules.0=$module",
                "-P:kuicksilver.tls.certificateChain=${chain.path}",
                "-P:kuicksilver.tls.privateKey=${key.path}",
            ) + (if (reload) arrayOf("-P:kuicksilver.tls.reloadInterval=1h") else emptyArray())
        val e = assertFailsWith<kotlinx.io.IOException> { EngineMain.createServer(args(reload = true)).engine }
        assertTrue("contains a private key" in e.message.orEmpty(), e.message)
        val plain = EngineMain.createServer(args(reload = false))
        val id = plain.engine.configuration.identity
        assertTrue(id is TlsIdentity.InMemory, "control: without reloading the file is served as before")
        id.close() // the server never started: nothing else closes it
    }

    /**
     * With `kuicksilver.tls.reloadInterval` the identity is reloadable and the files are watched from the start: files renewed
     * after `createServer` read them are served without a restart, and the watcher ends with the server.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun renewedPemFilesServedWithoutRestart() =
        serverTest {
            val chain = File(dir, "renew-chain.pem").apply { writeText(TestCerts.toPem("CERTIFICATE", TestCerts.server)) }
            val key = File(dir, "renew-key.pem").apply { writeText(TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey)) }
            val server =
                EngineMain.createServer(
                    arrayOf(
                        "-host=127.0.0.1",
                        "-port=0",
                        "-P:ktor.application.modules.size=1",
                        "-P:ktor.application.modules.0=$module",
                        "-P:kuicksilver.tls.certificateChain=${chain.path}",
                        "-P:kuicksilver.tls.privateKey=${key.path}",
                        "-P:kuicksilver.tls.reloadInterval=1h",
                    ),
                )
            val config = server.engine.configuration
            assertEquals(1.hours, config.identityReloadInterval)
            val identity = assertIs<TlsIdentity.Reloadable>(config.identity)
            assertEquals(Certificate(TestCerts.server), identity.current.chain[0])
            config.identitySettleForTest = Duration.ZERO
            // renewed after the server read them: the watcher's check at startup finds them
            chain.writeText(
                TestCerts.toPem("CERTIFICATE", TestCerts.serverViaIntermediate) + TestCerts.toPem("CERTIFICATE", TestCerts.intermediate),
            )
            key.writeText(TestCerts.toPem("PRIVATE KEY", TestCerts.serverViaIntermediateKey))
            server.startSuspend(false)
            try {
                val applied =
                    withTimeoutOrNull(20.seconds) {
                        while (identity.current.chain[0] != Certificate(TestCerts.serverViaIntermediate)) yield()
                        true
                    }
                assertTrue(applied == true, "the watcher did not apply the renewed files within 20 s")
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                val selector = SelectorManager(Dispatchers.IO)
                try {
                    val socket =
                        io.kuicksilver.ktor.network
                            .connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                            .tls(ServerFixtures.clientTls())
                    try {
                        assertEquals(
                            Certificate(TestCerts.serverViaIntermediate),
                            socket.peerCertificates[0],
                            "the renewed leaf on the wire",
                        )
                    } finally {
                        socket.close()
                    }
                } finally {
                    selector.close()
                }
                assertTrue(rawHttp(port, get).endsWith("engine main"))
            } finally {
                server.stop(100, 500)
            }
            assertTrue(server.engine.identityWatcherForTest!!.isCompleted, "the watcher ends with the server")
            val probe =
                TlsIdentity.fromPem(
                    TestCerts.toPem("CERTIFICATE", TestCerts.server),
                    TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey).toCharArray(),
                )
            assertFailsWith<IllegalStateException>("the identity EngineMain made is closed with the server") { identity.reload(probe) }
            probe.close()
        }
}
