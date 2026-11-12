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
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
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
import kotlin.test.assertFails
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

    /**
     * The `application.conf` of docs/guide/ktor.md ("EngineMain and configuration keys"), loaded as it stands with `-config`:
     * only the port, the module and the two file paths are replaced, so a key the guide shows and the engine no longer reads
     * (or reads otherwise) fails here.
     */
    @Test fun guideApplicationConfStarts() =
        serverTest {
            val guide =
                generateSequence(File("").absoluteFile) { it.parentFile }
                    .map { File(it, "docs/guide/ktor.md") }
                    .first { it.exists() }
                    .readText()
            val block = guide.substringAfter("```hocon\n").substringBefore("```")
            val chain = File(dir, "fullchain.pem").apply { writeText(TestCerts.toPem("CERTIFICATE", TestCerts.server)) }
            val key = File(dir, "privkey.pem").apply { writeText(TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey)) }
            val conf =
                block
                    .replace("port = 443", "port = 0\n        host = \"127.0.0.1\"")
                    .replace("com.example.ApplicationKt.module", module)
                    .replace("/etc/letsencrypt/live/example.com/fullchain.pem", chain.invariantSeparatorsPath)
                    .replace("/etc/letsencrypt/live/example.com/privkey.pem", key.invariantSeparatorsPath)
            assertTrue(
                conf.contains(chain.invariantSeparatorsPath) && conf.contains(key.invariantSeparatorsPath) && conf.contains(module),
                conf,
            )
            val file = File(dir, "application.conf").apply { writeText(conf) }
            val server = EngineMain.createServer(arrayOf("-config=${file.path}"))
            server.startSuspend(false)
            try {
                val c = server.engine.configuration
                assertEquals(1.hours, @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class) c.identityReloadInterval)
                assertEquals(4096, @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class) c.quicMaxConnectionsPerIp)
                val resp =
                    rawHttp(
                        server.engine
                            .resolvedConnectors()
                            .first()
                            .port,
                        get,
                    )
                assertTrue(resp.endsWith("engine main") && resp.contains("Alt-Svc: h3="), resp)
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

    /** `kuicksilver.http2RepeatOffenderPenalty` turns the backoff by address on; off by default (threat model 3.23). */
    @Test fun http2RepeatOffenderPenaltyKey() {
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        fun penalty(vararg extra: String): Pair<Duration, Boolean> {
            val server = EngineMain.createServer(arrayOf("-host=127.0.0.1", "-port=0", *extra))
            return server.engine.configuration.http2RepeatOffenderPenalty to (server.engine.h2Offenders != null)
        }
        assertEquals(Duration.ZERO to false, penalty(), "off by default")
        assertEquals(30.seconds to true, penalty("-P:kuicksilver.http2RepeatOffenderPenalty=30s"))
        assertEquals(Duration.ZERO to false, penalty("-P:kuicksilver.http2RepeatOffenderPenalty=0"))
        assertFailsWith<IllegalArgumentException> { penalty("-P:kuicksilver.http2RepeatOffenderPenalty=-1s") }
        assertFailsWith<IllegalArgumentException> { penalty("-P:kuicksilver.http2RepeatOffenderPenalty=soon") }
    }

    /** `kuicksilver.maxTcpConnections` and `kuicksilver.maxTcpConnectionsPerIp` (`0` is off) set the TCP connection limits. */
    @Test fun tcpConnectionLimitKeys() {
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        fun limits(vararg extra: String): Pair<Int, Int?> {
            val c = EngineMain.createServer(arrayOf("-host=127.0.0.1", "-port=0", *extra)).engine.configuration
            return c.maxTcpConnections to c.maxTcpConnectionsPerIp
        }
        assertEquals(10_000 to null, limits(), "the defaults: the per-IP limit is off")
        assertEquals(500 to 16, limits("-P:kuicksilver.maxTcpConnections=500", "-P:kuicksilver.maxTcpConnectionsPerIp=16"))
        assertEquals(10_000 to null, limits("-P:kuicksilver.maxTcpConnectionsPerIp=0"))
        assertFailsWith<IllegalArgumentException> { limits("-P:kuicksilver.maxTcpConnections=0") }
        assertFailsWith<IllegalArgumentException> { limits("-P:kuicksilver.maxTcpConnections=many") }
        assertFailsWith<IllegalArgumentException> { limits("-P:kuicksilver.maxTcpConnectionsPerIp=-1") }
    }

    /**
     * `kuicksilver.quicMaxConnections`, `kuicksilver.quicMaxConnectionsPerIp` (`0` is off) and `kuicksilver.quicAcceptQueue` set
     * the QUIC endpoint limits.
     */
    @Test fun quicLimitKeys() {
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        fun limits(vararg extra: String): Triple<Int, Int?, Int> {
            val c = EngineMain.createServer(arrayOf("-host=127.0.0.1", "-port=0", *extra)).engine.configuration
            return Triple(c.quicMaxConnections, c.quicMaxConnectionsPerIp, c.quicAcceptQueue)
        }
        assertEquals(Triple(10_000, 256, 128), limits(), "the defaults")
        assertEquals(
            Triple(500, 4096, 512),
            limits(
                "-P:kuicksilver.quicMaxConnections=500",
                "-P:kuicksilver.quicMaxConnectionsPerIp=4096",
                "-P:kuicksilver.quicAcceptQueue=512",
            ),
        )
        assertEquals(Triple(10_000, null, 128), limits("-P:kuicksilver.quicMaxConnectionsPerIp=0"))
        assertFailsWith<IllegalArgumentException> { limits("-P:kuicksilver.quicMaxConnections=0") }
        assertFailsWith<IllegalArgumentException> { limits("-P:kuicksilver.quicAcceptQueue=0") }
        assertFailsWith<IllegalArgumentException> { limits("-P:kuicksilver.quicAcceptQueue=many") }
        assertFailsWith<IllegalArgumentException> { limits("-P:kuicksilver.quicMaxConnectionsPerIp=-1") }
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

    private fun pem(
        name: String,
        text: String,
    ) = File(dir, name).apply { writeText(text) }

    private fun clientCaArgs(vararg extra: String): Array<String> {
        val chain = pem("ca-chain.pem", TestCerts.toPem("CERTIFICATE", TestCerts.server))
        val key = pem("ca-key.pem", TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey))
        return arrayOf(
            "-host=127.0.0.1",
            "-port=0",
            "-P:ktor.application.modules.size=1",
            "-P:ktor.application.modules.0=$module",
            "-P:kuicksilver.tls.certificateChain=${chain.path}",
            "-P:kuicksilver.tls.privateKey=${key.path}",
            "-P:kuicksilver.altSvc=false",
        ) + extra
    }

    @Test fun clientAuthKeyParsed() {
        assertEquals(ClientAuth.None, EngineMain.parseClientAuth(null))
        assertEquals(ClientAuth.None, EngineMain.parseClientAuth("none"))
        assertEquals(ClientAuth.Optional, EngineMain.parseClientAuth("optional"))
        assertEquals(ClientAuth.Required, EngineMain.parseClientAuth(" required "))
        assertFailsWith<IllegalArgumentException> { EngineMain.parseClientAuth("yes") }
    }

    /** The client CA keys go together, need the identity files, and the CA file gets the watcher's checks at startup. */
    @Test fun negative_clientCaKeyCombinationsRefused() {
        val ca = pem("client-ca.pem", TestCerts.toPem("CERTIFICATE", TestCerts.testCa))
        val e1 =
            assertFailsWith<IllegalArgumentException> {
                EngineMain
                    .createServer(
                        clientCaArgs("-P:kuicksilver.tls.clientAuth=required"),
                    ).engine
            }
        assertTrue("needs kuicksilver.tls.clientCa" in e1.message.orEmpty(), e1.message)
        val e2 =
            assertFailsWith<IllegalArgumentException> {
                EngineMain
                    .createServer(
                        clientCaArgs("-P:kuicksilver.tls.clientCa=${ca.path}"),
                    ).engine
            }
        assertTrue("optional or required" in e2.message.orEmpty(), e2.message)
        val e3 =
            assertFailsWith<IllegalArgumentException> {
                EngineMain
                    .createServer(
                        arrayOf(
                            "-host=127.0.0.1",
                            "-port=0",
                            "-P:ktor.application.modules.size=1",
                            "-P:ktor.application.modules.0=$module",
                            "-P:kuicksilver.tls.clientAuth=required",
                            "-P:kuicksilver.tls.clientCa=${ca.path}",
                        ),
                    ).engine
            }
        assertTrue("certificateChain" in e3.message.orEmpty(), e3.message)
        val withKey =
            pem(
                "client-ca-key.pem",
                TestCerts.toPem("CERTIFICATE", TestCerts.testCa) + TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey),
            )
        val e4 =
            assertFailsWith<kotlinx.io.IOException> {
                EngineMain
                    .createServer(
                        clientCaArgs("-P:kuicksilver.tls.clientAuth=required", "-P:kuicksilver.tls.clientCa=${withKey.path}"),
                    ).engine
            }
        assertTrue("contains a private key" in e4.message.orEmpty(), e4.message)
        assertFailsWith<IllegalArgumentException> {
            EngineMain
                .createServer(
                    clientCaArgs("-P:kuicksilver.tls.clientAuth=sometimes", "-P:kuicksilver.tls.clientCa=${ca.path}"),
                ).engine
        }
    }

    /** Without reloading the CA file is read once into an AnchoredCa; client certificates are required on the deployment port. */
    @Test fun clientCaRequiredOnTheDeploymentPort() =
        serverTest {
            val ca = pem("fixed-ca.pem", TestCerts.toPem("CERTIFICATE", TestCerts.testCa))
            val server =
                EngineMain.createServer(
                    clientCaArgs("-P:kuicksilver.tls.clientAuth=required", "-P:kuicksilver.tls.clientCa=${ca.path}"),
                )
            assertIs<TrustConfig.AnchoredCa>(server.engine.configuration.clientTrust)
            server.startSuspend(false)
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                assertTrue(rawHttp(port, get, ServerFixtures.clientTls(identity = clientA())).endsWith("engine main"))
                assertFails("negative: no client certificate") { rawHttp(port, get) }
                assertFails("negative: a certificate of another CA") { rawHttp(port, get, ServerFixtures.clientTls(identity = clientB())) }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * With `kuicksilver.tls.reloadInterval` the client CA file is watched as the identity's files are: a bundle renewed after
     * `createServer` read it is used for new handshakes without a restart.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun renewedClientCaFileUsedWithoutRestart() =
        serverTest {
            val ca = pem("renew-ca.pem", TestCerts.toPem("CERTIFICATE", TestCerts.testCa))
            val server =
                EngineMain.createServer(
                    clientCaArgs(
                        "-P:kuicksilver.tls.clientAuth=required",
                        "-P:kuicksilver.tls.clientCa=${ca.path}",
                        "-P:kuicksilver.tls.reloadInterval=1h",
                    ),
                )
            val config = server.engine.configuration
            val trust = assertIs<TrustConfig.ReloadableCa>(config.clientTrust)
            assertEquals(listOf(Certificate(TestCerts.testCa)), trust.current.roots)
            config.identitySettleForTest = Duration.ZERO
            ca.writeText(TestCerts.toPem("CERTIFICATE", TestCerts.otherCa)) // renewed after the server read it
            server.startSuspend(false)
            try {
                val applied =
                    withTimeoutOrNull(20.seconds) {
                        while (trust.current.roots != listOf(Certificate(TestCerts.otherCa))) yield()
                        true
                    }
                assertTrue(applied == true, "the watcher did not apply the renewed CA file within 20 s")
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                assertTrue(rawHttp(port, get, ServerFixtures.clientTls(identity = clientB())).endsWith("engine main"))
                assertFails("negative: the dropped CA's client") { rawHttp(port, get, ServerFixtures.clientTls(identity = clientA())) }
            } finally {
                server.stop(100, 500)
            }
            assertTrue(server.engine.identityWatcherForTest!!.isCompleted, "the watcher ends with the server")
        }

    private fun clientA() = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())

    private fun clientB() = TlsIdentity.fromDer(listOf(TestCerts.clientOtherCa), TestCerts.clientOtherCaKey.copyOf())
}
