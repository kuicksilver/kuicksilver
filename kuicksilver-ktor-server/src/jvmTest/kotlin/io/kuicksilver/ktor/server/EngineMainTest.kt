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
import kotlin.test.assertContentEquals
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

    /** `kuicksilver.webSocketsOverHttp2` turns WebSockets over HTTP/2 (RFC 8441) off; on by default, as over HTTP/3. */
    @Test fun webSocketsOverHttp2Key() {
        fun enabled(vararg extra: String): Boolean {
            val server = EngineMain.createServer(arrayOf("-host=127.0.0.1", "-port=0", *extra))
            @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
            return server.engine.configuration.webSocketsOverHttp2
        }
        assertEquals(true, enabled())
        assertEquals(false, enabled("-P:kuicksilver.webSocketsOverHttp2=false"))
        assertFailsWith<IllegalArgumentException> { enabled("-P:kuicksilver.webSocketsOverHttp2=no") }
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

    /** A request over TLS on the deployment port for [host], its status line. */
    private suspend fun statusFor(
        port: Int,
        host: String,
    ): String =
        kotlinx.coroutines.withContext(Dispatchers.IO) {
            (jdkContext().socketFactory.createSocket(java.net.InetAddress.getLoopbackAddress(), port) as javax.net.ssl.SSLSocket)
                .use { s ->
                    s.soTimeout = 20_000
                    s.outputStream.write("GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n".toByteArray())
                    s.inputStream.bufferedReader().readLine()
                }
        }

    /**
     * `kuicksilver.tls.trustedGateway = true` takes requests for a host the certificate does not name on the deployment port
     * (RFC 9110 section 7.4, the trusted-gateway exception); without it they get 421. Without the identity files it applies to
     * the cleartext port: absolute-form https targets from a TLS-terminating proxy are served, 421 without the key.
     */
    @Test fun trustedGatewayKeyTakesOtherHosts() =
        serverTest {
            for ((args, want) in listOf(clientCaArgs() to "421", clientCaArgs("-P:kuicksilver.tls.trustedGateway=true") to "200")) {
                val server = EngineMain.createServer(args)
                server.startSuspend(false)
                try {
                    val port =
                        server.engine
                            .resolvedConnectors()
                            .first()
                            .port
                    val line = statusFor(port, "elsewhere.test")
                    assertTrue(line.startsWith("HTTP/1.1 $want"), line)
                } finally {
                    server.stop(100, 500)
                }
            }
            // without the identity files the deployment port is cleartext, behind a TLS-terminating proxy: an absolute-form https
            // target gets 421 unless the key says the proxy is a trusted gateway
            for ((extra, want) in listOf(emptyArray<String>() to "421", arrayOf("-P:kuicksilver.tls.trustedGateway=true") to "200")) {
                val server =
                    EngineMain.createServer(
                        arrayOf(
                            "-host=127.0.0.1",
                            "-port=0",
                            "-P:ktor.application.modules.size=1",
                            "-P:ktor.application.modules.0=$module",
                            "-P:kuicksilver.http3=false",
                        ) + extra,
                    )
                server.startSuspend(false)
                try {
                    val port =
                        server.engine
                            .resolvedConnectors()
                            .first()
                            .port
                    val r =
                        rawHttp(
                            port,
                            "GET https://elsewhere.test/ HTTP/1.1\r\nHost: elsewhere.test\r\nConnection: close\r\n\r\n",
                            tls = null,
                        )
                    assertTrue(r.startsWith("HTTP/1.1 $want"), r)
                } finally {
                    server.stop(100, 500)
                }
            }
            assertFailsWith<IllegalArgumentException> {
                EngineMain
                    .createServer(
                        clientCaArgs("-P:kuicksilver.tls.trustedGateway=yes"),
                    ).engine
            }
        }

    /** `kuicksilver.tls.ocspStapling` reads a DER OCSP response file into the deployment port's stapling; a file that is no DER SEQUENCE is refused. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun ocspStaplingKeyReadsTheResponse() =
        serverTest {
            val der = byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x00) // SEQUENCE { INTEGER 0 }: what the setter checks
            val file = File(dir, "ocsp.der").apply { writeBytes(der) }
            val server = EngineMain.createServer(clientCaArgs("-P:kuicksilver.tls.ocspStapling=${file.path}"))
            assertContentEquals(
                der,
                server.engine.configuration.tlsOcspStapling
                    ?.current,
            )
            server.stop(0, 0)
            val bad = File(dir, "ocsp-bad.der").apply { writeBytes("not der".toByteArray()) }
            assertFailsWith<io.kuicksilver.tls.TlsException.Config> {
                EngineMain.createServer(clientCaArgs("-P:kuicksilver.tls.ocspStapling=${bad.path}")).engine
            }
        }

    /** Ktor's `-sslPort` connector cannot staple or trust a gateway: the two keys are refused next to it, naming the way out. */
    @Test fun negative_ocspStaplingAndTrustedGatewayKeysWithSslPortRefused() =
        serverTest {
            val cert = CertificateFactory.getInstance("X.509").generateCertificate(TestCerts.server.inputStream())
            val pk = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(TestCerts.serverKey))
            val ksFile = File(dir, "gateway-server.p12")
            KeyStore.getInstance("PKCS12").apply {
                load(null, null)
                setKeyEntry("mykey", pk, "pw".toCharArray(), arrayOf(cert))
                ksFile.outputStream().use { store(it, "pw".toCharArray()) }
            }
            val server =
                EngineMain.createServer(
                    clientCaArgs(
                        "-sslPort=0",
                        "-sslKeyStore=${ksFile.path}",
                        "-P:ktor.security.ssl.keyStorePassword=pw",
                        "-P:ktor.security.ssl.privateKeyPassword=pw",
                        "-P:kuicksilver.tls.trustedGateway=true",
                    ),
                )
            val e = assertFailsWith<io.kuicksilver.tls.TlsException.Config> { server.startSuspend(false) }
            assertTrue("tlsConnector(identity)" in e.message.orEmpty(), e.message)
            server.stop(0, 0)
        }

    @Test fun tlsVersionsKeyParsed() {
        assertNull(EngineMain.parseTlsVersions(null))
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls13, EngineMain.parseTlsVersions("tls13"))
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls12And13, EngineMain.parseTlsVersions(" tls12And13 "))
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls12And13, EngineMain.parseTlsVersions("TLS12AND13"))
        for (bad in listOf(
            "tls12",
            "1.2",
            "",
        )) {
            assertFailsWith<IllegalArgumentException>("negative: $bad") { EngineMain.parseTlsVersions(bad) }
        }
    }

    /**
     * `kuicksilver.tls.versions = tls12And13` serves the JDK's TLS 1.2 client on the deployment port (RFC 9325 section 3.1.1);
     * it needs the identity files, and is refused next to Ktor's `-sslPort`, whose key is `ktor.security.ssl.enabledProtocols`.
     */
    @Test fun tlsVersionsKeyServesTls12() =
        serverTest {
            val server = EngineMain.createServer(clientCaArgs("-P:kuicksilver.tls.versions=tls12And13"))
            assertEquals(io.kuicksilver.tls.TlsVersions.Tls12And13, server.engine.configuration.tlsVersions)
            server.startSuspend(false)
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                kotlinx.coroutines.withContext(Dispatchers.IO) {
                    (jdkContext().socketFactory.createSocket(java.net.InetAddress.getLoopbackAddress(), port) as javax.net.ssl.SSLSocket)
                        .use { s ->
                            s.soTimeout = 20_000
                            s.sslParameters = s.sslParameters.apply { protocols = arrayOf("TLSv1.2") }
                            s.startHandshake()
                            assertEquals("TLSv1.2", s.session.protocol)
                        }
                }
            } finally {
                server.stop(100, 500)
            }
            val e =
                assertFailsWith<IllegalArgumentException> {
                    EngineMain
                        .createServer(
                            arrayOf(
                                "-host=127.0.0.1",
                                "-port=0",
                                "-P:ktor.application.modules.size=1",
                                "-P:ktor.application.modules.0=$module",
                                "-P:kuicksilver.tls.versions=tls12And13",
                            ),
                        ).engine
                }
            assertTrue("certificateChain" in e.message.orEmpty(), e.message)
        }

    @Test fun negative_tlsVersionsKeyWithSslPortRefused() =
        serverTest {
            val cert = CertificateFactory.getInstance("X.509").generateCertificate(TestCerts.server.inputStream())
            val pk = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(TestCerts.serverKey))
            val ksFile = File(dir, "versions-server.p12")
            KeyStore.getInstance("PKCS12").apply {
                load(null, null)
                setKeyEntry("mykey", pk, "pw".toCharArray(), arrayOf(cert))
                ksFile.outputStream().use { store(it, "pw".toCharArray()) }
            }
            val server =
                EngineMain.createServer(
                    clientCaArgs(
                        "-sslPort=0",
                        "-sslKeyStore=${ksFile.path}",
                        "-P:ktor.security.ssl.keyStorePassword=pw",
                        "-P:ktor.security.ssl.privateKeyPassword=pw",
                        "-P:kuicksilver.tls.versions=tls12And13",
                    ),
                )
            val e = assertFailsWith<io.kuicksilver.tls.TlsException.Config> { server.startSuspend(false) }
            assertTrue("ktor.security.ssl.enabledProtocols" in e.message.orEmpty(), e.message)
            server.stop(0, 0)
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
        assertTrue("contains a private key; it must hold CA certificates only" in e4.message.orEmpty(), e4.message)
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

    /**
     * Ktor's sslConnector (`-sslPort`) takes client certificates from its own trustStore: EngineMain's client CA keys would not
     * apply to it, so the start is refused instead of serving that port without them.
     */
    @Test fun negative_clientCaKeysWithSslPortRefused() =
        serverTest {
            val cert = CertificateFactory.getInstance("X.509").generateCertificate(TestCerts.server.inputStream())
            val pk = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(TestCerts.serverKey))
            val ksFile = File(dir, "mtls-server.p12")
            KeyStore.getInstance("PKCS12").apply {
                load(null, null)
                setKeyEntry("mykey", pk, "pw".toCharArray(), arrayOf(cert))
                ksFile.outputStream().use { store(it, "pw".toCharArray()) }
            }
            val ca = pem("sslport-ca.pem", TestCerts.toPem("CERTIFICATE", TestCerts.testCa))
            val server =
                EngineMain.createServer(
                    clientCaArgs(
                        "-sslPort=0",
                        "-sslKeyStore=${ksFile.path}",
                        "-P:ktor.security.ssl.keyStorePassword=pw",
                        "-P:ktor.security.ssl.privateKeyPassword=pw",
                        "-P:kuicksilver.tls.clientAuth=required",
                        "-P:kuicksilver.tls.clientCa=${ca.path}",
                    ),
                )
            val e = assertFailsWith<io.kuicksilver.tls.TlsException.Config> { server.startSuspend(false) }
            assertTrue("ktor.security.ssl.trustStore" in e.message.orEmpty(), e.message)
            server.stop(0, 0)
        }

    private fun clientA() = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())

    private fun clientB() = TlsIdentity.fromDer(listOf(TestCerts.clientOtherCa), TestCerts.clientOtherCaKey.copyOf())
}
