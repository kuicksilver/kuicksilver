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
import io.kuicksilver.quic.QuicConfig
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
import kotlin.test.assertNotNull
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
                        "-P:kuicksilver.http3.altSvc=false",
                    ),
                )
            server.startSuspend(false)
            try {
                assertEquals(false, server.engine.configuration.http3.altSvc)
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
            val block =
                guide.substringAfter("### EngineMain and configuration keys").substringAfter("```hocon\n").substringBefore("```")
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
                assertEquals(1.hours, @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class) c.tls.reloadInterval)
                assertEquals(
                    4096,
                    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class) c.http3.endpoint.maxConnectionsPerIp,
                )
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

    /**
     * The first screen's `application.conf` of docs/guide/ktor.md ("Minimal example"), loaded as it stands: only the port
     * (with a loopback host), the module and the two file paths are replaced.
     */
    @Test fun guideFirstScreenConfStarts() =
        serverTest {
            val guide =
                generateSequence(File("").absoluteFile) { it.parentFile }
                    .map { File(it, "docs/guide/ktor.md") }
                    .first { it.exists() }
                    .readText()
            val block = guide.substringAfter("**Minimal example.**").substringAfter("```hocon\n").substringBefore("```")
            val chain = File(dir, "fullchain.pem").apply { writeText(TestCerts.toPem("CERTIFICATE", TestCerts.server)) }
            val key = File(dir, "privkey.pem").apply { writeText(TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey)) }
            val conf =
                block
                    .replace("ktor.deployment.port = 443", "ktor.deployment.port = 0\nktor.deployment.host = \"127.0.0.1\"")
                    .replace("com.example.ApplicationKt.module", module)
                    .replace("/etc/letsencrypt/live/example.com/fullchain.pem", chain.invariantSeparatorsPath)
                    .replace("/etc/letsencrypt/live/example.com/privkey.pem", key.invariantSeparatorsPath)
            assertTrue(
                conf.contains("ktor.deployment.port = 0") && conf.contains(chain.invariantSeparatorsPath) && conf.contains(module),
                conf,
            )
            val file = File(dir, "application.conf").apply { writeText(conf) }
            val server = EngineMain.createServer(arrayOf("-config=${file.path}"))
            server.startSuspend(false)
            try {
                assertEquals(1.hours, server.engine.configuration.tls.reloadInterval)
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
            return server.engine.configuration.http2.enabled
        }
        assertEquals(true, http2(), "on by default since 0.3.0")
        assertEquals(false, http2("-P:kuicksilver.http2.enabled=false"))
        assertFailsWith<IllegalArgumentException> { http2("-P:kuicksilver.http2.enabled=yes") }
    }

    /**
     * `kuicksilver.h2c` serves HTTP/2 over cleartext TCP with prior knowledge on the plain deployment port (RFC 9113 section
     * 3.3); off by default, and refused next to the TLS identity files (h2c needs the cleartext port).
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun h2cKey() =
        serverTest {
            fun mode(vararg extra: String): H2cMode {
                val server = EngineMain.createServer(arrayOf("-host=127.0.0.1", "-port=0", *extra))
                return server.engine.configuration.deploymentH2c
            }
            assertEquals(H2cMode.Off, mode())
            assertEquals(H2cMode.WithHttp11, mode("-P:kuicksilver.connector.h2c=withHttp11"))
            assertEquals(H2cMode.Only, mode("-P:kuicksilver.connector.h2c=only"))
            assertEquals(H2cMode.Off, mode("-P:kuicksilver.connector.h2c=off"))
            assertFailsWith<IllegalArgumentException> { mode("-P:kuicksilver.connector.h2c=yes") }
            assertFailsWith<IllegalArgumentException> { EngineMain.createServer(clientCaArgs("-P:kuicksilver.connector.h2c=only")).engine }
            // the deployment port serves h2c and HTTP/1.1
            val server =
                EngineMain.createServer(
                    arrayOf(
                        "-host=127.0.0.1",
                        "-port=0",
                        "-P:ktor.application.modules.size=1",
                        "-P:ktor.application.modules.0=$module",
                        "-P:kuicksilver.http3.enabled=false",
                        "-P:kuicksilver.connector.h2c=withHttp11",
                    ),
                )
            server.startSuspend(false)
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                RawH2Client.connectPlain(port).use { raw ->
                    raw.preface()
                    raw.headers(1, listOf(":method" to "GET", ":scheme" to "http", ":authority" to "server.test", ":path" to "/"))
                    val f = assertNotNull(raw.await { it.stream == 1 && it.type == RawFrame.HEADERS }, "a response on stream 1")
                    assertEquals(RawFrame.HEADERS, f.type)
                }
                val r = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n", tls = null)
                assertTrue(r.startsWith("HTTP/1.1 200"), r)
            } finally {
                server.stop(100, 500)
            }
        }

    /** `kuicksilver.webSocketsOverHttp2` turns WebSockets over HTTP/2 (RFC 8441) off; on by default, as over HTTP/3. */
    @Test fun webSocketsOverHttp2Key() {
        fun enabled(vararg extra: String): Boolean {
            val server = EngineMain.createServer(arrayOf("-host=127.0.0.1", "-port=0", *extra))
            @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
            return server.engine.configuration.webSockets.overHttp2
        }
        assertEquals(true, enabled())
        assertEquals(false, enabled("-P:kuicksilver.webSockets.overHttp2=false"))
        assertFailsWith<IllegalArgumentException> { enabled("-P:kuicksilver.webSockets.overHttp2=no") }
    }

    /** `kuicksilver.h1AllowBareLf` lets a bare LF end an HTTP/1.1 head line (RFC 9112 section 2.2 MAY); off by default. */
    @Test fun h1AllowBareLfKey() {
        fun allowed(vararg extra: String): Boolean {
            val server = EngineMain.createServer(arrayOf("-host=127.0.0.1", "-port=0", *extra))
            @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
            return server.engine.configuration.http1.allowBareLf
        }
        assertEquals(false, allowed())
        assertEquals(true, allowed("-P:kuicksilver.http1.allowBareLf=true"))
        assertFailsWith<IllegalArgumentException> { allowed("-P:kuicksilver.http1.allowBareLf=yes") }
    }

    /** `kuicksilver.http2RepeatOffenderPenalty` turns the backoff by address on; off by default (threat model 3.23). */
    @Test fun http2RepeatOffenderPenaltyKey() {
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        fun penalty(vararg extra: String): Pair<Duration, Boolean> {
            val server = EngineMain.createServer(arrayOf("-host=127.0.0.1", "-port=0", *extra))
            return (server.engine.configuration.http2.repeatOffenderPenalty ?: Duration.ZERO) to (server.engine.h2Offenders != null)
        }
        assertEquals(Duration.ZERO to false, penalty(), "off by default")
        assertEquals(30.seconds to true, penalty("-P:kuicksilver.http2.repeatOffenderPenalty=30s"))
        assertEquals(Duration.ZERO to false, penalty("-P:kuicksilver.http2.repeatOffenderPenalty=off"))
        assertFailsWith<IllegalArgumentException> { penalty("-P:kuicksilver.http2.repeatOffenderPenalty=-1s") }
        assertFailsWith<IllegalArgumentException> { penalty("-P:kuicksilver.http2.repeatOffenderPenalty=soon") }
    }

    /** `kuicksilver.maxTcpConnections` and `kuicksilver.maxTcpConnectionsPerIp` (`0` is off) set the TCP connection limits. */
    @Test fun tcpConnectionLimitKeys() {
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        fun limits(vararg extra: String): Pair<Int, Int?> {
            val c = EngineMain.createServer(arrayOf("-host=127.0.0.1", "-port=0", *extra)).engine.configuration
            return c.tcp.maxConnections to c.tcp.maxConnectionsPerIp
        }
        assertEquals(10_000 to null, limits(), "the defaults: the per-IP limit is off")
        assertEquals(500 to 16, limits("-P:kuicksilver.tcp.maxConnections=500", "-P:kuicksilver.tcp.maxConnectionsPerIp=16"))
        assertEquals(10_000 to null, limits("-P:kuicksilver.tcp.maxConnectionsPerIp=off"))
        assertFailsWith<IllegalArgumentException> { limits("-P:kuicksilver.tcp.maxConnections=0") }
        assertFailsWith<IllegalArgumentException> { limits("-P:kuicksilver.tcp.maxConnections=many") }
        assertFailsWith<IllegalArgumentException> { limits("-P:kuicksilver.tcp.maxConnectionsPerIp=-1") }
    }

    /**
     * `kuicksilver.quicMaxConnections`, `kuicksilver.quicMaxConnectionsPerIp` (`0` is off) and `kuicksilver.quicAcceptQueue` set
     * the QUIC endpoint limits.
     */
    @Test fun quicLimitKeys() {
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        fun limits(vararg extra: String): Triple<Int, Int?, Int> {
            val c = EngineMain.createServer(arrayOf("-host=127.0.0.1", "-port=0", *extra)).engine.configuration
            return Triple(c.http3.endpoint.maxConnections, c.http3.endpoint.maxConnectionsPerIp, c.http3.endpoint.acceptQueue)
        }
        assertEquals(Triple(10_000, 256, 128), limits(), "the defaults")
        assertEquals(
            Triple(500, 4096, 512),
            limits(
                "-P:kuicksilver.http3.endpoint.maxConnections=500",
                "-P:kuicksilver.http3.endpoint.maxConnectionsPerIp=4096",
                "-P:kuicksilver.http3.endpoint.acceptQueue=512",
            ),
        )
        assertEquals(Triple(10_000, null, 128), limits("-P:kuicksilver.http3.endpoint.maxConnectionsPerIp=off"))
        assertFailsWith<IllegalArgumentException> { limits("-P:kuicksilver.http3.endpoint.maxConnections=0") }
        assertFailsWith<IllegalArgumentException> { limits("-P:kuicksilver.http3.endpoint.acceptQueue=0") }
        assertFailsWith<IllegalArgumentException> { limits("-P:kuicksilver.http3.endpoint.acceptQueue=many") }
        assertFailsWith<IllegalArgumentException> { limits("-P:kuicksilver.http3.endpoint.maxConnectionsPerIp=-1") }
    }

    /** `kuicksilver.quic.*`: the QUIC transport of the HTTP/3 listeners, each key the `QuicConfig` option of its name. */
    @Test
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    fun quicTransportKeys() {
        fun quic(vararg extra: String): KuicksilverApplicationEngine.Configuration =
            EngineMain.createServer(arrayOf("-host=127.0.0.1", "-port=0", *extra)).engine.configuration
        val none = quic()
        assertEquals(QuicConfig.Default.maxIdleTimeout, none.resolveQuic().maxIdleTimeout, "no key: the default")
        val cfg =
            quic(
                "-P:kuicksilver.http3.quic.pathMtu.initial=1350",
                "-P:kuicksilver.http3.quic.pathMtu.maxSend=1380",
                "-P:kuicksilver.http3.quic.pathMtu.maxReceive=1400",
                "-P:kuicksilver.http3.quic.pathMtu.discovery=false",
                "-P:kuicksilver.http3.quic.maxIdleTimeout=1m",
                "-P:kuicksilver.http3.quic.handshakeTimeout=5s",
                "-P:kuicksilver.http3.quic.keepAlive=15s",
                "-P:kuicksilver.http3.quic.maxBidiStreams=500",
                "-P:kuicksilver.http3.quic.migration.allow=false",
            )
        val c = cfg.resolveQuic()
        assertEquals(1350, c.initialUdpPayloadSize)
        assertEquals(1380, c.maxSendUdpPayloadSize)
        assertEquals(1400, c.maxUdpPayloadSize)
        assertEquals(false, c.pmtud)
        assertEquals(60.seconds, c.maxIdleTimeout)
        assertEquals(5.seconds, c.handshakeTimeout)
        assertEquals(15.seconds, c.keepAlive)
        assertEquals(500L, c.maxBidiStreams)
        assertEquals(false, c.allowMigration)
        assertEquals(1350, cfg.resolveQuic().initialUdpPayloadSize, "what the HTTP/3 listeners get")
        // the other options keep their defaults
        assertEquals(QuicConfig.Default.initialStreamWindow, c.initialStreamWindow)
        assertEquals(QuicConfig.Default.versions, c.versions)
        val off = quic("-P:kuicksilver.http3.quic.maxIdleTimeout=off", "-P:kuicksilver.http3.quic.keepAlive=off").resolveQuic()
        assertEquals(Duration.ZERO, off.maxIdleTimeout, "0: no idle timeout of our own")
        assertNull(off.keepAlive, "0: no keep-alive")
        assertEquals(1452, quic("-P:kuicksilver.http3.quic.pathMtu.initial=1452").resolveQuic().initialUdpPayloadSize)
    }

    @Test
    fun negative_quicTransportKeysRefuseBadValuesByName() {
        fun refused(vararg extra: String): String =
            assertFailsWith<IllegalArgumentException>(extra.joinToString()) {
                EngineMain.createServer(arrayOf("-host=127.0.0.1", "-port=0", *extra))
            }.message!!
        // RFC 9000 section 14: below 1200 is no QUIC datagram size
        assertEquals(
            "kuicksilver.http3.quic: pathMtu { initial } must be 1200..65527",
            refused("-P:kuicksilver.http3.quic.pathMtu.initial=1199"),
        )
        assertEquals(
            "kuicksilver.http3.quic: pathMtu { maxSend } must be 1200..65527",
            refused("-P:kuicksilver.http3.quic.pathMtu.maxSend=1000"),
        )
        assertEquals(
            "kuicksilver.http3.quic.pathMtu.maxReceive: must be at most 1500 (the endpoint's datagram slots), not 70000",
            refused("-P:kuicksilver.http3.quic.pathMtu.maxReceive=70000"),
        )
        // what QuicConfig takes but the HTTP/3 listener's endpoint would refuse only at bind, once the server starts
        assertEquals(
            "kuicksilver.http3.quic.pathMtu.maxReceive: must be at most 1500 (the endpoint's datagram slots), not 1501",
            refused("-P:kuicksilver.http3.quic.pathMtu.maxReceive=1501"),
        )
        assertEquals(
            "kuicksilver.http3.quic: pathMtu { maxReceive } must be 1200..65527",
            refused("-P:kuicksilver.http3.quic.pathMtu.maxReceive=1199"),
        )
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        assertEquals(
            1500,
            EngineMain
                .createServer(arrayOf("-host=127.0.0.1", "-port=0", "-P:kuicksilver.http3.quic.pathMtu.maxReceive=1500"))
                .engine.configuration
                .resolveQuic()
                .maxUdpPayloadSize,
        )
        assertEquals(
            "kuicksilver.http3.quic.pathMtu.initial: \"1350b\" is not a whole number",
            refused("-P:kuicksilver.http3.quic.pathMtu.initial=1350b"),
        )
        assertEquals(
            "kuicksilver.http3.quic.pathMtu.discovery: \"maybe\" is not true or false",
            refused("-P:kuicksilver.http3.quic.pathMtu.discovery=maybe"),
        )
        assertEquals(
            "kuicksilver.http3.quic.migration.allow: \"yes\" is not true or false",
            refused("-P:kuicksilver.http3.quic.migration.allow=yes"),
        )
        assertEquals(
            "kuicksilver.http3.quic.maxIdleTimeout: \"soon\" is not a duration in whole milliseconds (30s, 1h, 250ms), or off",
            refused("-P:kuicksilver.http3.quic.maxIdleTimeout=soon"),
        )
        assertTrue(
            refused(
                "-P:kuicksilver.http3.quic.handshakeTimeout=0s",
            ).startsWith("kuicksilver.http3.quic: handshakeTimeout must be positive"),
        )
        assertTrue(refused("-P:kuicksilver.http3.quic.maxIdleTimeout=-1s").startsWith("kuicksilver.http3.quic: maxIdleTimeout"))
        assertEquals(
            "kuicksilver.http3.quic: keepAlive must be at most 3/4 of maxIdleTimeout",
            refused("-P:kuicksilver.http3.quic.maxIdleTimeout=10s", "-P:kuicksilver.http3.quic.keepAlive=9s"),
        )
        assertEquals(
            "kuicksilver.http3.quic: maxBidiStreams and expert { maxUniStreams } must be 0..2^60",
            refused("-P:kuicksilver.http3.quic.maxBidiStreams=-1"),
        )
        assertEquals(
            "kuicksilver.quic.maxUniStreams was replaced in 0.3.0 by kuicksilver.http3.quic.expert.maxUniStreams",
            refused("-P:kuicksilver.quic.maxUniStreams=many"),
        )
        // a misspelt key does not leave the default in place silently
        val typo = refused("-P:kuicksilver.quic.initialPacketSize=1350")
        assertTrue(
            typo.startsWith("kuicksilver.quic.initialPacketSize is not a Kuicksilver key"),
            typo,
        )
    }

    /**
     * The `kuicksilver.http3.quic` block of docs/guide/quic.md ("Tunnels and NAT paths (WireGuard)"), loaded as it stands with `-config`, so
     * a key the guide shows and the engine does not read (or reads otherwise) fails here.
     */
    @Test
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    fun guideQuicTransportBlockLoads() {
        val guide =
            generateSequence(File("").absoluteFile) { it.parentFile }
                .map { File(it, "docs/guide/quic.md") }
                .first { it.exists() }
                .readText()
        val block = guide.substringAfter("### Tunnels and NAT paths (WireGuard)").substringAfter("```hocon\n").substringBefore("```")
        assertTrue(block.contains("kuicksilver.http3 {") && block.contains("quic {"), block)
        val file = File(dir, "quic.conf").apply { writeText("ktor.deployment.port = 0\nktor.deployment.host = \"127.0.0.1\"\n$block") }
        val c =
            EngineMain
                .createServer(arrayOf("-config=${file.path}"))
                .engine.configuration
                .resolveQuic()
        assertEquals(1350, c.initialUdpPayloadSize)
        assertEquals(1372, c.maxSendUdpPayloadSize)
        assertEquals(true, c.pmtud)
        assertEquals(60.seconds, c.maxIdleTimeout)
        assertEquals(15.seconds, c.keepAlive)
    }

    @Test fun reloadIntervalKeyParsed() {
        fun interval(value: String) =
            EngineMain
                .createServer(clientCaArgs("-P:kuicksilver.tls.reloadInterval=$value"))
                .engine.configuration.tls.reloadInterval
        assertEquals(30.seconds, interval("30s"))
        assertEquals(1.hours, interval("1h"))
        assertEquals(1.hours, interval("PT1H"))
        assertNull(interval("off"), "off turns polling off")
        assertEquals(
            "kuicksilver.tls.reloadInterval: use off instead of 0",
            assertFailsWith<IllegalArgumentException> { interval("0") }.message,
        )
        assertFailsWith<IllegalArgumentException> { interval("soon") }
        assertFailsWith<IllegalArgumentException>("busy polling is refused") { interval("500ms") }
        assertFailsWith<IllegalArgumentException> { interval("-1h") }
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
        val refused = EngineMain.createServer(args(reload = true))
        val e = assertFailsWith<kotlinx.io.IOException> { refused.start(false) }
        runCatching { refused.stop(0, 0) }
        assertTrue("contains a private key" in e.message.orEmpty(), e.message)
        val plain = EngineMain.createServer(args(reload = false))
        val id = plain.engine.configuration.tls.identity
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
            assertEquals(1.hours, config.tls.reloadInterval)
            assertEquals(Certificate(TestCerts.server), config.tls.identity!!.chain[0])
            config.tls.settleForTest = Duration.ZERO
            // renewed after the server read them: the watcher's check at startup finds them
            chain.writeText(
                TestCerts.toPem("CERTIFICATE", TestCerts.serverViaIntermediate) + TestCerts.toPem("CERTIFICATE", TestCerts.intermediate),
            )
            key.writeText(TestCerts.toPem("PRIVATE KEY", TestCerts.serverViaIntermediateKey))
            server.startSuspend(false)
            val identity = assertIs<TlsIdentity.Reloadable>(server.engine.engineTls.identity)
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
            "-P:kuicksilver.http3.altSvc=false",
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
            for ((args, want) in listOf(
                clientCaArgs() to "421",
                clientCaArgs("-P:kuicksilver.connector.allowMisdirectedHosts=true") to "200",
            )) {
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
            for ((extra, want) in listOf(
                emptyArray<String>() to "421",
                arrayOf("-P:kuicksilver.connector.allowMisdirectedHosts=true") to "200",
            )) {
                val server =
                    EngineMain.createServer(
                        arrayOf(
                            "-host=127.0.0.1",
                            "-port=0",
                            "-P:ktor.application.modules.size=1",
                            "-P:ktor.application.modules.0=$module",
                            "-P:kuicksilver.http3.enabled=false",
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
                        clientCaArgs("-P:kuicksilver.connector.allowMisdirectedHosts=yes"),
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
                server.engine.configuration.tls.ocspStapling
                    ?.current,
            )
            server.stop(0, 0)
            val bad = File(dir, "ocsp-bad.der").apply { writeBytes("not der".toByteArray()) }
            assertFailsWith<io.kuicksilver.tls.TlsException.Config> {
                EngineMain.createServer(clientCaArgs("-P:kuicksilver.tls.ocspStapling=${bad.path}")).engine
            }
        }

    /**
     * `kuicksilver.tls.echKeys` reads the ECH key files (each the PEM `openssl ech` writes) into the deployment port's keys,
     * which its TLS connector carries; a file that is no ECH key, and the key without the identity files, are refused.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun echKeysKeyReadsTheKeyFiles() =
        serverTest {
            val a = File(dir, "ech-a.pem").apply { writeText(EchTestKeys.A) }
            val b = File(dir, "ech-b.pem").apply { writeText(EchTestKeys.B) }
            val server = EngineMain.createServer(clientCaArgs("-P:kuicksilver.tls.echKeys=${a.path},${b.path}"))
            val keys = server.engine.configuration.tls.echKeys
            kotlin.test.assertNotNull(keys)
            server.stop(0, 0)
            // the engine made the keys, so it frees them when it stops: a closed set takes no rotation
            assertFailsWith<io.kuicksilver.tls.TlsException.Config> { keys.rotate(listOf(io.kuicksilver.tls.EchKey(EchTestKeys.B))) }
            val bad = File(dir, "ech-bad.pem").apply { writeText("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n") }
            assertFailsWith<io.kuicksilver.tls.TlsException.Config> {
                EngineMain.createServer(clientCaArgs("-P:kuicksilver.tls.echKeys=${bad.path}")).engine
            }
            assertFailsWith<IllegalArgumentException> {
                EngineMain
                    .createServer(
                        arrayOf(
                            "-host=127.0.0.1",
                            "-port=0",
                            "-P:ktor.application.modules.size=1",
                            "-P:ktor.application.modules.0=$module",
                            "-P:kuicksilver.tls.echKeys=${a.path}",
                        ),
                    ).engine
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
                        "-P:kuicksilver.connector.allowMisdirectedHosts=true",
                    ),
                )
            val e = assertFailsWith<io.kuicksilver.tls.TlsException.Config> { server.startSuspend(false) }
            assertTrue("tlsConnector { }" in e.message.orEmpty(), e.message)
            server.stop(0, 0)
        }

    /**
     * Without the identity files, `kuicksilver.tls.trustedGateway` is for the cleartext deployment port and is accepted next to
     * Ktor's `-sslPort` connector: the cleartext port serves an absolute-form https target, the sslConnector still answers
     * 421 for a host its certificate does not name.
     */
    @Test fun trustedGatewayKeyForThePlainPortNextToSslPort() =
        serverTest {
            val cert = CertificateFactory.getInstance("X.509").generateCertificate(TestCerts.server.inputStream())
            val pk = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(TestCerts.serverKey))
            val ksFile = File(dir, "gateway-plain-server.p12")
            KeyStore.getInstance("PKCS12").apply {
                load(null, null)
                setKeyEntry("mykey", pk, "pw".toCharArray(), arrayOf(cert))
                ksFile.outputStream().use { store(it, "pw".toCharArray()) }
            }
            val server =
                EngineMain.createServer(
                    arrayOf(
                        "-host=127.0.0.1",
                        "-port=0",
                        "-sslPort=0",
                        "-sslKeyStore=${ksFile.path}",
                        "-P:ktor.security.ssl.keyStorePassword=pw",
                        "-P:ktor.security.ssl.privateKeyPassword=pw",
                        "-P:ktor.application.modules.size=1",
                        "-P:ktor.application.modules.0=$module",
                        "-P:kuicksilver.http3.enabled=false",
                        "-P:kuicksilver.connector.allowMisdirectedHosts=true",
                    ),
                )
            server.startSuspend(false)
            try {
                val connectors = server.engine.resolvedConnectors()
                val plain = connectors.first { it.type == io.ktor.server.engine.ConnectorType.HTTP }.port
                val ssl = connectors.first { it.type == io.ktor.server.engine.ConnectorType.HTTPS }.port
                val request = "GET https://elsewhere.test/ HTTP/1.1\r\nHost: elsewhere.test\r\nConnection: close\r\n\r\n"
                val r = rawHttp(plain, request, tls = null)
                assertTrue(r.startsWith("HTTP/1.1 200"), r)
                val other = rawHttp(ssl, "GET / HTTP/1.1\r\nHost: elsewhere.test\r\nConnection: close\r\n\r\n")
                assertTrue(other.startsWith("HTTP/1.1 421"), other)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * `kuicksilver.proxyProtocol.*` turns the PROXY protocol on for the deployment port: a request after a header from a
     * trusted source is served, one without a header is not; an invalid source, a key without trustedSources and Ktor's
     * `-sslPort` connector next to it are refused.
     */
    @Test fun proxyProtocolKeysOnTheDeploymentPort() =
        serverTest {
            fun args(vararg extra: String) =
                arrayOf(
                    "-host=127.0.0.1",
                    "-port=0",
                    "-P:ktor.application.modules.size=1",
                    "-P:ktor.application.modules.0=$module",
                    *extra,
                )
            val server =
                EngineMain.createServer(
                    args(
                        "-P:kuicksilver.connector.proxyProtocol.trustedSources.size=2",
                        "-P:kuicksilver.connector.proxyProtocol.trustedSources.0=127.0.0.1",
                        "-P:kuicksilver.connector.proxyProtocol.trustedSources.1=::1",
                        "-P:kuicksilver.connector.proxyProtocol.headerTimeout=4s",
                        "-P:kuicksilver.connector.proxyProtocol.maxHeaderSize=512",
                    ),
                )

            @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
            val pp = server.engine.configuration.deploymentProxyProtocol!!
            assertEquals(listOf("127.0.0.1", "::1"), pp.trustedSources)
            assertEquals(4.seconds, pp.headerTimeout)
            assertEquals(512, pp.maxHeaderSize)
            server.startSuspend(false)
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                val served = rawHttp(port, "PROXY TCP4 192.0.2.1 198.51.100.2 1 80\r\n$get", tls = null)
                assertTrue(served.startsWith("HTTP/1.1 200") && served.endsWith("engine main"), served)
                val refused = runCatching { rawHttp(port, get, tls = null) }.getOrDefault("")
                assertEquals("", refused, "a request without a PROXY header was answered")
            } finally {
                server.stop(100, 500)
            }
            // one comma-separated string works too
            val listed = EngineMain.createServer(args("-P:kuicksilver.connector.proxyProtocol.trustedSources=10.0.0.0/8, 192.0.2.7"))
            @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
            assertEquals(
                listOf("10.0.0.0/8", "192.0.2.7"),
                listed.engine.configuration.deploymentProxyProtocol!!
                    .trustedSources,
            )
            listed.stop(0, 0)
            for (bad in listOf(
                arrayOf("-P:kuicksilver.connector.proxyProtocol.trustedSources=10.0.0.1/8"),
                arrayOf("-P:kuicksilver.connector.proxyProtocol.headerTimeout=2s"),
                arrayOf(
                    "-P:kuicksilver.connector.proxyProtocol.trustedSources=10.0.0.0/8",
                    "-P:kuicksilver.connector.proxyProtocol.maxHeaderSize=many",
                ),
                arrayOf(
                    "-P:kuicksilver.connector.proxyProtocol.trustedSources=10.0.0.0/8",
                    "-P:kuicksilver.connector.proxyProtocol.headerTimeout=soon",
                ),
                // below the spec's "at least 3 seconds to cover a TCP retransmit"
                arrayOf(
                    "-P:kuicksilver.connector.proxyProtocol.trustedSources=10.0.0.0/8",
                    "-P:kuicksilver.connector.proxyProtocol.headerTimeout=2s",
                ),
            )) {
                assertFailsWith<IllegalArgumentException>(bad.joinToString()) { EngineMain.createServer(args(*bad)).engine }
            }
        }

    /** The deployment port's PROXY protocol with a request-head deadline below 3 s does not start, naming both settings. */
    @Test fun negative_proxyProtocolKeysWithAShortRequestHeadDeadlineRefused() =
        serverTest {
            val server =
                EngineMain.createServer(
                    arrayOf(
                        "-host=127.0.0.1",
                        "-port=0",
                        "-P:ktor.application.modules.size=1",
                        "-P:ktor.application.modules.0=$module",
                        "-P:kuicksilver.connector.proxyProtocol.trustedSources=127.0.0.1",
                    ),
                )
            @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
            server.engine.configuration.requestHeaderTimeout = 1.seconds
            val e = assertFailsWith<IllegalArgumentException> { server.startSuspend(false) }
            assertTrue(
                "kuicksilver.connector.proxyProtocol" in e.message.orEmpty() && "requestHeaderTimeout" in e.message.orEmpty(),
                e.message,
            )
            server.stop(0, 0)
        }

    /** Ktor's `-sslPort` connector cannot take the PROXY protocol: the keys are refused next to it, naming the way out. */
    @Test fun negative_proxyProtocolKeysWithSslPortRefused() =
        serverTest {
            val cert = CertificateFactory.getInstance("X.509").generateCertificate(TestCerts.server.inputStream())
            val pk = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(TestCerts.serverKey))
            val ksFile = File(dir, "proxy-server.p12")
            KeyStore.getInstance("PKCS12").apply {
                load(null, null)
                setKeyEntry("mykey", pk, "pw".toCharArray(), arrayOf(cert))
                ksFile.outputStream().use { store(it, "pw".toCharArray()) }
            }
            val server =
                EngineMain.createServer(
                    arrayOf(
                        "-host=127.0.0.1",
                        "-port=0",
                        "-sslPort=0",
                        "-sslKeyStore=${ksFile.path}",
                        "-P:ktor.security.ssl.keyStorePassword=pw",
                        "-P:ktor.security.ssl.privateKeyPassword=pw",
                        "-P:ktor.application.modules.size=1",
                        "-P:ktor.application.modules.0=$module",
                        "-P:kuicksilver.http3.enabled=false",
                        "-P:kuicksilver.connector.proxyProtocol.trustedSources=127.0.0.1",
                    ),
                )
            val e = assertFailsWith<io.kuicksilver.tls.TlsException.Config> { server.startSuspend(false) }
            assertTrue("kuicksilver.connector.proxyProtocol" in e.message.orEmpty(), e.message)
            server.stop(0, 0)
        }

    @Test fun tlsVersionsKeyParsed() {
        fun versions(value: String) =
            EngineMain
                .createServer(clientCaArgs("-P:kuicksilver.tls.versions=$value"))
                .engine.configuration.tls.versions
        assertEquals(
            io.kuicksilver.tls.TlsVersions.Tls13,
            EngineMain
                .createServer(clientCaArgs())
                .engine.configuration.tls.versions,
        )
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls13, versions("tls13"))
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls12And13, versions(" tls12And13 "))
        assertEquals(io.kuicksilver.tls.TlsVersions.Tls12And13, versions("TLS12AND13"))
        for (bad in listOf("tls12", "1.2", "")) {
            assertFailsWith<IllegalArgumentException>("negative: $bad") { versions(bad) }
        }
    }

    /**
     * `kuicksilver.tls.versions = tls12And13` serves the JDK's TLS 1.2 client on the deployment port (RFC 9325 section 3.1.1);
     * it needs the identity files, and is refused next to Ktor's `-sslPort`, whose key is `ktor.security.ssl.enabledProtocols`.
     */
    @Test fun tlsVersionsKeyServesTls12() =
        serverTest {
            val server = EngineMain.createServer(clientCaArgs("-P:kuicksilver.tls.versions=tls12And13"))
            assertEquals(io.kuicksilver.tls.TlsVersions.Tls12And13, server.engine.configuration.tls.versions)
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

    /**
     * A TLS 1.3 handshake of a client offering only [group] with the server on [port]; null when it worked. The JDK's client
     * where it can name its groups per socket (SSLParameters.setNamedGroups, JDK 20), else (the JDK 17 run of CI's
     * jdk-compat job) Kuicksilver's own TCP client with that group alone.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private suspend fun handshakeFails(
        port: Int,
        group: String,
    ): Throwable? {
        if (Runtime.version().feature() >= 20) return jdkHandshakeFails(port, group)
        val selector = SelectorManager(Dispatchers.IO)
        try {
            return runCatching {
                val config =
                    io.kuicksilver.tls.tlsConfig(io.kuicksilver.tls.TlsRole.Client) {
                        alpn = listOf("http/1.1")
                        serverName = "server.test"
                        trust = TrustConfig.AnchoredCa(listOf(ServerFixtures.testCa))
                        keyExchangeGroups = io.kuicksilver.tls.KeyExchangeGroups(listOf(group))
                    }
                io.kuicksilver.ktor.network
                    .connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                    .tls(config)
                    .close()
            }.exceptionOrNull()
        } finally {
            selector.close()
        }
    }

    /** [handshakeFails] with the JDK's client, which offers only [group] (its named groups; JDK 20 and later). */
    private suspend fun jdkHandshakeFails(
        port: Int,
        group: String,
    ): Throwable? =
        kotlinx.coroutines.withContext(Dispatchers.IO) {
            runCatching {
                (jdkContext().socketFactory.createSocket(java.net.InetAddress.getLoopbackAddress(), port) as javax.net.ssl.SSLSocket)
                    .use { s ->
                        s.soTimeout = 20_000
                        s.sslParameters =
                            s.sslParameters.apply {
                                protocols = arrayOf("TLSv1.3")
                                namedGroups = arrayOf(group)
                            }
                        s.startHandshake()
                    }
            }.exceptionOrNull()
        }

    /**
     * `kuicksilver.tls.keyExchangeGroups` (a list) sets the deployment port's groups: a server of secp384r1 alone serves a client
     * of secp384r1 and refuses one of x25519 (RFC 9846 section 4.2.1, handshake_failure); names are case-insensitive.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun keyExchangeGroupsKeySetsTheServersGroups() =
        serverTest {
            val server =
                EngineMain.createServer(
                    clientCaArgs("-P:kuicksilver.tls.keyExchangeGroups.size=1", "-P:kuicksilver.tls.keyExchangeGroups.0=SECP384R1"),
                )
            assertEquals(
                io.kuicksilver.tls.KeyExchangeGroups(listOf(io.kuicksilver.tls.KeyExchangeGroups.SECP384R1)),
                server.engine.configuration.tls.keyExchangeGroups,
            )
            server.startSuspend(false)
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                assertEquals(null, handshakeFails(port, "secp384r1"), "a client of secp384r1 is served")
                val refused = handshakeFails(port, "x25519")
                if (Runtime.version().feature() >= 20) {
                    assertTrue(refused is javax.net.ssl.SSLException, "a client of x25519 alone is refused: $refused")
                } else {
                    // Kuicksilver's client: the server's handshake_failure (40) alert, found along the causes
                    val alert =
                        generateSequence(refused) { it.cause }
                            .filterIsInstance<io.kuicksilver.tls.TlsException.AlertReceived>()
                            .firstOrNull()
                    assertEquals(40, alert?.code, "a client of x25519 alone is refused with handshake_failure: $refused")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A single value (a `-P:` key, or a `${?ENV}` substitution in HOCON) is read as names separated by `:` or `,`; a bad one is
     * refused with the key named, as a bad list is.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun keyExchangeGroupsKeyTakesASeparatedString() {
        val one = EngineMain.createServer(clientCaArgs("-P:kuicksilver.tls.keyExchangeGroups=x25519")).engine
        assertEquals(listOf(io.kuicksilver.tls.KeyExchangeGroups.X25519), one.configuration.tls.keyExchangeGroups.groups)
        val two = EngineMain.createServer(clientCaArgs("-P:kuicksilver.tls.keyExchangeGroups=secp384r1:x25519, secp256r1")).engine
        assertEquals(
            listOf(
                io.kuicksilver.tls.KeyExchangeGroups.SECP384R1,
                io.kuicksilver.tls.KeyExchangeGroups.X25519,
                io.kuicksilver.tls.KeyExchangeGroups.SECP256R1,
            ),
            two.configuration.tls.keyExchangeGroups.groups,
        )
        for (bad in listOf("nope", "", "x25519::secp256r1")) {
            val e =
                assertFailsWith<IllegalArgumentException>("\"$bad\"") {
                    EngineMain.createServer(clientCaArgs("-P:kuicksilver.tls.keyExchangeGroups=$bad")).engine
                }
            assertTrue(e.message.orEmpty().startsWith("kuicksilver.tls.keyExchangeGroups: "), "\"$bad\": ${e.message}")
        }
    }

    @Test fun negative_keyExchangeGroupsKeyRefusesAnInvalidListOrNoIdentity() {
        val e =
            assertFailsWith<IllegalArgumentException> {
                EngineMain
                    .createServer(
                        clientCaArgs("-P:kuicksilver.tls.keyExchangeGroups.size=1", "-P:kuicksilver.tls.keyExchangeGroups.0=P-256"),
                    ).engine
            }
        assertTrue("kuicksilver.tls.keyExchangeGroups" in e.message.orEmpty() && "P-256" in e.message.orEmpty(), e.message)
        val dup =
            assertFailsWith<IllegalArgumentException> {
                EngineMain
                    .createServer(
                        clientCaArgs(
                            "-P:kuicksilver.tls.keyExchangeGroups.size=2",
                            "-P:kuicksilver.tls.keyExchangeGroups.0=x25519",
                            "-P:kuicksilver.tls.keyExchangeGroups.1=X25519",
                        ),
                    ).engine
            }
        assertTrue("twice" in dup.message.orEmpty(), dup.message)
        val noIdentity =
            assertFailsWith<IllegalArgumentException> {
                EngineMain
                    .createServer(
                        arrayOf(
                            "-host=127.0.0.1",
                            "-port=0",
                            "-P:ktor.application.modules.size=1",
                            "-P:ktor.application.modules.0=$module",
                            "-P:kuicksilver.tls.keyExchangeGroups.size=1",
                            "-P:kuicksilver.tls.keyExchangeGroups.0=x25519",
                        ),
                    ).engine
            }
        assertTrue("certificateChain" in noIdentity.message.orEmpty(), noIdentity.message)
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

    /** Ktor's `-sslPort` connector has no key-exchange group setting: the key next to it fails the start instead of not applying. */
    @Test fun negative_keyExchangeGroupsKeyWithSslPortRefused() =
        serverTest {
            val cert = CertificateFactory.getInstance("X.509").generateCertificate(TestCerts.server.inputStream())
            val pk = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(TestCerts.serverKey))
            val ksFile = File(dir, "groups-server.p12")
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
                        "-P:kuicksilver.tls.keyExchangeGroups=secp384r1",
                    ),
                )
            val e = assertFailsWith<io.kuicksilver.tls.TlsException.Config> { server.startSuspend(false) }
            assertTrue(
                "(kuicksilver.tls.keyExchangeGroups) does not apply to" in e.message.orEmpty(),
                e.message,
            )
            server.stop(0, 0)
        }

    @Test fun clientAuthKeyParsed() {
        val ca = pem("auth-ca.pem", TestCerts.toPem("CERTIFICATE", TestCerts.testCa))

        fun auth(vararg extra: String) =
            EngineMain
                .createServer(clientCaArgs(*extra))
                .engine.configuration.tls.clientAuth
        assertEquals(ClientAuth.None, auth())
        assertEquals(ClientAuth.None, auth("-P:kuicksilver.tls.clientAuth=none"))
        assertEquals(ClientAuth.Optional, auth("-P:kuicksilver.tls.clientAuth=optional", "-P:kuicksilver.tls.clientCa=${ca.path}"))
        assertEquals(ClientAuth.Required, auth("-P:kuicksilver.tls.clientAuth= required ", "-P:kuicksilver.tls.clientCa=${ca.path}"))
        assertFailsWith<IllegalArgumentException> { auth("-P:kuicksilver.tls.clientAuth=yes") }
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
            assertIs<TrustConfig.AnchoredCa>(server.engine.configuration.tls.clientTrust)
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
            assertEquals(listOf(Certificate(TestCerts.testCa)), assertIs<TrustConfig.AnchoredCa>(config.tls.clientTrust).roots)
            config.tls.settleForTest = Duration.ZERO
            ca.writeText(TestCerts.toPem("CERTIFICATE", TestCerts.otherCa)) // renewed after the server read it
            server.startSuspend(false)
            val trust = assertIs<TrustConfig.ReloadableCa>(server.engine.engineTls.trust)
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
