// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.DelicateKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.KeyExchangeGroups
import io.kuicksilver.tls.TlsVersions
import java.io.File
import java.nio.file.Files
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * The `EngineMain` keys follow the engine's DSL (ADR-0026, design section 4): each of [EngineMain.KNOWN_KEYS] reaches its
 * option, every old key fails the start with its replacement named, an unknown key with the closest known one, `off` is
 * the only "none" and `0` is refused where it would mean one.
 */
class EngineMainKeysTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val dir: File = Files.createTempDirectory("kuicksilver-engine-keys").toFile().also { it.deleteOnExit() }
    private val chain = File(dir, "chain.pem").apply { writeText(TestCerts.toPem("CERTIFICATE", TestCerts.server)) }
    private val key = File(dir, "key.pem").apply { writeText(TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey)) }
    private val ca = File(dir, "ca.pem").apply { writeText(TestCerts.toPem("CERTIFICATE", TestCerts.testCa)) }
    private val ocsp = File(dir, "ocsp.der").apply { writeBytes(byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x00)) }
    private val ech = File(dir, "ech.pem").apply { writeText(EchTestKeys.A) }

    private fun configuration(vararg keys: String): KuicksilverApplicationEngine.Configuration {
        val server = EngineMain.createServer(arrayOf("-host=127.0.0.1", "-port=0", *keys.map { "-P:$it" }.toTypedArray()))
        return server.engine.configuration
    }

    private fun refused(vararg keys: String): String =
        assertFailsWith<IllegalArgumentException>(keys.joinToString()) { configuration(*keys) }.message!!

    private val tlsFiles = arrayOf("kuicksilver.tls.certificateChain=${chain.path}", "kuicksilver.tls.privateKey=${key.path}")

    /** A non-default value per key, what it sets, and the keys it needs besides itself. */
    private class Row(
        val key: String,
        val value: String,
        val needs: Array<String> = emptyArray(),
        val check: (KuicksilverApplicationEngine.Configuration) -> Unit,
    )

    private val rows: List<Row> by lazy {
        listOf(
            Row("kuicksilver.requestHeaderTimeout", "PT10S") { assertEquals(10.seconds, it.requestHeaderTimeout) },
            Row("kuicksilver.tls.certificateChain", chain.path, arrayOf("kuicksilver.tls.privateKey=${key.path}")) {
                assertNotNull(it.tls.identity)
                assertEquals(chain.path to key.path, it.tls.identityFiles)
            },
            Row("kuicksilver.tls.privateKey", key.path, arrayOf("kuicksilver.tls.certificateChain=${chain.path}")) {
                assertNotNull(it.tls.identity)
            },
            Row("kuicksilver.tls.reloadInterval", "1h", tlsFiles) { assertEquals(1.hours, it.tls.reloadInterval) },
            Row("kuicksilver.tls.clientAuth", "REQUIRED", tlsFiles + "kuicksilver.tls.clientCa=${ca.path}") {
                assertEquals(ClientAuth.Required, it.tls.clientAuth, "names in any case")
            },
            Row("kuicksilver.tls.clientCa", ca.path, tlsFiles + "kuicksilver.tls.clientAuth=optional") {
                assertEquals(ca.path, it.tls.clientCaFile)
            },
            Row("kuicksilver.tls.versions", "tls12And13", tlsFiles) { assertEquals(TlsVersions.Tls12And13, it.tls.versions) },
            Row("kuicksilver.tls.keyExchangeGroups", "x25519:secp256r1", tlsFiles) {
                assertEquals(listOf(KeyExchangeGroups.X25519, KeyExchangeGroups.SECP256R1), it.tls.keyExchangeGroups.groups)
            },
            Row("kuicksilver.tls.ocspStapling", ocsp.path, tlsFiles) { assertEquals(ocsp.path, it.tls.ocspFile) },
            Row("kuicksilver.tls.echKeys", ech.path, tlsFiles) {
                assertNotNull(it.tls.echKeys)
                assertTrue(it.tls.closeEchKeysOnStop)
                it.tls.echKeys!!.close()
            },
            Row("kuicksilver.connector.allowMisdirectedHosts", "true") { assertTrue(it.deploymentAllowMisdirectedHosts) },
            Row("kuicksilver.connector.h2c", "withHttp11") { assertEquals(H2cMode.WithHttp11, it.deploymentH2c) },
            Row("kuicksilver.connector.proxyProtocol.trustedSources", "10.0.0.0/8,192.0.2.7") {
                assertEquals(listOf("10.0.0.0/8", "192.0.2.7"), it.deploymentProxyProtocol!!.trustedSources)
            },
            Row(
                "kuicksilver.connector.proxyProtocol.headerTimeout",
                "4s",
                arrayOf("kuicksilver.connector.proxyProtocol.trustedSources=10.0.0.0/8"),
            ) { assertEquals(4.seconds, it.deploymentProxyProtocol!!.headerTimeout) },
            Row(
                "kuicksilver.connector.proxyProtocol.maxHeaderSize",
                "1024",
                arrayOf("kuicksilver.connector.proxyProtocol.trustedSources=10.0.0.0/8"),
            ) { assertEquals(1024, it.deploymentProxyProtocol!!.maxHeaderSize) },
            Row("kuicksilver.http1.allowBareLf", "true") { assertTrue(it.http1.allowBareLf) },
            Row("kuicksilver.http2.enabled", "true") { assertTrue(it.http2.enabled) },
            Row("kuicksilver.http2.repeatOffenderPenalty", "30s") { assertEquals(30.seconds, it.http2.repeatOffenderPenalty) },
            Row("kuicksilver.http3.enabled", "false") { assertEquals(false, it.http3.enabled) },
            Row("kuicksilver.http3.altSvc", "false") { assertEquals(false, it.http3.altSvc) },
            Row("kuicksilver.http3.earlyData.enabled", "true") { assertTrue(it.http3.earlyData.enabled) },
            Row("kuicksilver.http3.endpoint.loops", "2") { assertEquals(2, it.http3.endpoint.loops) },
            Row("kuicksilver.http3.endpoint.maxConnections", "500") { assertEquals(500, it.http3.endpoint.maxConnections) },
            Row("kuicksilver.http3.endpoint.maxConnectionsPerIp", "4096") { assertEquals(4096, it.http3.endpoint.maxConnectionsPerIp) },
            Row("kuicksilver.http3.endpoint.acceptQueue", "512") { assertEquals(512, it.http3.endpoint.acceptQueue) },
            Row("kuicksilver.http3.quic.maxIdleTimeout", "1m") { assertEquals(1.minutes, it.resolveQuic().maxIdleTimeout) },
            Row("kuicksilver.http3.quic.handshakeTimeout", "5s") { assertEquals(5.seconds, it.resolveQuic().handshakeTimeout) },
            Row("kuicksilver.http3.quic.keepAlive", "15s") { assertEquals(15.seconds, it.resolveQuic().keepAlive) },
            Row("kuicksilver.http3.quic.maxBidiStreams", "500") { assertEquals(500L, it.resolveQuic().maxBidiStreams) },
            Row("kuicksilver.http3.quic.pathMtu.maxReceive", "1400") { assertEquals(1400, it.resolveQuic().maxUdpPayloadSize) },
            Row("kuicksilver.http3.quic.pathMtu.initial", "1350") { assertEquals(1350, it.resolveQuic().initialUdpPayloadSize) },
            Row("kuicksilver.http3.quic.pathMtu.maxSend", "1380") { assertEquals(1380, it.resolveQuic().maxSendUdpPayloadSize) },
            Row("kuicksilver.http3.quic.pathMtu.discovery", "false") { assertEquals(false, it.resolveQuic().pmtud) },
            Row("kuicksilver.http3.quic.migration.allow", "false") { assertEquals(false, it.resolveQuic().allowMigration) },
            Row("kuicksilver.webSockets.overHttp2", "false") { assertEquals(false, it.webSockets.overHttp2) },
            Row("kuicksilver.webSockets.overHttp3", "false") { assertEquals(false, it.webSockets.overHttp3) },
            Row("kuicksilver.webSockets.maxMessageSize", "1024") { assertEquals(1024L, it.webSockets.maxMessageSize) },
            Row("kuicksilver.tcp.maxConnections", "50") { assertEquals(50, it.tcp.maxConnections) },
            Row("kuicksilver.tcp.maxConnectionsPerIp", "256") { assertEquals(256, it.tcp.maxConnectionsPerIp) },
        )
    }

    @Test fun everyKnownKeyReachesItsOption() {
        assertEquals(EngineMain.KNOWN_KEYS, rows.map { it.key }.toSet(), "a row per key")
        for (row in rows) {
            val c = configuration("${row.key}=${row.value}", *row.needs)
            row.check(c)
        }
    }

    @Test fun ktorsIdleTimeoutKeyIsTheHttp1One() {
        assertEquals(90.seconds, configuration("ktor.deployment.connectionIdleTimeoutSeconds=90").http1.idleTimeout)
    }

    @Test fun negative_everyRenamedKeyNamesItsReplacement() {
        for ((old, new) in EngineMain.RENAMED_KEYS) {
            if (old == "kuicksilver.http3") continue // a scalar there has a message of its own
            assertEquals("$old was replaced in 0.3.0 by $new", refused("$old=1"), old)
        }
    }

    @Test fun negative_the02xHttp3SwitchNamesTheBlock() {
        assertEquals(
            "kuicksilver.http3 = true|false was replaced in 0.3.0 by kuicksilver.http3.enabled",
            refused("kuicksilver.http3=false"),
        )
    }

    @Test fun negative_the02xAltSvcKeyNamesItsReplacement() {
        assertEquals("kuicksilver.altSvc was replaced in 0.3.0 by kuicksilver.http3.altSvc", refused("kuicksilver.altSvc=false"))
    }

    @Test fun negative_the02xUdpSocketCountKeyNamesItsReplacement() {
        assertEquals(
            "kuicksilver.udpSocketCount was replaced in 0.3.0 by kuicksilver.http3.endpoint.loops",
            refused("kuicksilver.udpSocketCount=2"),
        )
    }

    @Test fun negative_the02xWebSocketsOverHttp3KeyNamesItsReplacement() {
        assertEquals(
            "kuicksilver.webSocketsOverHttp3 was replaced in 0.3.0 by kuicksilver.webSockets.overHttp3",
            refused("kuicksilver.webSocketsOverHttp3=false"),
        )
    }

    @Test fun negative_aDerivedKeyIsRefused() {
        assertEquals(
            "kuicksilver.quic.maxUniStreams is derived by the engine (RFC 9114 section 6.2: HTTP/3 needs at least 3, the engine keeps the default); remove it",
            refused("kuicksilver.quic.maxUniStreams=16"),
        )
    }

    @Test fun negative_aTypoNamesTheClosestKey() {
        assertEquals(
            "kuicksilver.http3.endpoint.maxConections is not a Kuicksilver key; did you mean kuicksilver.http3.endpoint.maxConnections?",
            refused("kuicksilver.http3.endpoint.maxConections=5"),
        )
        // an old key misspelt: its replacement
        assertEquals(
            "kuicksilver.udpSocketCont is not a Kuicksilver key; did you mean kuicksilver.http3.endpoint.loops?",
            refused("kuicksilver.udpSocketCont=2"),
        )
        // a known name in the wrong block
        assertEquals(
            "kuicksilver.http3.quic.maxConnections is not a Kuicksilver key; did you mean kuicksilver.http3.endpoint.maxConnections?",
            refused("kuicksilver.http3.quic.maxConnections=5"),
        )
        assertEquals("kuicksilver.colour is not a Kuicksilver key", refused("kuicksilver.colour=blue"))
    }

    @Test fun offIsTheOnlyNone() {
        assertNull(configuration("kuicksilver.http2.repeatOffenderPenalty=off").http2.repeatOffenderPenalty)
        assertNull(configuration("kuicksilver.http3.endpoint.maxConnectionsPerIp=off").http3.endpoint.maxConnectionsPerIp)
        assertNull(configuration("kuicksilver.tcp.maxConnectionsPerIp=off").tcp.maxConnectionsPerIp)
        assertEquals(
            kotlin.time.Duration.ZERO,
            configuration("kuicksilver.http3.quic.maxIdleTimeout=off").resolveQuic().maxIdleTimeout,
            "no idle timeout",
        )
        assertNull(configuration("kuicksilver.http3.quic.keepAlive=off").resolveQuic().keepAlive)
        assertNull(configuration("kuicksilver.tls.reloadInterval=off", *tlsFiles).tls.reloadInterval)
    }

    @Test fun negative_zeroForNoneIsRefused() {
        for (key in listOf(
            "kuicksilver.http2.repeatOffenderPenalty",
            "kuicksilver.http3.endpoint.maxConnectionsPerIp",
            "kuicksilver.tcp.maxConnectionsPerIp",
            "kuicksilver.http3.quic.maxIdleTimeout",
            "kuicksilver.http3.quic.keepAlive",
        )) {
            assertEquals("$key: use off instead of 0", refused("$key=0"))
        }
        assertEquals("kuicksilver.tls.reloadInterval: use off instead of 0", refused("kuicksilver.tls.reloadInterval=0", *tlsFiles))
    }

    @Test fun negative_valuesAreStrict() {
        assertEquals("kuicksilver.http2.enabled: \"yes\" is not true or false", refused("kuicksilver.http2.enabled=yes"))
        assertEquals(
            "kuicksilver.requestHeaderTimeout: \"soon\" is not a duration in whole milliseconds (30s, 1h, 250ms)",
            refused("kuicksilver.requestHeaderTimeout=soon"),
        )
        // the timers and transport parameters behind a key work in milliseconds: 0.5ms would become 0, "none"
        for (v in listOf("0.5ms", "1500us", "1.0005s")) {
            assertEquals(
                "kuicksilver.http3.quic.maxIdleTimeout: \"$v\" is not a duration in whole milliseconds (30s, 1h, 250ms), or off",
                refused("kuicksilver.http3.quic.maxIdleTimeout=$v"),
            )
        }
        assertEquals(
            "kuicksilver.requestHeaderTimeout: \"2500us\" is not a duration in whole milliseconds (30s, 1h, 250ms)",
            refused("kuicksilver.requestHeaderTimeout=2500us"),
        )
        assertEquals(1500.milliseconds, configuration("kuicksilver.requestHeaderTimeout=1.5s").requestHeaderTimeout)
        assertEquals("kuicksilver.tcp.maxConnections: \"many\" is not a whole number", refused("kuicksilver.tcp.maxConnections=many"))
        assertEquals("kuicksilver.connector.h2c: \"both\" is not off, withHttp11, only", refused("kuicksilver.connector.h2c=both"))
        // the option's own refusal, with the key in front
        assertEquals(
            "kuicksilver.tcp.maxConnections: tcp { maxConnections } must be at least 1",
            refused("kuicksilver.tcp.maxConnections=-1"),
        )
        assertEquals(
            "kuicksilver.requestHeaderTimeout: requestHeaderTimeout must be a positive, finite duration",
            refused("kuicksilver.requestHeaderTimeout=0s"),
        )
    }
}
