// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
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
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

/**
 * `tls { pemFiles(...); clientCaFile(...); reloadInterval }` in code watches its files as `EngineMain`'s
 * `kuicksilver.tls.*` keys do: the same watcher, started by the engine.
 */
class ServerPemFilesJvmTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val dir: File = Files.createTempDirectory("kuicksilver-pem-files").toFile().also { it.deleteOnExit() }

    private fun pem(
        name: String,
        text: String,
    ) = File(dir, name).apply { writeText(text) }

    @Test fun renewedFilesAreServedWithoutRestart() =
        serverTest {
            val chain = pem("chain.pem", TestCerts.toPem("CERTIFICATE", TestCerts.server))
            val key = pem("key.pem", TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey))
            val ca = pem("ca.pem", TestCerts.toPem("CERTIFICATE", TestCerts.testCa))
            val server =
                kuicksilverServer(null, configure = {
                    tls {
                        pemFiles(chain.path, key.path)
                        clientCaFile(ca.path)
                        clientAuth = ClientAuth.Optional
                        reloadInterval = 1.hours
                        settleForTest = Duration.ZERO
                    }
                    tlsConnector {
                        host = "127.0.0.1"
                        port = 0
                    }
                    http3 { enabled = false }
                }) { routing { get("/") { call.respondText("pem files") } } }
            assertIs<TrustConfig.AnchoredCa>(server.engine.configuration.tls.clientTrust, "read now")
            // renewed after the configuration read them: the watchers' checks at startup find them
            chain.writeText(
                TestCerts.toPem("CERTIFICATE", TestCerts.serverViaIntermediate) + TestCerts.toPem("CERTIFICATE", TestCerts.intermediate),
            )
            key.writeText(TestCerts.toPem("PRIVATE KEY", TestCerts.serverViaIntermediateKey))
            ca.writeText(TestCerts.toPem("CERTIFICATE", TestCerts.otherCa))
            server.startSuspend(false)
            val identity = assertIs<TlsIdentity.Reloadable>(server.engine.engineTls.identity)
            val trust = assertIs<TrustConfig.ReloadableCa>(server.engine.engineTls.trust)
            try {
                val applied =
                    withTimeoutOrNull(20.seconds) {
                        while (identity.current.chain[0] != Certificate(TestCerts.serverViaIntermediate) ||
                            trust.current.roots != listOf(Certificate(TestCerts.otherCa))
                        ) {
                            yield()
                        }
                        true
                    }
                assertTrue(applied == true, "the watchers did not apply the renewed files within 20 s")
                val port =
                    server.engine
                        .resolvedConnectors()
                        .single()
                        .port
                val selector = SelectorManager(Dispatchers.IO)
                try {
                    val socket =
                        io.kuicksilver.ktor.network
                            .connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                            .tls(ServerFixtures.clientTls())
                    try {
                        assertEquals(Certificate(TestCerts.serverViaIntermediate), socket.peerCertificates[0], "the renewed leaf")
                    } finally {
                        socket.close()
                    }
                } finally {
                    selector.close()
                }
            } finally {
                server.stop(100, 500)
            }
            val probe =
                TlsIdentity.fromPem(
                    TestCerts.toPem("CERTIFICATE", TestCerts.server),
                    TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey).toCharArray(),
                )
            assertFailsWith<IllegalStateException>("the identity read from files is closed with the engine") { identity.reload(probe) }
            probe.close()
        }

    @Test fun negative_aCombinedPemIsRefusedWithReloadInterval() =
        serverTest {
            val keyText = TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey)
            val combined = pem("combined.pem", TestCerts.toPem("CERTIFICATE", TestCerts.server) + keyText)
            val key = pem("combined-key.pem", keyText)
            val server =
                kuicksilverServer(null, configure = {
                    tls {
                        pemFiles(combined.path, key.path) // accepted while nothing watches the file
                        reloadInterval = 1.hours
                    }
                    tlsConnector {
                        host = "127.0.0.1"
                        port = 0
                    }
                }) {}
            val e = assertFailsWith<kotlinx.io.IOException> { server.startSuspend(false) }
            assertTrue("contains a private key" in e.message!!, e.message)
            runCatching { server.stopSuspend(0, 0) }
        }
}
