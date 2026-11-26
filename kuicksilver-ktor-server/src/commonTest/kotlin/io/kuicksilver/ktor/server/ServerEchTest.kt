// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.EchConfigList
import io.kuicksilver.tls.EchKey
import io.kuicksilver.tls.EchServerKeys
import io.kuicksilver.tls.EchStatus
import io.kuicksilver.tls.ServerTlsOverride
import io.kuicksilver.tls.SessionCache
import io.kuicksilver.tls.TlsConnection
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsIdentity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The TLS connector's Encrypted Client Hello keys (RFC 9849 section 7.1, shared mode): accepted, rejected with retry
 * configurations, rotated while the server runs, and the `sniSelector` during a rejection, which is asked for the
 * public_name and whose certificate for it the client authenticates (section 6.1.7).
 */
class ServerEchTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun listOf(pem: String): EchConfigList {
        val body = pem.substringAfter("-----BEGIN ECHCONFIG-----").substringBefore("-----END ECHCONFIG-----")
        return EchConfigList.parseBase64(body.lines().joinToString(""))
    }

    private val listA by lazy { listOf(EchTestKeys.A) }
    private val listB by lazy { listOf(EchTestKeys.B) }

    /** The certificate for `server.test` alone (with its intermediate): it does not cover the public_name. */
    private fun innerOnly(): TlsIdentity =
        TlsIdentity.fromDer(
            kotlin.collections.listOf(TestCerts.serverBigChain, TestCerts.intermediate),
            TestCerts.serverBigChainKey.copyOf(),
        )

    /** A TLS connector with [keys]; its selector records each name and answers by it, the default identity covering neither. */
    private suspend fun server(
        keys: EchServerKeys,
        names: MutableList<String?>,
        lock: Mutex,
    ): Pair<Server, Int> {
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { identity = TlsIdentity.fromDer(kotlin.collections.listOf(TestCerts.proxy), TestCerts.proxyKey.copyOf()) }
                    host = "127.0.0.1"
                    port = 0
                    tls { echKeys = keys }
                    tls {
                        sniSelector = { hello ->
                            lock.withLock { names += hello.serverName }
                            when (hello.serverName) {
                                EchTestKeys.PUBLIC_NAME -> ServerTlsOverride(ServerFixtures.identity())

                                // covers *.wild.test
                                "server.test" -> ServerTlsOverride(innerOnly())

                                else -> null
                            }
                        }
                    }
                }
            }) { routing { get("/") { call.respondText("ok") } } }
        server.startSuspend(false)
        return server to
            server.engine
                .resolvedConnectors()
                .first()
                .port
    }

    /**
     * A handshake on a session cache of its own, closed before this returns: the tickets the server sends after the handshake
     * (six per connection) are released whenever the connection's reader stores them, before or after. A cache left open kept
     * them for the rest of the process, which the leak sentinel reported as `ksl.session x12` when both accepted handshakes'
     * tickets were read before the socket closed (seen on Windows).
     */
    private suspend fun handshake(
        port: Int,
        list: EchConfigList,
    ): TlsConnection {
        val selector = SelectorManager(Dispatchers.IO)
        val cache = SessionCache()
        val tcp =
            io.kuicksilver.ktor.network
                .connectTcp(selector, InetSocketAddress("127.0.0.1", port))
        return try {
            withTimeout(10.seconds) {
                val tls =
                    TlsConnection.client(
                        tcp.openReadChannel(),
                        tcp.openWriteChannel(autoFlush = true),
                        io.kuicksilver.tls.tlsConfig(io.kuicksilver.tls.TlsRole.Client) {
                            alpn = kotlin.collections.listOf("http/1.1")
                            serverName = "server.test"
                            trust =
                                io.kuicksilver.tls.TrustConfig
                                    .AnchoredCa(kotlin.collections.listOf(ServerFixtures.testCa))
                            ech { configList = list }
                        },
                        EmptyCoroutineContext,
                        cache,
                    )
                // the server's six tickets (TlsConnection.TCP_TICKETS) stored before the socket closes, as Windows read them:
                // every run then has tickets for the cache to release
                try {
                    while (cache.size() < 6) delay(5)
                } catch (t: Throwable) {
                    tls.close()
                    throw t
                }
                tls
            }
        } finally {
            tcp.close()
            selector.close()
            cache.close()
        }
    }

    /**
     * Accepted: the selector sees the inner name. Rejected (another key): the selector sees the public_name, its certificate
     * for it authenticates the rejection, and the client gets the connector's retry configurations; after a rotation the
     * new key is accepted on the same server.
     */
    @Test fun keysRejectionSelectorAndRotation() =
        runBlocking {
            val names = ArrayList<String?>()
            val lock = Mutex()
            val keys = EchServerKeys(kotlin.collections.listOf(EchKey(EchTestKeys.A)))
            val (server, port) = server(keys, names, lock)
            try {
                val accepted = handshake(port, listA)
                assertEquals(EchStatus.Accepted, accepted.echStatus)
                accepted.close()
                keys.rotate(kotlin.collections.listOf(EchKey(EchTestKeys.B)))
                val e = assertFailsWith<TlsException.EchRejected> { handshake(port, listA) }
                assertEquals(listB, e.retryConfigs)
                val retried = handshake(port, e.retryConfigs!!)
                assertEquals(EchStatus.Accepted, retried.echStatus)
                retried.close()
                assertEquals(
                    kotlin.collections.listOf<String?>("server.test", EchTestKeys.PUBLIC_NAME, "server.test"),
                    lock.withLock { names.toList() },
                )
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    /**
     * The selector's answer for the public_name is what the client checks during a rejection: one that does not cover the
     * public_name leaves the rejection unauthenticated (RFC 9849 section 6.1.7), and the client gets no retry configurations.
     */
    @Test fun negative_aPublicNameCertificateThatDoesNotCoverItFailsTheRejection() =
        runBlocking {
            val server =
                embeddedServer(Kuicksilver, configure = {
                    tlsConnector {
                        tls { identity = innerOnly() }
                        host = "127.0.0.1"
                        port = 0
                        tls { echKeys = EchServerKeys(kotlin.collections.listOf(EchKey(EchTestKeys.B))) }
                    }
                }) { routing { get("/") { call.respondText("ok") } } }
            server.startSuspend(false)
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                val e = assertFailsWith<TlsException> { handshake(port, listA) }
                assertTrue(e is TlsException.Verify, "$e")
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    @Test fun connectorCarriesTheKeysToBothTlsConfigurations() {
        val keys = EchServerKeys(kotlin.collections.listOf(EchKey(EchTestKeys.A)))
        val c =
            testConnector {
                tls {
                    identity = ServerFixtures.identity()
                    echKeys = keys
                }
            }
        assertEquals(keys, c.tlsConfig(kotlin.collections.listOf("http/1.1")).echKeys)
        assertEquals(keys, c.tlsConfig(kotlin.collections.listOf("h3")).echKeys)
        assertEquals(keys, c.withPort(1).tls.echKeys)
    }
}
