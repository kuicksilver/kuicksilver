// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)

package io.kuicksilver.quic.api

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.MemoryNetwork
import io.kuicksilver.quic.MemoryTokenStore
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.QuicTokenStore
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * The token store's `take` removes the token: one it returns as the store's deadline fires (the timeout lands on another
 * thread after `take` returned, before the deadline's scope completed) is used, never dropped.
 */
class TokenStoreRaceTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val serverAddr = InetSocketAddress("10.0.0.2", 2222)
    private val clientAddr = InetSocketAddress("10.0.0.1", 1111)

    @Test fun negative_aTokenTakenAsTheDeadlineFiresIsUsed(): Unit =
        runBlocking {
            val net = MemoryNetwork()
            val b = net.open(serverAddr)
            val a = net.open(clientAddr)
            val server =
                QuicEndpoint.bind(
                    serverAddr,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                            crypto = KslQuicCrypto
                            admission = ConnectionAdmission.AlwaysRetry
                            io = { b }
                        }.build(),
                )
            val client =
                QuicEndpoint.bind(
                    clientAddr,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            crypto = KslQuicCrypto
                            io = { a }
                        }.build(),
                )
            try {
                withTimeout(20.seconds) {
                    val inner = MemoryTokenStore()
                    val stored = CompletableDeferred<Unit>()
                    var racing = false
                    val store =
                        object : QuicTokenStore {
                            override suspend fun put(
                                key: String,
                                token: ByteArray,
                            ) {
                                inner.put(key, token)
                                stored.complete(Unit)
                            }

                            override suspend fun take(key: String): ByteArray? {
                                val t = inner.take(key)
                                if (racing) {
                                    yield() // returns through a resumption, as a real store does
                                    val job = currentCoroutineContext().job
                                    while (!job.isCancelled) Thread.onSpinWait() // the deadline fires meanwhile
                                }
                                return t
                            }
                        }
                    val config = QuicClientConfig.Builder(CoreFixtures.client()).apply { tokenStore = store }.build()

                    suspend fun connectOnce() =
                        coroutineScope {
                            val accepted = async { server.accept() }
                            val c = client.connect(serverAddr, config)
                            accepted.await()
                            c.close()
                        }
                    connectOnce()
                    stored.await()
                    racing = true
                    val retries = server.stats.retriesSent
                    connectOnce()
                    assertEquals(1L, server.stats.newTokensAccepted, "the token the store gave up is in the Initial")
                    assertEquals(retries, server.stats.retriesSent, "no Retry for the token holder")
                }
            } finally {
                client.close()
                server.close()
            }
        }
}
