// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.quic

import android.content.Context
import android.net.ConnectivityManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The Android binding of [NetworkMigrator] on a device or emulator, over loopback (runs in CI's android job). */
@RunWith(AndroidJUnit4::class)
class NetworkMigrationAndroidTest {
    private val connectivity =
        InstrumentationRegistry.getInstrumentation().targetContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    @Test fun bindingToTheActiveNetworkSucceeds() =
        runBlocking {
            KslLoader.ensureLoaded()
            val network = connectivity.activeNetwork
            assumeTrue("the device has a default network", network != null)
            for (prefer in IoPreference.entries) {
                val io = DatagramIo.open(InetSocketAddress("0.0.0.0", 0), network!!, prefer)
                try {
                    assertTrue(io.localAddress.port != 0, "$prefer bound")
                } finally {
                    io.close()
                }
            }
        }

    @Test fun theSameNetworkReportedTwiceDoesNotMigrate() =
        runBlocking {
            KslLoader.ensureLoaded()
            val network = connectivity.activeNetwork
            assumeTrue("the device has a default network", network != null)
            val lo = InetSocketAddress("127.0.0.1", 0)
            val server =
                QuicEndpoint.bind(
                    lo,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                            ; crypto = KslQuicCrypto
                        }.build(),
                )
            val client = QuicEndpoint.bind(lo, QuicEndpointConfig.Builder().apply { crypto = KslQuicCrypto }.build())
            try {
                withTimeout(60.seconds) {
                    val accepted = async { server.accept() }
                    val c = client.connect(server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                    accepted.await()
                    val reports = Channel<android.net.Network?>(Channel.UNLIMITED)
                    var opened = 0
                    val m =
                        NetworkMigrator(c, reports.receiveAsFlow(), { n ->
                            opened++
                            DatagramIo.open(lo, n)
                        }, this)
                    val first = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { m.events.first() }
                    m.start()
                    for (r in listOf(network, network, network, null)) reports.send(r) // the null orders after the repeats
                    assertEquals(MigrationEvent.NetworkLost, first.await(), "nothing happened before the loss")
                    assertEquals(network, m.network.value)
                    m.close()
                    assertEquals(0, opened, "the same network twice is no change")
                    assertEquals(1, c.paths.size)
                    c.close()
                }
            } finally {
                client.close()
                server.close()
            }
        }
}
