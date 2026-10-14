// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.quic

import android.content.Context
import android.net.ConnectivityManager
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.api.readExactly
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The Android binding of [NetworkMigrator] on a device or emulator, over loopback (runs in CI's android job). */
@RunWith(AndroidJUnit4::class)
class NetworkMigrationAndroidTest {
    private val connectivity =
        InstrumentationRegistry.getInstrumentation().targetContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    /** The Android sample of docs/guide/quic.md (an instrumentation test has no lifecycle: a coroutine scope stands in). */
    @Test fun followDefaultNetworkSample() =
        runBlocking {
            KslLoader.ensureLoaded()
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val lo = InetSocketAddress("127.0.0.1", 0)
            val server =
                QuicEndpoint.bind(
                    lo,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                            crypto = KslQuicCrypto
                        }.build(),
                )
            val client = QuicEndpoint.bind(lo, QuicEndpointConfig.Builder().apply { crypto = KslQuicCrypto }.build())
            try {
                withTimeout(60.seconds) {
                    val accepted = async { server.accept() }
                    val connection = client.connect(server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                    accepted.await()
                    val lifecycleScope = this
                    // guide:quic:android-follow
                    val cm = context.getSystemService(ConnectivityManager::class.java)
                    val migrator = connection.followDefaultNetwork(cm, lifecycleScope) // started; migrator.close() stops it
                    val log = lifecycleScope.launch { migrator.events.collect { Log.i("quic", "$it") } }
                    migrator.close()
                    log.cancel()
                    connection.close()
                }
            } finally {
                client.close()
                server.close()
            }
        }

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

    /** A real migration between two sockets bound to the active network (different local ports: the key changes, the network not). */
    @Test fun migratesBetweenTwoSocketsOnTheActiveNetwork() =
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
                    val s = accepted.await()
                    val echo =
                        launch {
                            while (true) {
                                val st = s.acceptStream()
                                val got = st.input.readExactly(4)
                                st.output.writeFully(got, 0, 4)
                                st.output.flushAndClose()
                            }
                        }

                    suspend fun roundTrip() {
                        val st = c.openBidi()
                        st.output.writeFully(byteArrayOf(1, 2, 3, 4), 0, 4)
                        st.output.flushAndClose()
                        assertContentEquals(byteArrayOf(1, 2, 3, 4), st.input.readExactly(4))
                    }
                    roundTrip()
                    val keys = MutableStateFlow<Pair<android.net.Network, Int>?>(network!! to 1)
                    val m = NetworkMigrator(c, keys, { (n, _) -> DatagramIo.open(lo, n) }, this)
                    val migrated = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { m.events.first() }
                    m.start()
                    m.network.first { it != null }
                    val before = c.activePath!!.localAddress
                    keys.value = network to 2 // same network, a new socket: a real path change
                    val e = assertIs<MigrationEvent.Migrated<Pair<android.net.Network, Int>>>(migrated.await())
                    assertEquals(2, e.new.second)
                    assertNotEquals(before, c.activePath!!.localAddress, "the connection moved to the new socket")
                    roundTrip() // traffic continues on the new path
                    m.close()
                    echo.cancel()
                    c.close()
                }
            } finally {
                client.close()
                server.close()
            }
        }

    /**
     * `defaultNetworks()` starts with the current default network, and its shared callback is unregistered when the last
     * collector stops: 150 collections in a row stay below Android's limit of about 100 callbacks per app.
     */
    @Test fun defaultNetworksStartsWithTheDefaultAndReleasesItsCallback() =
        runBlocking {
            val network = connectivity.activeNetwork
            assumeTrue("the device has a default network", network != null)
            withTimeout(60.seconds) {
                repeat(150) { assertEquals(network, connectivity.defaultNetworks().first()) }
                // two collectors at once share one callback and both see the default
                val a = async { connectivity.defaultNetworks().first() }
                val b = async { connectivity.defaultNetworks().first() }
                assertEquals(network, a.await())
                assertEquals(network, b.await())
            }
        }

    /** `followDefaultNetwork` takes the current default network as the connection's: no migration, traffic goes on. */
    @Test fun followDefaultNetworkStaysOnTheCurrentDefault() =
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
                            crypto = KslQuicCrypto
                        }.build(),
                )
            val client = QuicEndpoint.bind(lo, QuicEndpointConfig.Builder().apply { crypto = KslQuicCrypto }.build())
            try {
                withTimeout(60.seconds) {
                    val accepted = async { server.accept() }
                    val c = client.connect(server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                    val s = accepted.await()
                    val echo =
                        launch {
                            val st = s.acceptStream()
                            val got = st.input.readExactly(4)
                            st.output.writeFully(got, 0, 4)
                            st.output.flushAndClose()
                        }
                    val m = c.followDefaultNetwork(connectivity, this, local = lo)
                    assertEquals(network, m.network.first { it != null })
                    assertEquals(1, c.paths.size, "the default network it is already on: no new path")
                    val st = c.openBidi()
                    st.output.writeFully(byteArrayOf(5, 6, 7, 8), 0, 4)
                    st.output.flushAndClose()
                    assertContentEquals(byteArrayOf(5, 6, 7, 8), st.input.readExactly(4))
                    echo.join()
                    m.close()
                    c.close()
                }
            } finally {
                client.close()
                server.close()
            }
        }
}
