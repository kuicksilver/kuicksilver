// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.MemoryDatagramIo
import io.kuicksilver.quic.MemoryNetwork
import io.kuicksilver.quic.PreferredAddress
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TrackingCrypto
import kotlinx.coroutines.runBlocking
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** An endpoint that fails to come up closes every socket it opened and frees every key it made. */
@OptIn(ExperimentalKuicksilverApi::class)
class EndpointLoopCleanupTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val serverAddr = InetSocketAddress("10.0.0.2", 2222)
    private val otherAddr = InetSocketAddress("10.0.0.3", 2222)
    private val preferredAddr = InetSocketAddress("10.0.0.4", 4444)

    private fun config(
        crypto: TrackingCrypto,
        loops: Int = 1,
        open: ((InetSocketAddress) -> DatagramIo)? = null,
    ) = QuicEndpointConfig
        .Builder()
        .apply {
            server =
                QuicServerConfig
                    .Builder(CoreFixtures.server())
                    .apply { preferredAddress = PreferredAddress(preferredAddr, null) }
                    .build()
            this.crypto = crypto
            this.loops = loops
            open?.let { o -> io = { at -> o(at) } }
        }.build()

    @Test fun aLoopThatCannotBeBuiltClosesTheSocketsBindOpened() =
        runBlocking {
            val net = MemoryNetwork()
            val opened = ArrayList<MemoryDatagramIo>()
            val crypto = TrackingCrypto(resetKeys = 0) // the endpoint core cannot be made
            assertFailsWith<IllegalStateException> {
                EndpointLoop.bind(serverAddr, config(crypto) { at -> net.open(at).also { opened += it } })
            }
            assertEquals(listOf(serverAddr, preferredAddr), opened.map { it.localAddress }, "the main and the preferred socket")
            assertTrue(opened.all { it.closed }, "every socket bind opened is closed")
            assertEquals(0, crypto.live)
        }

    @Test fun aGroupWhoseSecondLoopCannotBeBuiltFreesTheFirstAndClosesEverySocket() =
        runBlocking {
            val net = MemoryNetwork()
            val crypto = TrackingCrypto(resetKeys = 1) // loop 0 is built, loop 1 is not
            val ios = listOf(net.open(serverAddr), net.open(otherAddr))
            val preferred = listOf(listOf<DatagramIo>(net.open(preferredAddr)), emptyList())
            assertFailsWith<IllegalStateException> { LoopGroup.create(config(crypto, loops = 2), ios, preferred) }
            assertTrue(ios.all { it.closed }, "the loops' sockets")
            assertTrue((preferred[0][0] as MemoryDatagramIo).closed, "the preferred socket")
            assertEquals(0, crypto.live, "loop 0's reset key and its reference to the group's token keys")
        }

    /** A socket whose close throws, after it really closed (an OS error on close). */
    private class ThrowingCloseIo(
        val inner: MemoryDatagramIo,
    ) : DatagramIo by inner {
        override fun close() {
            inner.close()
            throw kotlinx.io.IOException("close: EIO (test)")
        }
    }

    @Test fun aSocketWhoseCloseThrowsDoesNotKeepTheEndpointFromFreeingTheRest() =
        runBlocking {
            val net = MemoryNetwork()
            val crypto = TrackingCrypto()
            var preferred: MemoryDatagramIo? = null
            val ep =
                EndpointLoop.bind(
                    serverAddr,
                    config(crypto) { at ->
                        if (at == preferredAddr) net.open(at).also { preferred = it } else ThrowingCloseIo(net.open(at))
                    },
                )
            ep.closeAndJoin()
            assertTrue(preferred!!.closed, "the preferred socket after the main socket's close threw")
            assertEquals(0, crypto.live, "the endpoint core's keys")
        }
}
