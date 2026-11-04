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
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

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
            val alloc = CountingAllocator()
            val ios = listOf(net.open(serverAddr), net.open(otherAddr))
            val preferred = listOf(listOf<DatagramIo>(net.open(preferredAddr)), emptyList())
            assertFailsWith<IllegalStateException> {
                LoopGroup.create(config(crypto, loops = 2), ios, preferred, allocate = alloc::allocate)
            }
            assertEquals(49, alloc.made.size, "loop 0's batches")
            assertTrue(alloc.allClosed, "loop 0's batches (discardUnstarted)")
            assertTrue(ios.all { it.closed }, "the loops' sockets")
            assertTrue((preferred[0][0] as MemoryDatagramIo).closed, "the preferred socket")
            assertEquals(0, crypto.live, "loop 0's reset key and its reference to the group's token keys")
        }

    @Test fun aGroupWhoseTokenKeysCannotBeMadeClosesEverySocket() =
        runBlocking {
            val net = MemoryNetwork()
            val crypto = TrackingCrypto(tokenKeys = 0) // the group's Retry key is refused before any loop exists
            val ios = listOf(net.open(serverAddr), net.open(otherAddr))
            val preferred = listOf(listOf<DatagramIo>(net.open(preferredAddr)), emptyList())
            assertFailsWith<IllegalStateException> { LoopGroup.create(config(crypto, loops = 2), ios, preferred) }
            assertTrue(ios.all { it.closed }, "the loops' sockets")
            assertTrue((preferred[0][0] as MemoryDatagramIo).closed, "the preferred socket")
            assertEquals(0, crypto.live)
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

    /** Hands out buffers, remembers them, and fails the [failAt]-th allocation (1-based; 0 never). */
    private class CountingAllocator(
        val failAt: Int = 0,
    ) {
        val made = ArrayList<io.kuicksilver.native.PacketBuffer>()
        private var n = 0

        fun allocate(size: Int): io.kuicksilver.native.PacketBuffer {
            if (++n == failAt) throw IllegalStateException("out of native memory (test)")
            return io.kuicksilver.native.PacketBuffer
                .allocate(size)
                .also { made += it }
        }

        val allClosed: Boolean
            get() = made.all { runCatching { it[0] }.exceptionOrNull() is IllegalStateException }
    }

    @Test fun aLoopWhoseLastBatchCannotBeAllocatedFreesTheOthers() =
        runBlocking {
            val net = MemoryNetwork()
            val crypto = TrackingCrypto()
            val alloc = CountingAllocator(failAt = 16 + 32 + 1) // the single-slot batch, after both others
            val opened = ArrayList<MemoryDatagramIo>()
            assertFailsWith<IllegalStateException> {
                EndpointLoop.bind(serverAddr, config(crypto) { at -> net.open(at).also { opened += it } }, alloc::allocate)
            }
            assertEquals(48, alloc.made.size)
            assertTrue(alloc.allClosed, "the in and out batches")
            assertTrue(opened.all { it.closed })
            assertEquals(0, crypto.live, "the endpoint core")
        }

    @Test fun aLoopThatFailsToStartIsClosedWhole() =
        runBlocking {
            val net = MemoryNetwork()
            val crypto = TrackingCrypto()
            val alloc = CountingAllocator()
            val opened = ArrayList<MemoryDatagramIo>()
            assertFailsWith<IllegalStateException> {
                EndpointLoop.bind(
                    serverAddr,
                    config(crypto) { at -> net.open(at).also { opened += it } },
                    alloc::allocate,
                    beforeStartForTest = { throw IllegalStateException("start refused (test)") },
                )
            }
            assertEquals(49, alloc.made.size)
            assertTrue(alloc.allClosed, "every batch")
            assertTrue(opened.size == 2 && opened.all { it.closed }, "the main and the preferred socket")
            assertEquals(0, crypto.live, "the endpoint core")
        }

    @Test fun aClosedLoopHasStoppedItsTimerAndReceiversBeforeItFreesTheBatches() =
        runBlocking {
            val net = MemoryNetwork()
            val alloc = CountingAllocator()
            val ep = EndpointLoop.bind(serverAddr, config(TrackingCrypto()) { at -> net.open(at) }, alloc::allocate) as EndpointLoop
            ep.closeAndJoin()
            assertTrue(ep.writersEndedForTest, "receive, timer and preferred receivers joined by the close job")
            assertTrue(alloc.allClosed)
        }

    /**
     * A flush that holds the flush lock (here suspended as if in a send) when the close job is about to free the batches:
     * the close waits for it, and a flush after the release does nothing.
     */
    @Test fun aFlushInFlightKeepsTheBatchesUntilItEnds() =
        runBlocking {
            val net = MemoryNetwork()
            val alloc = CountingAllocator()
            val ep = EndpointLoop.bind(serverAddr, config(TrackingCrypto()) { at -> net.open(at) }, alloc::allocate) as EndpointLoop
            val held = kotlinx.coroutines.CompletableDeferred<Unit>()
            val freedWhileHeld = kotlinx.coroutines.CompletableDeferred<Boolean>()
            ep.beforeReleaseForTest = {
                ep.scope.launch {
                    ep.withFlushLockForTest {
                        held.complete(Unit)
                        try {
                            kotlinx.coroutines.yield() // the close job runs now: it must wait for this lock, not free the batches
                        } finally {
                            // also when the close job, not waiting, freed everything and cancelled this coroutine
                            freedWhileHeld.complete(alloc.made.any { runCatching { it[0] }.isFailure })
                        }
                    }
                }
                held.await()
            }
            kotlinx.coroutines.withTimeout(20.seconds) { ep.closeAndJoin() }
            assertEquals(
                false,
                kotlinx.coroutines.withTimeout(20.seconds) { freedWhileHeld.await() },
                "no batch freed while a flush held the lock",
            )
            assertTrue(alloc.allClosed)
            kotlinx.coroutines.withContext(ep.dispatcher) { ep.flush() } // after the release: a no-op, no freed buffer touched
        }
}
