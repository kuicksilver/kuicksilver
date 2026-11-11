// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.KslDatagramIo
import io.kuicksilver.quic.endpoint.ByteRoute
import io.kuicksilver.quic.endpoint.SipKey
import io.kuicksilver.tls.KslUdpSocket
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicInt
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** Where the receiver of a shared accelerated socket ([SocketDispatcher]) blocks. */
class SocketDispatcherThreadTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * An idle shared socket gives its blocking thread back between its receive slices: with a one-thread view of
     * `Dispatchers.IO` as the blocking dispatcher, other work on it still runs. The receiver held its thread for the
     * socket's lifetime, so 64 such sockets left `Dispatchers.IO` without a thread for anyone else.
     */
    @Test fun anIdleSharedSocketLeavesItsBlockingThreadToOthers(): Unit =
        runBlocking {
            val io = KslDatagramIo.open(InetSocketAddress("127.0.0.1", 0)) ?: return@runBlocking // no accelerated socket here
            val oneThread = Dispatchers.IO.limitedParallelism(1)
            val d = SocketDispatcher(io, listOf(io.sender()), 8, SipKey(1, 2), blocking = oneThread)
            d.start(ByteRoute(0, 8))
            try {
                delay(300) // the receiver is in its slices by now
                // a slice is 100 ms: the other work runs within a few of them. Awaited from outside the one thread, so a receiver
                // that holds it makes this fail instead of hang
                val other = async(Dispatchers.Default) { withContext(oneThread) { "ran" } }
                assertEquals("ran", withTimeoutOrNull(2.seconds) { other.await() })
            } finally {
                d.inboxes.forEach { it.close() }
                withTimeout(5.seconds) { d.receiverForTest?.join() }
            }
        }

    /**
     * A busy shared socket (datagrams in every slice, so no slice comes back empty) still gives its blocking thread back
     * every [SocketDispatcher.BUSY_ROUNDS] rounds: other work on the one-thread view runs while the flood goes on.
     */
    @Test fun aBusySharedSocketStillLeavesItsBlockingThreadToOthers(): Unit =
        runBlocking {
            val io = KslDatagramIo.open(InetSocketAddress("127.0.0.1", 0)) ?: return@runBlocking // no accelerated socket here
            val oneThread = Dispatchers.IO.limitedParallelism(1)
            val d = SocketDispatcher(io, listOf(io.sender()), 8, SipKey(1, 2), blocking = oneThread)
            d.start(ByteRoute(0, 8))
            val sender = KslUdpSocket.open(KslUdpSocket.encodeAddress(byteArrayOf(127, 0, 0, 1), 0), 0)
            val to = KslUdpSocket.encodeAddress(byteArrayOf(127, 0, 0, 1), io.localAddress.port)
            val flooding = AtomicInt(1)
            val flood =
                launch(Dispatchers.Default) {
                    PacketBuffer.allocate(100).use { buf ->
                        while (flooding.load() == 1) sender.send(arrayOf(buf), intArrayOf(100), to, ByteArray(1), 1)
                    }
                }
            try {
                delay(300) // the receiver is busy with the flood by now
                val other = async(Dispatchers.Default) { withContext(oneThread) { flooding.load() } }
                // 1: it ran while the flood still went on, not only once it stopped
                assertEquals(1, withTimeoutOrNull(2.seconds) { other.await() })
                assertTrue(d.dropped > 0, "the flood reached the receiver (nobody empties the ring: the surplus is dropped)")
            } finally {
                flooding.store(0)
                flood.join()
                sender.close()
                d.inboxes.forEach { it.close() }
                withTimeout(5.seconds) { d.receiverForTest?.join() }
            }
        }
}
