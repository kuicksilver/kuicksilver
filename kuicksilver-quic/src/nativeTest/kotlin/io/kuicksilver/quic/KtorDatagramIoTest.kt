// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.toByteArray
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalKuicksilverApi::class)
class KtorDatagramIoTest {
    @Test fun loopbackClientSendReceive() =
        runBlocking {
            val a = DatagramIo.open(InetSocketAddress("127.0.0.1", 0))
            val b = DatagramIo.open(InetSocketAddress("127.0.0.1", 0))
            try {
                val out = PacketBatch(1)
                out.buffer(0).copyFrom(byteArrayOf(5, 6, 7), 0, 0, 3)
                out.setLength(0, 3)
                out.setAddress(0, b.localAddress)
                assertEquals(1, a.send(out))
                val inb = PacketBatch(4)
                withTimeout(5.seconds) { while (inb.count == 0) b.receive(inb) }
                assertContentEquals(byteArrayOf(5, 6, 7), inb.buffer(0).toByteArray(inb.length(0)))
                assertEquals(a.localAddress.port, inb.address(0)!!.port)
                out.close()
                inb.close()
            } finally {
                a.close()
                b.close()
            }
        }

    /**
     * A refused bind (the port is taken) leaves nothing behind: before, every refusal leaked its `SelectorManager`, a
     * selection thread of `Dispatchers.IO` and a pipe pair, so 64 of them (an ephemeral `port = 0` server retrying taken
     * UDP twins, a client retrying) starved `Dispatchers.IO` and hung whatever ran there next, Ktor's server stop included.
     */
    @Test fun negative_refusedPortableBindReleasesItsSelector() =
        runBlocking {
            val held = DatagramIo.open(InetSocketAddress("127.0.0.1", 0), IoPreference.Portable)
            try {
                val taken = InetSocketAddress("127.0.0.1", held.localAddress.port)
                assertFailsWith<Throwable> { DatagramIo.open(taken, IoPreference.Portable).close() } // warm-up
                val before = openDescriptors()
                repeat(20) { assertFailsWith<Throwable> { DatagramIo.open(taken, IoPreference.Portable).close() } }
                // the default (accelerated, then portable) path, which the HTTP/3 server binds with
                repeat(20) { assertFailsWith<Throwable> { DatagramIo.open(taken).close() } }
                // a refused bind returns once its selector's loop has ended and closed its pipe (KtorDatagramIo.open)
                val leaked = openDescriptors() - before
                assertTrue(leaked < 10, "40 refused binds left $leaked descriptors open")
            } finally {
                held.close()
            }
        }

    /**
     * The same while every thread of `Dispatchers.Default` and `Dispatchers.IO` is held (as in a loaded run of the whole
     * suite), so no selector loop can run: a refused bind must not return with its selector's wakeup pipe still open, it
     * waits for the loop. The binds start on the test's own thread while the threads are held; a bind that returns there
     * at once (the previous code: 40 refused binds left 78 descriptors open at that point) is counted before the threads
     * are let go, one that waits is counted once they were and it returned.
     *
     * The count starts once a first round has held the same threads: Kotlin/Native's dispatchers start a thread when a task
     * finds none free and keep it, so the first round starts every thread the measured one uses. On Windows the count is
     * the process's handles (`GetProcessHandleCount`), threads and their events among them; counted from before the first
     * hold, the threads it started read as leaks whenever no earlier test had grown `Dispatchers.IO` to its 64 threads
     * (run 44453449060: "40 refused binds left 281 descriptors open", the same on main 8f76f749f, 279; the descriptors of
     * Linux and macOS count no thread).
     */
    @Test fun negative_refusedBindsReleaseTheirSelectorsUnderBusyDispatchers() =
        runBlocking {
            val held = DatagramIo.open(InetSocketAddress("127.0.0.1", 0), IoPreference.Portable)
            try {
                val taken = InetSocketAddress("127.0.0.1", held.localAddress.port)
                assertFailsWith<Throwable> { DatagramIo.open(taken, IoPreference.Portable).close() } // warm-up
                refusedBindsWhileThreadsAreHeld(taken) {} // starts the threads the measured round holds
                val before = openDescriptors()
                var leakedWhileHeld: Int? = null
                refusedBindsWhileThreadsAreHeld(taken) { leakedWhileHeld = openDescriptors() - before }
                val leaked = leakedWhileHeld ?: (openDescriptors() - before)
                assertTrue(leaked < 10, "40 refused binds left $leaked descriptors open")
            } finally {
                held.close()
            }
        }

    /**
     * Makes 40 refused binds of [taken] while more tasks than `Dispatchers.Default` and `Dispatchers.IO` have threads hold
     * every one of them, and returns once the binds and the holders ended. [whileHeld] runs while the threads are still held,
     * and only if the binds already returned by then.
     */
    private suspend fun refusedBindsWhileThreadsAreHeld(
        taken: InetSocketAddress,
        whileHeld: () -> Unit,
    ) = coroutineScope {
        val go = CompletableDeferred<Unit>()
        try {
            // more tasks than either dispatcher has threads, each holding its thread until the binds were made
            val holding =
                List(512) { i ->
                    launch(if (i % 2 == 0) Dispatchers.Default else Dispatchers.IO) { runBlocking { go.await() } }
                }
            val binds =
                async(start = CoroutineStart.UNDISPATCHED) {
                    repeat(20) { assertFailsWith<Throwable> { DatagramIo.open(taken, IoPreference.Portable).close() } }
                    repeat(20) { assertFailsWith<Throwable> { DatagramIo.open(taken).close() } }
                }
            if (binds.isCompleted) whileHeld()
            go.complete(Unit)
            binds.await()
            holding.joinAll()
        } finally {
            go.complete(Unit)
        }
    }

    /**
     * The portable socket does not use ktor-network for a specific IPv6 address (Ktor issue KTOR-10017, security, under
     * coordinated disclosure): it refuses `::1` instead of binding.
     */
    @Test fun negative_portableRefusesASpecificIpv6Address() =
        runBlocking {
            assertFailsWith<UnsupportedOperationException> { DatagramIo.open(InetSocketAddress("::1", 0), IoPreference.Portable).close() }
            Unit
        }

    /** ... and refuses to send to an IPv6 address. */
    @Test fun negative_portableRefusesIpv6Destinations() =
        runBlocking {
            val a = DatagramIo.open(InetSocketAddress("0.0.0.0", 0), IoPreference.Portable)
            val out = PacketBatch(1)
            try {
                out.buffer(0).copyFrom(byteArrayOf(1), 0, 0, 1)
                out.setLength(0, 1)
                out.setAddress(0, InetSocketAddress("2001:db8::1", 4433))
                assertFailsWith<IOException> { a.send(out) }
                assertFailsWith<IOException> { a.trySend(out) }
                Unit
            } finally {
                out.close()
                a.close()
            }
        }

    /** The IPv6 wildcard `::` is allowed (a host without IPv6 fails with its own error). */
    @Test fun portableBindsTheIpv6Wildcard() =
        runBlocking {
            val r = runCatching { DatagramIo.open(InetSocketAddress("::", 0), IoPreference.Portable).close() }
            assertTrue(r.exceptionOrNull() !is UnsupportedOperationException, "$r")
        }

    private fun openDescriptors(): Int = openHandleCount()
}
