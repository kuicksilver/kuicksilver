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
import kotlinx.coroutines.delay
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
     * The measured round is the second. Kotlin/Native's dispatchers start a thread when a task finds none free and keep it,
     * so the first round starts every thread the second holds. On Windows the count is the process's handles
     * (`GetProcessHandleCount`), threads and their events among them; counted from before the first hold, the threads it
     * started read as leaks whenever no earlier test had grown `Dispatchers.IO` to its 64 threads (run 44453449060: "40
     * refused binds left 281 descriptors open", the same on main 8f76f749f, 279). The baseline is taken once the count has
     * settled after the first round: a selector loop that was still to run then (the regression this test is for) would
     * close its pipe during the second round and hide one of that round's. Linux and macOS count descriptors only, no
     * thread: there the second round's count is held against the one from before the first round too.
     */
    @Test fun negative_refusedBindsReleaseTheirSelectorsUnderBusyDispatchers() =
        runBlocking {
            val held = DatagramIo.open(InetSocketAddress("127.0.0.1", 0), IoPreference.Portable)
            try {
                val taken = InetSocketAddress("127.0.0.1", held.localAddress.port)
                assertFailsWith<Throwable> { DatagramIo.open(taken, IoPreference.Portable).close() } // warm-up
                val initial = settledDescriptors()
                refusedBindsWhileThreadsAreHeld(taken) {} // starts the threads the measured round holds
                val before = settledDescriptors()
                var whileHeld: Int? = null
                refusedBindsWhileThreadsAreHeld(taken) { whileHeld = openDescriptors() }
                val after = whileHeld ?: settledDescriptors()
                assertTrue(after - before < 10, "40 refused binds left ${after - before} descriptors open")
                if (!handlesCountThreads) {
                    assertTrue(after - initial < 10, "80 refused binds left ${after - initial} descriptors open")
                }
            } finally {
                held.close()
            }
        }

    /**
     * The count once it has stopped moving: read every 50 ms until five reads in a row agree, at most for 10 s (then the
     * last read). The selector loops of binds that already returned close their pipes when a thread takes them, and
     * nothing signals that; the count is what is measured.
     */
    private suspend fun settledDescriptors(): Int {
        var last = openDescriptors()
        var same = 0
        val start =
            kotlin.time.TimeSource.Monotonic
                .markNow()
        while (same < 5 && start.elapsedNow() < 10.seconds) {
            delay(50)
            val n = openDescriptors()
            if (n == last) same++ else same = 0
            last = n
        }
        return last
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

    /** Whether [openDescriptors] counts every handle of the process, threads among them (Windows), not descriptors alone. */
    @OptIn(kotlin.experimental.ExperimentalNativeApi::class)
    private val handlesCountThreads: Boolean = kotlin.native.Platform.osFamily == kotlin.native.OsFamily.WINDOWS
}
