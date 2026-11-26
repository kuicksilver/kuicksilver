// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslException
import io.kuicksilver.native.toByteArray
import io.kuicksilver.tls.KslUdpSocket
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
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalKuicksilverApi::class)
class KtorDatagramIoTest {
    /** No DF, no QUIC (RFC 9000 section 14): the portable socket, which cannot set DF, is refused with a typed error. */
    @Test fun negative_thePortableSocketIsRefusedWithoutDf() =
        runBlocking {
            val e =
                assertFailsWith<QuicException.DontFragmentUnavailable> {
                    DatagramIo.open(InetSocketAddress("127.0.0.1", 0), IoPreference.Portable).close()
                }
            assertEquals(null, e.family)
        }

    /**
     * A port in use is a refused bind, as on the JVM, not a lack of DF: the accelerated socket's bind failure is what the
     * caller sees (an `IOException`), so the Ktor server's ephemeral TCP + UDP pair tries another port instead of serving
     * HTTP/1.1 alone. Red before: DontFragmentUnavailable from the portable socket the refusal fell back to.
     */
    @Test fun negative_aTakenPortIsARefusedBindNotALackOfDf() =
        runBlocking {
            val held = DatagramIo.open(InetSocketAddress("127.0.0.1", 0))
            try {
                val e = assertFailsWith<IOException> { DatagramIo.open(InetSocketAddress("127.0.0.1", held.localAddress.port)).close() }
                assertTrue(e !is QuicException.DontFragmentUnavailable, "a refused bind, not no DF: $e")
            } finally {
                held.close()
            }
        }

    /**
     * A bind address that does not resolve is an address error (an `IOException` naming it), as the portable socket's own
     * resolution fails elsewhere, not a lack of DF. The resolver is replaced: what a name resolves to depends on the
     * host's DNS (a fake-IP resolver answers every name). Red before: DontFragmentUnavailable, refused never called.
     */
    @Test fun negative_anUnresolvableBindAddressIsAnAddressErrorNotALackOfDf() =
        runBlocking {
            val real = KslDatagramIo.addressResolver
            KslDatagramIo.addressResolver = { null }
            try {
                val seen = ArrayList<Throwable>()
                assertNull(KslDatagramIo.open(InetSocketAddress("unresolvable.test", 0), refused = { seen += it }))
                assertTrue(seen.singleOrNull() is IOException, "refused gets the address error: $seen")
                val e = assertFailsWith<IOException> { DatagramIo.open(InetSocketAddress("unresolvable.test", 0)).close() }
                assertTrue(e !is QuicException.DontFragmentUnavailable, "an address error, not no DF: $e")
                assertTrue("unresolvable.test" in (e.message ?: ""), "${e.message}")
            } finally {
                KslDatagramIo.addressResolver = real
            }
        }

    /**
     * What Ktor's `resolveAddress()` really does on Kotlin/Native for a name that does not resolve: it throws, a
     * `PosixException` built from `errno` after `getaddrinfo` failed (`getaddrinfo` reports through its return code, so that
     * errno is stale: the iOS simulator said ENOTCONN for `no-such-host.invalid`). That is the address error too, an
     * `IOException` naming the address, for the client socket and for the server's bind, not the stale errno. Red before:
     * the PosixException escaped `KslDatagramIo.open` as it was.
     */
    @Test fun negative_aBindAddressWhoseResolverThrowsIsAnAddressError() =
        runBlocking {
            val real = KslDatagramIo.addressResolver
            val stale =
                io.ktor.utils.io.errors.PosixException
                    .forErrno(platform.posix.ENOTCONN)
            KslDatagramIo.addressResolver = { throw stale }
            try {
                val seen = ArrayList<Throwable>()
                assertNull(KslDatagramIo.open(InetSocketAddress("unresolvable.test", 0), refused = { seen += it }))
                val r = seen.singleOrNull()
                assertTrue(r is IOException && r !is QuicException, "refused gets the address error: $seen")
                assertTrue("unresolvable.test" in (r.message ?: ""), "${r.message}")
                assertSame(stale, r.cause, "the resolver's failure kept as the cause")
                val e = assertFailsWith<IOException> { DatagramIo.open(InetSocketAddress("unresolvable.test", 0)).close() }
                assertTrue(e !is QuicException, "an address error, not no DF: $e")
                val server =
                    quicEndpointConfig {
                        server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                        runtime { crypto = NullCryptoProvider }
                        observability { logger = KuicksilverLogger.None }
                    }
                val s =
                    runCatching { QuicEndpoint.bind(InetSocketAddress("unresolvable.test", 0), server).closeAndJoin() }
                        .exceptionOrNull()
                assertTrue(s is IOException && s !is QuicException, "the server's bind: the address error, got $s")
                assertTrue("unresolvable.test" in (s.message ?: ""), "${s.message}")
            } finally {
                KslDatagramIo.addressResolver = real
            }
        }

    /**
     * A connect target whose lookup throws, as Ktor's `resolveAddress()` does on Kotlin/Native (a PosixException with a stale
     * errno): `withLiteralHost` keeps the name as its KDoc says, and connect fails at once with
     * [QuicException.ConnectionLost.NoViablePath] caused by an `IOException` naming the target, as on the JVM
     * (UnresolvableTargetJvmTest). Red before: the PosixException ENOTCONN escaped both.
     */
    @Test fun negative_aConnectTargetWhoseLookupThrowsIsNoViablePath() =
        runBlocking {
            val real = addressLookup
            val stale =
                io.ktor.utils.io.errors.PosixException
                    .forErrno(platform.posix.ENOTCONN)
            // only the target's lookup throws: the bind address goes through the same lookup (KslDatagramIo.addressResolver)
            addressLookup = { if (it.hostname == "unresolvable.test") throw stale else real(it) }
            try {
                val name = InetSocketAddress("unresolvable.test", 443)
                assertSame(name, name.withLiteralHost())
                assertEquals("unresolvable.test", name.withLiteralHost(444).hostname)
                assertNull(name.resolveAddressOrNull())
                val client =
                    QuicEndpoint.bind(
                        InetSocketAddress("127.0.0.1", 0),
                        quicEndpointConfig { runtime { crypto = NullCryptoProvider } },
                    )
                try {
                    val e =
                        assertFailsWith<QuicException.ConnectionLost.NoViablePath> {
                            withTimeout(5.seconds) { client.connect(name, QuicClientConfig.Builder(CoreFixtures.client()).build()) }
                        }
                    val cause = e.cause
                    assertTrue(cause is IOException, "the address error as the cause: $cause")
                    assertTrue("unresolvable.test" in (cause.message ?: ""), "${cause.message}")
                    assertSame(stale, cause.cause, "the resolver's failure kept as the cause")
                } finally {
                    client.closeAndJoin()
                }
            } finally {
                addressLookup = real
            }
        }

    /**
     * A closing endpoint answers [QuicException.EndpointClosing] whatever the target, a name that could not be resolved
     * included. Red before: NoViablePath, the target checked before the endpoint.
     */
    @Test fun negative_aClosingEndpointIsEndpointClosingEvenForAnUnresolvableTarget() =
        runBlocking {
            val real = addressLookup
            addressLookup = {
                if (it.hostname ==
                    "unresolvable.test"
                ) {
                    throw io.ktor.utils.io.errors.PosixException
                        .forErrno(platform.posix.ENOTCONN)
                } else {
                    real(it)
                }
            }
            try {
                val client =
                    QuicEndpoint.bind(
                        InetSocketAddress("127.0.0.1", 0),
                        quicEndpointConfig { runtime { crypto = NullCryptoProvider } },
                    )
                client.close()
                assertFailsWith<QuicException.EndpointClosing> {
                    client.connect(InetSocketAddress("unresolvable.test", 443), QuicClientConfig.Builder(CoreFixtures.client()).build())
                }
                client.closeAndJoin()
            } finally {
                addressLookup = real
            }
        }

    /**
     * Any other refusal of the accelerated socket (a `KslException`: limits, a sandbox) reaches the caller through
     * `refused` and ends in a lack of DF that is not lasting (the socket may open next time), with the refusal attached as
     * suppressed; a refused bind (an `IOException`) is thrown as it is.
     */
    @Test fun negative_aRefusalOtherThanABindIsATransientLackOfDfThatKeepsItsReason() =
        runBlocking {
            val ksl = KslException.Internal(0xff shl 16, 0, "injected: no socket")
            val bind = IOException("injected: UDP bind refused")
            for (injected in listOf<Throwable>(ksl, bind)) {
                val seen = ArrayList<Throwable>()
                val e =
                    withOpener({ _, _, failed ->
                        failed(injected)
                        null
                    }) {
                        assertNull(KslDatagramIo.open(InetSocketAddress("127.0.0.1", 0), refused = { seen += it }))
                        assertEquals(listOf(injected), seen, "refused gets the refusal")
                        assertFails { DatagramIo.open(InetSocketAddress("127.0.0.1", 0)).close() }
                    }
                if (injected === bind) {
                    assertSame(bind, e)
                } else {
                    assertTrue(e is QuicException.DontFragmentUnavailable, "$e")
                    assertFalse(e.permanent)
                    assertTrue(e.suppressedExceptions.any { it === ksl }, "the reason kept: ${e.suppressedExceptions}")
                }
            }
        }

    /** A process whose loopback probe failed: the lack of DF lasts for the process (a CONNECT-UDP proxy may remember it). */
    @Test fun negative_anUnsupportedAcceleratedSocketIsALastingLackOfDf() =
        runBlocking {
            val real = KslDatagramIo.unsupportedReason
            KslDatagramIo.unsupportedReason = { "injected: probe refused" }
            try {
                val e =
                    assertFailsWith<QuicException.DontFragmentUnavailable> {
                        DatagramIo.open(InetSocketAddress("127.0.0.1", 0)).close()
                    }
                assertTrue(e.permanent)
                assertTrue(e.suppressedExceptions.any { "injected: probe refused" in (it.message ?: "") }, "${e.suppressedExceptions}")
            } finally {
                KslDatagramIo.unsupportedReason = real
            }
        }

    /** An accelerated socket the system gave no DF: refused, and the lack lasts (the system refuses DF there). */
    @Test fun negative_anAcceleratedSocketGrantedNoDfIsALastingLackOfDf() =
        runBlocking {
            val e =
                withOpener({ a, f, failed -> KslUdpSocket.openOrNull(a, f and KslUdpSocket.DF.inv(), failed) }) {
                    assertFailsWith<QuicException.DontFragmentUnavailable> {
                        DatagramIo.open(InetSocketAddress("127.0.0.1", 0)).close()
                    }
                }
            assertTrue(e.permanent)
            assertTrue(e.suppressedExceptions.any { "no Don't Fragment" in (it.message ?: "") }, "${e.suppressedExceptions}")
        }

    private inline fun <T> withOpener(
        noinline opener: (ByteArray, Int, (Throwable) -> Unit) -> KslUdpSocket?,
        block: () -> T,
    ): T {
        val real = KslDatagramIo.socketOpener
        KslDatagramIo.socketOpener = opener
        try {
            return block()
        } finally {
            KslDatagramIo.socketOpener = real
        }
    }

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
            val held = KtorDatagramIo.open(InetSocketAddress("127.0.0.1", 0))
            try {
                val taken = InetSocketAddress("127.0.0.1", held.localAddress.port)
                assertFailsWith<Throwable> { KtorDatagramIo.open(taken).close() } // warm-up
                val diag = HandleDiagnostics("refused binds")
                val before = openDescriptors()
                diag.mark("before")
                repeat(20) { assertFailsWith<Throwable> { KtorDatagramIo.open(taken).close() } }
                assertEquals(0, refusedSelectorsRunning(), "a refused portable bind returned before its selector ended")
                diag.mark("after 20 portable")
                // the default (accelerated, then portable) path, which the HTTP/3 server binds with
                repeat(20) { assertFailsWith<Throwable> { DatagramIo.open(taken).close() } }
                assertEquals(0, refusedSelectorsRunning(), "a refused bind returned before its selector ended")
                diag.mark("after 20 default")
                // a refused bind returns once its selector's loop has ended and closed its pipe (KtorDatagramIo.open)
                val leaked = openDescriptors() - before
                diag.report(leaked < 10) { "40 refused binds left $leaked descriptors open" }
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
     *
     * On Windows the 2026-11-19 VM run left about one Event handle per refused bind of the measured round (54 and 37 for 40,
     * there 5 s later as well), no thread, while every selector of those binds had ended (`refusedSelectorsRunning`). Three
     * measured rounds tell a cache from a leak: round A with binds, the control C holding the threads without binds, round B
     * with binds again, each counted after a GC. A cache of the runtime fills in the first rounds and stays, so round B adds
     * nothing; a leak of the binds adds as much in B as in A, and only B decides on Windows. The next run (7c92d0695) showed a
     * cache: Event +55 in round A, +6 in the control, +2 in round B, threads and semaphores flat, the same before and after
     * the GC. The first busy round of refused binds fills a one-time cache of about 55 events, which then stays.
     */
    @Test fun negative_refusedBindsReleaseTheirSelectorsUnderBusyDispatchers() =
        runBlocking {
            val held = KtorDatagramIo.open(InetSocketAddress("127.0.0.1", 0))
            try {
                val taken = InetSocketAddress("127.0.0.1", held.localAddress.port)
                assertFailsWith<Throwable> { KtorDatagramIo.open(taken).close() } // warm-up
                val diag = HandleDiagnostics("refused binds under busy dispatchers")
                val initial = settledDescriptors()
                diag.mark("initial")
                refusedBindsWhileThreadsAreHeld(taken) {} // starts the threads the measured rounds hold
                val before = settledDescriptors(collect = true)
                diag.mark("before (after the first round, settled, after a GC)")
                val a = measuredRound(taken, binds = true, diag, "round A, 40 binds")
                val c = measuredRound(taken, binds = false, diag, "round C, no binds (the control)")
                val b = measuredRound(taken, binds = true, diag, "round B, 40 binds")
                val rounds = "round A ${a - before}, the control ${c - a}, round B ${b - c}"
                if (handlesCountThreads) {
                    // every handle of the process counts: a cache of the runtime fills in the first rounds and stays (round
                    // B adds nothing), a leak of the binds grows with every round of binds (round B adds as much as round A)
                    diag.report(b - c < 10) { "40 refused binds left ${b - c} handles open in the last round ($rounds)" }
                } else {
                    diag.report(a - before < 10 && b - c < 10) { "40 refused binds left descriptors open: $rounds" }
                    assertTrue(b - initial < 10, "120 refused binds left ${b - initial} descriptors open")
                }
            } finally {
                held.close()
            }
        }

    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private fun refusedSelectorsRunning(): Int = KtorDatagramIo.refusedSelectorsRunning.load()

    /**
     * One measured round: the threads held, 40 refused binds made (none with [binds] false: the control, which holds the
     * threads alone), every selector of them ended by the time the binds returned. Returns the count while the threads were
     * still held when the binds returned by then (a bind that returned without waiting for its loop shows here), else the
     * settled count after a GC (what a finalizer still holds is not a leak of the binds).
     */
    private suspend fun measuredRound(
        taken: InetSocketAddress,
        binds: Boolean,
        diag: HandleDiagnostics,
        label: String,
    ): Int {
        var whileHeld: Int? = null
        refusedBindsWhileThreadsAreHeld(taken, binds) {
            if (!binds) return@refusedBindsWhileThreadsAreHeld // the control is measured as the rounds of binds are
            whileHeld = openDescriptors()
            diag.mark("$label, while held (the binds returned before the threads were let go)")
            // a bind returned while no selector loop could run: its own must have ended all the same
            assertEquals(0, refusedSelectorsRunning(), "a refused bind returned before its selector ended")
        }
        assertEquals(0, refusedSelectorsRunning(), "a refused bind returned before its selector ended")
        whileHeld?.let { return it }
        diag.mark("$label, settled")
        val n = settledDescriptors(collect = true)
        diag.mark("$label, settled after a GC")
        return n
    }

    /**
     * What the handle count was made of at each [mark], by kind ([handleBreakdown]): on Windows, where the count is every
     * handle of the process, a failure says which object types grew (threads and their events, or the sockets and events of a
     * selector) and what is left after a further 5 s.
     */
    private class HandleDiagnostics(
        private val what: String,
    ) {
        private val marks = ArrayList<Pair<String, Map<String, Int>>>()

        fun mark(label: String) {
            marks += label to handleBreakdown()
        }

        suspend fun report(
            ok: Boolean,
            message: () -> String,
        ) {
            if (!ok) {
                delay(5_000) // a late end: what settles only after the binds' own wait is not theirs
                mark("5 s later")
            }
            val text = describe()
            assertTrue(ok, "${message()}\n$text")
        }

        private fun describe(): String {
            val first = marks.first().second
            return marks.joinToString("\n") { (label, m) ->
                val kinds = (first.keys + m.keys).sorted()
                val change =
                    kinds.mapNotNull { k ->
                        val d = (m[k] ?: 0) - (first[k] ?: 0)
                        if (d != 0) "$k ${if (d > 0) "+" else ""}$d" else null
                    }
                "  $label: total ${m.values.sum()}; vs ${marks.first().first}: ${change.joinToString().ifEmpty { "no change" }}"
            }
        }
    }

    /**
     * The count once it has stopped moving: read every 50 ms until five reads in a row agree, at most for 10 s (then the
     * last read); with [collect], after a full GC, so what only a finalizer still holds is gone. The selector loops of binds that already returned close their pipes when a thread takes them, and
     * nothing signals that; the count is what is measured.
     */
    @OptIn(kotlin.native.runtime.NativeRuntimeApi::class)
    private suspend fun settledDescriptors(collect: Boolean = false): Int {
        if (collect) {
            kotlin.native.runtime.GC
                .collect()
        }
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
     * Makes 40 refused binds of [taken] (none without [binds]) while more tasks than `Dispatchers.Default` and
     * `Dispatchers.IO` have threads hold every one of them, and returns once the binds and the holders ended. [whileHeld]
     * runs while the threads are still held, and only if the binds already returned by then.
     */
    private suspend fun refusedBindsWhileThreadsAreHeld(
        taken: InetSocketAddress,
        binds: Boolean = true,
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
                    if (!binds) return@async
                    repeat(20) { assertFailsWith<Throwable> { KtorDatagramIo.open(taken).close() } }
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
            assertFailsWith<UnsupportedOperationException> { KtorDatagramIo.open(InetSocketAddress("::1", 0)).close() }
            Unit
        }

    /** ... and refuses to send to an IPv6 address. */
    @Test fun negative_portableRefusesIpv6Destinations() =
        runBlocking {
            val a = KtorDatagramIo.open(InetSocketAddress("0.0.0.0", 0))
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
            val r = runCatching { KtorDatagramIo.open(InetSocketAddress("::", 0)).close() }
            assertTrue(r.exceptionOrNull() !is UnsupportedOperationException, "$r")
        }

    private fun openDescriptors(): Int = openHandleCount()
}

/** Whether [openHandleCount] counts every handle of the process, threads among them (Windows), not descriptors alone. */
@OptIn(kotlin.experimental.ExperimentalNativeApi::class)
private val handlesCountThreads: Boolean = kotlin.native.Platform.osFamily == kotlin.native.OsFamily.WINDOWS
