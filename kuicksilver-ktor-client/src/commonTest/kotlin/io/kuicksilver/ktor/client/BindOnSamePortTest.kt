package io.kuicksilver.ktor.client

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.ktor.network.bindTcp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** [bindOnSamePort]: the order of the attempts, what is released, and which failures end it. */
class BindOnSamePortTest {
    /** A taken port, as the OS reports it (a type [mayBeTaken] retries). */
    private class Taken(
        port: Int,
    ) : Exception("port $port taken")

    /** Fake binders: a free port is 1000 + the call number; [fail] decides per call (side, port) what to throw. */
    private class Fakes(
        val fail: (side: Char, port: Int) -> Throwable? = { _, _ -> null },
        val failRelease: Boolean = false,
    ) {
        val calls = mutableListOf<String>()
        val released = mutableListOf<String>()
        private var next = 1000

        fun bind(side: Char): suspend (Int) -> Pair<String, Int> =
            { port ->
                calls += "$side$port"
                fail(side, port)?.let { throw it }
                val p = if (port == 0) next++ else port
                "$side@$p" to p
            }

        fun release(): suspend (String) -> Unit =
            {
                released += it
                if (failRelease) throw IllegalStateException("release of $it failed")
            }

        suspend fun run() = bindOnSamePort(bind('a'), release(), bind('b'), release())
    }

    @Test fun firstOrderSucceedsReleasingNothing() =
        runBlocking {
            val f = Fakes()
            assertEquals(Triple("a@1000", "b@1000", 1000), f.run())
            assertEquals(listOf("a0", "b1000"), f.calls)
            assertEquals(emptyList(), f.released)
        }

    @Test fun attemptsAlternateWhichSideTakesAFreePort() =
        runBlocking {
            // every twin of a free port is taken for the first four attempts
            var twins = 0
            val f = Fakes(fail = { side, port -> if (port != 0 && twins++ < 4) Taken(port) else null })
            assertEquals(Triple("a@1004", "b@1004", 1004), f.run())
            assertEquals(listOf("a0", "b1000", "b0", "a1001", "a0", "b1002", "b0", "a1003", "a0", "b1004"), f.calls)
            assertEquals(listOf("a@1000", "b@1001", "a@1002", "b@1003"), f.released)
        }

    @Test fun afterAllAttemptsTheLastFailureIsTheCause() =
        runBlocking {
            val f = Fakes(fail = { _, port -> if (port != 0) Taken(port) else null })
            val e = assertFailsWith<IllegalStateException> { f.run() }
            assertEquals(SAME_PORT_ATTEMPTS * 2, f.calls.size)
            assertEquals(SAME_PORT_ATTEMPTS, f.released.size)
            assertEquals("port ${1000 + SAME_PORT_ATTEMPTS - 1} taken", e.cause?.message)
        }

    @Test fun cancellationOfTheTwinReleasesTheHeldSideAndStops() =
        runBlocking {
            for (cancelled in listOf('a', 'b')) {
                // the first attempt's twin fails (b), so that a's cancellation comes on the second attempt, as a twin
                var twins = 0
                val f =
                    Fakes(fail = { side, port ->
                        when {
                            port == 0 -> null
                            side == cancelled -> CancellationException("cancelled")
                            twins++ == 0 -> Taken(port)
                            else -> null
                        }
                    })
                assertFailsWith<CancellationException> { f.run() }
                if (cancelled == 'b') {
                    assertEquals(listOf("a0", "b1000"), f.calls)
                    assertEquals(listOf("a@1000"), f.released)
                } else {
                    assertEquals(listOf("a0", "b1000", "b0", "a1001"), f.calls)
                    assertEquals(listOf("a@1000", "b@1001"), f.released)
                }
            }
        }

    @Test fun cancellationOfTheFreeSideStops() =
        runBlocking {
            val f = Fakes(fail = { _, _ -> CancellationException("cancelled") })
            assertFailsWith<CancellationException> { f.run() }
            assertEquals(listOf("a0"), f.calls)
            assertEquals(emptyList(), f.released)
        }

    @Test fun aFailureThatIsNoTakenPortIsThrownAtOnce() =
        runBlocking {
            val refused = IllegalArgumentException("refused configuration")
            val f = Fakes(fail = { side, _ -> if (side == 'b') refused else null })
            assertSame(refused, assertFailsWith<IllegalArgumentException> { f.run() })
            assertEquals(listOf("a0", "b1000"), f.calls)
            assertEquals(listOf("a@1000"), f.released)
        }

    @Test fun aFailingReleaseDoesNotHideTheBindFailure() =
        runBlocking {
            val f = Fakes(fail = { _, port -> if (port != 0) Taken(port) else null }, failRelease = true)
            val e = assertFailsWith<IllegalStateException> { f.run() }
            val bind = assertIs<Taken>(e.cause)
            assertEquals(listOf("release of b@1019 failed"), bind.suppressedExceptions.map { it.message })
        }

    /**
     * Real sockets: the UDP-first attempt finds its TCP twin taken (by a listener of ours) and the second attempt binds TCP
     * on a free port and UDP on that number ([udpOn] honours the port it is given). Where our listener cannot take the
     * twin (already taken by another, as on the Windows CI), only the pair on one port is asserted.
     */
    @Test fun aTakenTwinGoesToTheOtherOrder() =
        clientTest {
            val selector = SelectorManager(Dispatchers.IO)
            var blocker: io.ktor.network.sockets.ServerSocket? = null
            try {
                val calls = mutableListOf<String>()
                val (u, t, port) =
                    bindOnSamePort(
                        first = { p ->
                            calls += "udp$p"
                            udpOn(selector, p)
                        },
                        releaseFirst = { it.close() },
                        second = { p ->
                            calls += "tcp$p"
                            if (calls.size == 2) {
                                // a twin someone else already holds leaves no blocker; a cancellation still ends the test
                                blocker =
                                    runCatching { bindTcp(selector, "127.0.0.1", p) }
                                        .onFailure { if (it is CancellationException) throw it }
                                        .getOrNull()
                            }
                            tcpOn(selector, p)
                        },
                        releaseSecond = { it.close() },
                    )
                try {
                    assertTrue(port != 0)
                    assertEquals(port, (u.localAddress as InetSocketAddress).port)
                    assertEquals(port, (t.localAddress as InetSocketAddress).port)
                    if (blocker != null) {
                        // the second attempt went TCP-first (later ones may follow where its UDP twin is taken too)
                        assertEquals(listOf("udp0", "tcp0"), listOf(calls[0], calls[2]), "$calls")
                        assertEquals("udp$port", calls.last())
                    }
                } finally {
                    u.close()
                    t.close()
                }
            } finally {
                blocker?.close()
                selector.close()
            }
        }

    /** A taken port fails [tcpOn] and [testServer] with a failure [mayBeTaken] retries. */
    @Test fun aTakenPortIsRetried() =
        clientTest {
            val selector = SelectorManager(Dispatchers.IO)
            val taken = bindTcp(selector, "127.0.0.1", 0)
            try {
                val port = (taken.localAddress as InetSocketAddress).port
                val tcp = runCatching { tcpOn(selector, port) }
                tcp.getOrNull()?.first?.close()
                val tcpFailure = tcp.exceptionOrNull()
                assertTrue(tcpFailure != null && mayBeTaken(tcpFailure), "tcpOn on a taken port: $tcp")
                val server = runCatching { testServer(plain = true, port = port) { routing { get("/") { call.respondText("") } } } }
                server.getOrNull()?.first?.let { runCatching { it.stop(0, 0) } }
                val serverFailure = server.exceptionOrNull()
                assertTrue(serverFailure != null && mayBeTaken(serverFailure), "testServer on a taken port: $server")
            } finally {
                taken.close()
                selector.close()
            }
        }
}
