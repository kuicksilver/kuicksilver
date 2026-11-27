// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
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
     * on a free port and UDP on that number ([udpOn] honours the port it is given). That UDP twin may be taken or refused
     * too (another socket of the run, or a reserved port range: Windows excludes ranges for TCP and UDP apart), as on the
     * Windows CI of 2026-11-27, so the pair may come from any later attempt, of either order ([pairPastTakenTwins]).
     */
    @Test fun aTakenTwinGoesToTheOtherOrder() = clientTest { pairPastTakenTwins(1) }

    /** Real sockets: the twins of both orders taken (by sockets of ours), the third attempt, UDP-first again, pairs. */
    @Test fun aTakenTwinOfTheOtherOrderGoesBackToTheFirst() = clientTest { pairPastTakenTwins(2) }

    /**
     * [bindOnSamePort] on real sockets, with the twins of its first [taken] attempts held by sockets of ours just before
     * the attempt binds them. Asserted: the pair on one port; the attempts alternate, UDP-first first, each a free port then
     * its twin on that number ([attempts]); the last one bound its twin on the port returned; an attempt whose twin we held
     * did not pair. Where we cannot take a twin (already taken by another, as on the Windows CI) nothing is said about that
     * attempt: the other holder may let it go before the twin's bind.
     */
    private suspend fun pairPastTakenTwins(taken: Int) {
        val selector = SelectorManager(Dispatchers.IO)
        val blockers = mutableListOf<Pair<Int, () -> Unit>>() // attempt index, close
        try {
            val calls = mutableListOf<String>()
            var attempt = -1

            suspend fun record(
                kind: String,
                p: Int,
            ) {
                calls += "$kind$p"
                if (p == 0) {
                    attempt++
                } else if (attempt < taken) {
                    // a twin someone else already holds leaves no blocker; a cancellation still ends the test
                    runCatching {
                        if (kind == "tcp") {
                            bindTcp(selector, "127.0.0.1", p).let { s -> { s.close() } }
                        } else {
                            udpOn(selector, p).first.let { s -> { s.close() } }
                        }
                    }.onFailure { if (it is CancellationException) throw it }
                        .onSuccess { blockers += attempt to it }
                }
            }
            val (u, t, port) =
                bindOnSamePort(
                    first = { p ->
                        record("udp", p)
                        udpOn(selector, p)
                    },
                    releaseFirst = { it.close() },
                    second = { p ->
                        record("tcp", p)
                        tcpOn(selector, p)
                    },
                    releaseSecond = { it.close() },
                )
            try {
                assertTrue(port != 0)
                assertEquals(port, (u.localAddress as InetSocketAddress).port)
                assertEquals(port, (t.localAddress as InetSocketAddress).port)
                val attempts = attempts(calls)
                attempts.forEachIndexed { i, (free, _) ->
                    assertEquals(if (i % 2 == 0) "udp0" else "tcp0", free, "attempt $i of $calls")
                }
                val twin = if (attempts.lastIndex % 2 == 0) "tcp$port" else "udp$port"
                assertEquals(twin, attempts.last().second, "the pairing attempt has no twin, or not on the port: $calls")
                for ((i, _) in blockers) assertTrue(i < attempts.lastIndex, "attempt $i paired on a twin we held: $calls")
            } finally {
                u.close()
                t.close()
            }
        } finally {
            blockers.forEach { (_, close) -> close() }
            selector.close()
        }
    }

    /**
     * The [calls] of [bindOnSamePort] as its attempts: a bind of a free port ("udp0", "tcp0"), then the bind of its twin on
     * that number unless the free bind failed (an entry with a port, or none).
     */
    private fun attempts(calls: List<String>): List<Pair<String, String?>> {
        val out = mutableListOf<Pair<String, String?>>()
        var k = 0
        while (k < calls.size) {
            val free = calls[k++]
            val twin = calls.getOrNull(k)?.takeIf { it != "udp0" && it != "tcp0" }
            if (twin != null) k++
            out += free to twin
        }
        return out
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
