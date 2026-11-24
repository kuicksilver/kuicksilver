// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.server.h1

import io.ktor.http.cio.Request
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kotlinx.io.readByteArray
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A request that offers an upgrade (RFC 9110 section 7.8) and carries neither Content-Length nor Transfer-Encoding has a
 * zero-length body (RFC 9112 section 6.3 item 7), whatever the server decides about the upgrade: the body ends at once,
 * and the connection's later bytes reach the new protocol only once an upgrade is taken. In-memory channels, virtual
 * time.
 */
class H1PipelineUpgradeOfferTest {
    private fun TestScope.pipeline(handler: suspend H1RequestScope.(Request) -> Unit): Pair<ByteChannel, ByteChannel> {
        val toServer = ByteChannel()
        val fromServer = ByteChannel()
        backgroundScope.startH1Pipeline(H1Connection(toServer, fromServer, null, null), 45.seconds, 30.seconds, handler = handler)
        runCurrent()
        return toServer to fromServer
    }

    private val ok = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

    /**
     * The handler reads the body of an upgrade offer before it answers: the body is empty and ends at once, the response
     * goes out, and the next request on the connection is served. Before, the body stayed open until the response head
     * settled the upgrade, which waited for the handler: the connection hung.
     */
    @Test fun negative_theBodyOfAnUpgradeOfferEndsAtOnce() =
        runTest {
            val bodies = mutableListOf<Int>()
            val (toServer, fromServer) =
                pipeline { request ->
                    request.release()
                    bodies += input.readBuffer().readByteArray().size
                    output.writeStringUtf8(ok)
                    output.flush()
                }
            toServer.writeStringUtf8(
                "GET /a HTTP/1.1\r\nHost: s\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n" +
                    "GET /b HTTP/1.1\r\nHost: s\r\n\r\n",
            )
            toServer.flush()
            assertEquals(ok + ok, withTimeout(10.seconds) { fromServer.readText((ok + ok).length) })
            assertEquals(listOf(0, 0), bodies)
        }

    /**
     * Every order of reading the body and answering, on one connection of upgrade offers: the body read whole, then a
     * Content-Length response; read whole, then a chunked response; read in 1-byte pieces, then a response; the response
     * first, then the body. Each body is empty, each response arrives, in order.
     */
    @Test fun negative_everyOrderOfReadingTheBodyOfAnUpgradeOfferEnds() =
        runTest {
            val chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"
            val bodies = mutableListOf<Int>()
            val (toServer, fromServer) =
                pipeline { request ->
                    val path = request.uri.toString()
                    request.release()
                    when (path) {
                        "/whole" -> {
                            bodies += input.readBuffer().readByteArray().size
                            output.writeStringUtf8(ok)
                        }

                        "/chunked" -> {
                            bodies += input.readBuffer().readByteArray().size
                            output.writeStringUtf8(chunked)
                        }

                        "/bytewise" -> {
                            val one = ByteArray(1)
                            var n = 0
                            while (input.readAvailable(one, 0, 1) >= 0) n++
                            bodies += n
                            output.writeStringUtf8(ok)
                        }

                        else -> {
                            output.writeStringUtf8(ok)
                            output.flush()
                            bodies += input.readBuffer().readByteArray().size
                        }
                    }
                    output.flush()
                }
            val paths = listOf("/whole", "/chunked", "/bytewise", "/answer-first", "/whole")
            toServer.writeStringUtf8(
                paths.joinToString("") { "GET $it HTTP/1.1\r\nHost: s\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n" },
            )
            toServer.flush()
            val expected = ok + chunked + ok + ok + ok
            assertEquals(expected, withTimeout(10.seconds) { fromServer.readText(expected.length) })
            assertEquals(List(paths.size) { 0 }, bodies)
        }

    /**
     * Reading the (empty) body does not take the bytes after the head away from the new protocol: the handler reads the
     * body, switches protocols, and the upgraded input carries everything the client sent after the request.
     */
    @Test fun anUpgradeTakenAfterTheBodyWasReadGetsTheBytesAfterTheHead() =
        runTest {
            val seen = CompletableDeferred<Pair<Int, String>>()
            val (toServer, _) =
                pipeline { request ->
                    request.release()
                    val body = input.readBuffer().readByteArray().size
                    output.writeStringUtf8("HTTP/1.1 101 Switching Protocols\r\nUpgrade: test\r\nConnection: Upgrade\r\n\r\n")
                    output.flush()
                    upgraded!!.complete(true)
                    seen.complete(body to upgradeInput!!.readText(10))
                }
            toServer.writeStringUtf8("GET /ws HTTP/1.1\r\nHost: s\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\nnew-bytes!")
            toServer.flush()
            assertEquals(0 to "new-bytes!", withTimeout(10.seconds) { seen.await() })
        }

    /**
     * An upgrade the server does not take: the upgraded input ends empty, and what follows the head is read as the next
     * request.
     */
    @Test fun anUpgradeNotTakenEndsTheUpgradedInputAndServesTheNextRequest() =
        runTest {
            val upgradedInputs = mutableListOf<ByteReadChannel?>()
            val (toServer, fromServer) =
                pipeline { request ->
                    request.release()
                    upgradedInputs += upgradeInput
                    output.writeStringUtf8(ok)
                    output.flush()
                }
            toServer.writeStringUtf8(
                "GET /a HTTP/1.1\r\nHost: s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nGET /b HTTP/1.1\r\nHost: s\r\n\r\n",
            )
            toServer.flush()
            assertEquals(ok + ok, withTimeout(10.seconds) { fromServer.readText((ok + ok).length) })
            val first = assertNotNull(upgradedInputs[0])
            assertEquals(0, first.readBuffer().readByteArray().size)
            assertTrue(first.isClosedForRead)
            assertNull(upgradedInputs[1], "a request without an upgrade offer has no upgraded input")
        }

    /**
     * What makes a request an upgrade offer: a GET, the `upgrade` option in any case and position, in any Connection field
     * line, and an Upgrade that names a protocol. Empty list elements are ignored (RFC 9110 section 5.6.1.2), so an
     * Upgrade of only commas names none, and an empty Connection field carries no option.
     */
    @Test fun negative_upgradeOffersFollowTheListRules() =
        runTest {
            val offered = mutableListOf<Boolean>()
            val (toServer, fromServer) =
                pipeline { request ->
                    request.release()
                    offered += upgraded != null
                    output.writeStringUtf8(ok)
                    output.flush()
                }
            val heads =
                listOf(
                    "Connection: keep-alive\r\nConnection: Upgrade\r\nUpgrade: h2c" to true,
                    "Connection: ,\tupgrade ,\r\nUpgrade: , h2c" to true,
                    "Connection:\r\nUpgrade: h2c" to false,
                    "Connection: upgrade\r\nUpgrade: , ,\t" to false,
                    "Connection: upgradex\r\nUpgrade: h2c" to false,
                )
            toServer.writeStringUtf8(heads.joinToString("") { "GET / HTTP/1.1\r\nHost: s\r\n${it.first}\r\n\r\n" })
            toServer.flush()
            val expected = ok.repeat(heads.size)
            assertEquals(expected, withTimeout(10.seconds) { fromServer.readText(expected.length) })
            assertEquals(heads.map { it.second }, offered, heads.map { it.first }.toString())
        }

    /**
     * An empty Connection field (or one of only commas and OWS) is a valid empty list (RFC 9110 section
     * 5.6.1.2), not a bad request: the request is served, and the connection stays open for the next one. Before, Ktor's
     * parser threw on the empty value and the engine answered 400.
     */
    @Test fun negative_anEmptyConnectionFieldIsAccepted() =
        runTest {
            var served = 0
            val (toServer, fromServer) =
                pipeline { request ->
                    request.release()
                    served++
                    output.writeStringUtf8(ok)
                    output.flush()
                }
            val values = listOf("Connection:\r\n", "Connection: \r\n", "Connection: \t \r\n", "Connection: , ,\r\n")
            toServer.writeStringUtf8(values.joinToString("") { "GET / HTTP/1.1\r\nHost: s\r\n$it\r\n" })
            toServer.flush()
            val expected = ok.repeat(values.size)
            assertEquals(expected, withTimeout(10.seconds) { fromServer.readText(expected.length) })
            assertEquals(values.size, served)
            assertFalse(fromServer.isClosedForRead)
        }

    /**
     * The 101 checks of RFC 9110 section 7.8 ([upgradeProblem]): an Upgrade that names a protocol, each one offered by
     * the request (any case, any field line; a version only when it is the offered one), and [switchesToWebSocket] on the
     * list's elements, not on a substring.
     */
    @Test fun negative_upgradeResponsesFollowSection7_8() {
        assertNull(upgradeProblem(listOf("websocket"), listOf("WebSocket")))
        assertNull(upgradeProblem(listOf("h2c", "foo/1, bar"), listOf("foo")))
        assertNull(upgradeProblem(listOf("foo/1"), listOf("FOO/1", "", " , foo")))
        assertNotNull(upgradeProblem(listOf("h2c"), emptyList()))
        assertNotNull(upgradeProblem(listOf("h2c"), listOf(" , ,\t")))
        assertNotNull(upgradeProblem(listOf("h2c"), listOf("h2c, foo")))
        assertNotNull(upgradeProblem(listOf("foo/1"), listOf("foo/2")))
        assertNotNull(upgradeProblem(listOf("foo"), listOf("foo/1")))
        assertNotNull(upgradeProblem(emptyList(), listOf("foo")))
        assertTrue(switchesToWebSocket(listOf("h2c", "WebSocket")))
        assertFalse(switchesToWebSocket(listOf("x-websocket-tunnel")))
        assertFalse(switchesToWebSocket(listOf("websocket2, h2c")))
    }

    /** Reads [length] characters (ASCII), or what came before the end. */
    private suspend fun ByteReadChannel.readText(length: Int): String {
        val out = StringBuilder()
        val buf = ByteArray(4096)
        while (out.length < length) {
            val n = readAvailable(buf, 0, minOf(buf.size, length - out.length))
            if (n < 0) break
            out.append(buf.decodeToString(0, n))
        }
        return out.toString()
    }
}
