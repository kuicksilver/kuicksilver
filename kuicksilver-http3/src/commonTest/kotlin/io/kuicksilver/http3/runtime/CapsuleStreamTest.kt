// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.runtime

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Capsule
import io.kuicksilver.http3.CapsuleConfig
import io.kuicksilver.http3.CapsuleProtocol
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3Stream
import io.kuicksilver.http3.capsuleConfig
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.DatagramSendResult
import io.kuicksilver.quic.DatagramUnsupportedReason
import io.kuicksilver.quic.QuicException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.seconds

private const val WT_TYPE = 0x2843L

private val connectOn = http3Settings { enableConnectProtocol = true }

private val noH3Datagrams =
    http3Settings {
        enableConnectProtocol = true
        h3Datagram = false
    }

private val known = CapsuleConfig(knownTypes = setOf(WT_TYPE))

private fun capsuleBytes(
    type: Long,
    value: ByteArray,
) = VarInt.encode(type) + VarInt.encode(value.size.toLong()) + value

/** The HTTP/3 error code of a stream the peer reset or stopped, however the layer above reported it. */
private fun h3Code(e: Throwable): Long? =
    generateSequence(e) { it.cause }.firstNotNullOfOrNull {
        when (it) {
            is Http3Exception.Protocol -> it.h3Code
            is QuicException.StreamError.Reset -> it.code
            is QuicException.StreamError.Stopped -> it.code
            else -> null
        }
    }

/** Reads [s]'s input until the peer's reset and returns its code; fails when the input ends cleanly. */
private suspend fun peerResetCode(s: Http3Stream): Long? {
    val e =
        assertFailsWith<Throwable>("the stream ended cleanly instead of being reset") { withTimeout(5.seconds) { s.input.readAllBytes() } }
    return h3Code(e)
}

class CapsuleStreamTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun capsulesBothWays() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                val server =
                    async {
                        val s =
                            p.server
                                .acceptRequest()
                                .acceptConnect()
                                .useCapsuleProtocol(known)
                        val got = s.capsules.first()
                        s.send(Capsule(WT_TYPE, "ack".encodeToByteArray()))
                        s.close()
                        got
                    }
                val c = p.client.connect(connectReq(), "test-capsules").useCapsuleProtocol(known)
                c.send(Capsule(WT_TYPE, "bye".encodeToByteArray()))
                assertEquals(Capsule(WT_TYPE, "bye".encodeToByteArray()), withTimeout(5.seconds) { server.await() })
                // the server's close() wrote its queue, then FIN: the client's flow ends normally after the capsule
                assertEquals(listOf(Capsule(WT_TYPE, "ack".encodeToByteArray())), withTimeout(5.seconds) { c.capsules.toList() })
                c.close()
            }
        }

    /** RFC 9297 section 3.2: a capsule of an unknown type is skipped, whatever its size, and the next one is delivered. */
    @Test fun unknownCapsuleSkipped() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                val server =
                    async {
                        p.server
                            .acceptRequest()
                            .acceptConnect()
                            .useCapsuleProtocol(known)
                    }
                val c = p.client.connect(connectReq(), "test-capsules")
                launch {
                    c.output.writeFully(capsuleBytes(0x2a, ByteArray(1 shl 20)))
                    c.output.writeFully(capsuleBytes(WT_TYPE, "x".encodeToByteArray()))
                    c.output.flushAndClose()
                }
                val s = withTimeout(5.seconds) { server.await() }
                assertEquals(listOf(Capsule(WT_TYPE, "x".encodeToByteArray())), withTimeout(10.seconds) { s.capsules.toList() })
            }
        }

    /** RFC 9297 section 3.3: a FIN inside a capsule is a malformed message, not a clean end; the stream is reset with H3_MESSAGE_ERROR. */
    @Test fun negative_truncatedCapsuleResetsStream() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                val server =
                    async {
                        p.server
                            .acceptRequest()
                            .acceptConnect()
                            .useCapsuleProtocol(known)
                    }
                val c = p.client.connect(connectReq(), "test-capsules")
                c.output.writeFully(capsuleBytes(WT_TYPE, ByteArray(10)).copyOf(7))
                c.output.flushAndClose()
                val s = withTimeout(5.seconds) { server.await() }
                val e = assertFailsWith<Http3Exception.MessageError> { withTimeout(5.seconds) { s.capsules.toList() } }
                assertEquals(c.streamId, e.streamId)
                assertEquals(Http3ErrorCode.MESSAGE_ERROR, peerResetCode(c))
            }
        }

    @Test fun negative_knownCapsuleAboveLimit() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                val server =
                    async {
                        p.server
                            .acceptRequest()
                            .acceptConnect()
                            .useCapsuleProtocol(known)
                    }
                val c = p.client.connect(connectReq(), "test-capsules")
                launch {
                    peerMayHaveClosed {
                        c.output.writeFully(capsuleBytes(WT_TYPE, ByteArray(65_537)))
                        c.output.flushAndClose()
                    }
                }
                val s = withTimeout(5.seconds) { server.await() }
                assertFailsWith<Http3Exception.MessageError> { withTimeout(5.seconds) { s.capsules.toList() } }
                assertEquals(Http3ErrorCode.MESSAGE_ERROR, peerResetCode(c))
                assertFalse(p.server.closed.isCompleted, "a malformed capsule is a stream error, the connection lives on")
            }
        }

    /** RFC 9297 section 3.5: without QUIC DATAGRAM (the peer's SETTINGS_H3_DATAGRAM=0) a datagram goes out as a DATAGRAM capsule. */
    @Test fun datagramCapsuleFallback() =
        h3Test {
            H3Pair.open(serverSettings = noH3Datagrams).useScoped { p ->
                val server =
                    async {
                        p.server
                            .acceptRequest()
                            .acceptConnect()
                            .useCapsuleProtocol()
                    }
                val c = p.client.connect(connectReq(), "test-capsules").useCapsuleProtocol()
                assertEquals(DatagramSendResult.Sent, c.trySendDatagram("x".encodeToByteArray()))
                c.sendDatagram("y".encodeToByteArray())
                val s = withTimeout(5.seconds) { server.await() }
                assertEquals(
                    listOf("x", "y"),
                    withTimeout(5.seconds) {
                        s.datagrams
                            .take(2)
                            .toList()
                            .map { it.decodeToString() }
                    },
                )
                // the server's own SETTINGS_H3_DATAGRAM=0 (Disabled) falls back too
                assertEquals(DatagramSendResult.Sent, s.trySendDatagram("z".encodeToByteArray()))
                assertEquals("z", withTimeout(5.seconds) { c.datagrams.first() }.decodeToString())
            }
        }

    @Test fun datagramFallbackOff() =
        h3Test {
            H3Pair.open(serverSettings = noH3Datagrams).useScoped { p ->
                launch { p.server.acceptRequest().acceptConnect() }
                val c = p.client.connect(connectReq(), "test-capsules").useCapsuleProtocol(CapsuleConfig(datagramFallback = false))
                assertEquals(
                    DatagramSendResult.Unsupported(DatagramUnsupportedReason.PeerDoesNotSupport),
                    c.trySendDatagram("x".encodeToByteArray()),
                )
                assertFailsWith<QuicException.DatagramUnsupported> { c.sendDatagram("x".encodeToByteArray()) }
            }
        }

    /** RFC 9297 section 3.5: DATAGRAM capsules are received even when QUIC DATAGRAM frames are in use, in the same flow. */
    @Test fun datagramCapsuleReceivedWithQuicDatagrams() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                val clientReady = CompletableDeferred<Unit>()
                launch {
                    val s = p.server.acceptRequest().acceptConnect()
                    clientReady.await()
                    s.output.writeFully(capsuleBytes(CapsuleProtocol.DATAGRAM, "cap".encodeToByteArray()))
                    s.output.flush()
                    assertEquals(DatagramSendResult.Sent, s.trySendDatagram("quic".encodeToByteArray()))
                }
                val c = p.client.connect(connectReq(), "test-capsules").useCapsuleProtocol()
                val got =
                    async {
                        c.datagrams
                            .take(2)
                            .toList()
                            .map { it.decodeToString() }
                    }
                clientReady.complete(Unit)
                assertEquals(listOf("cap", "quic"), withTimeout(5.seconds) { got.await() }.sorted())
            }
        }

    /** RFC 9297 section 3.5: a datagram too large for QUIC is not turned into a capsule. */
    @Test fun tooLargeDoesNotFallBack() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                launch { p.server.acceptRequest().acceptConnect() }
                val c = p.client.connect(connectReq(), "test-capsules").useCapsuleProtocol()
                assertIs<DatagramSendResult.TooLarge>(c.trySendDatagram(ByteArray(100_000)))
            }
        }

    /** RFC 9297 section 3.2: a CONNECT with content-length cannot use the Capsule Protocol; the receiver treats it as malformed. */
    @Test fun negative_capsuleProtocolWithContentLength() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                val server =
                    async {
                        val s = p.server.acceptRequest().acceptConnect()
                        assertFailsWith<Http3Exception.MessageError> { s.useCapsuleProtocol() }
                    }
                // the server's reset races the 2xx: connect() either fails with it or returns a stream that sees it
                val connected =
                    runCatching {
                        p.client.connect(
                            http3Request("CONNECT", "server.test", "/chat") { headers = Http3Headers.of("content-length" to "0") },
                            "test-capsules",
                        )
                    }
                withTimeout(5.seconds) { server.await() }
                val code = connected.fold(onSuccess = { peerResetCode(it) }, onFailure = { h3Code(it) })
                assertEquals(Http3ErrorCode.MESSAGE_ERROR, code, "client saw ${connected.exceptionOrNull() ?: "a stream"}")
            }
        }

    /** RFC 9297 section 3.2: a 204, 205 or 206 response cannot use the Capsule Protocol. */
    @Test fun negative_capsuleProtocolWith204() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                val serverBody =
                    async {
                        val r = p.server.acceptRequest()
                        r.respond(204)
                        runCatching { withTimeout(5.seconds) { r.body.readAllBytes() } }.exceptionOrNull()
                    }
                val c = p.client.connect(connectReq(), "test-capsules")
                val e = assertFailsWith<Http3Exception.MessageError> { c.useCapsuleProtocol() }
                assertEquals(c.streamId, e.streamId)
                val seen = withTimeout(5.seconds) { serverBody.await() }
                assertEquals(Http3ErrorCode.MESSAGE_ERROR, seen?.let(::h3Code), "the server saw $seen")
            }
        }

    /** Our own message breaking section 3.2 is a programming error, reported before any capsule is sent. */
    @Test fun ownContentTypeRejected() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                launch { p.server.acceptRequest().acceptConnect() }
                val c =
                    p.client.connect(
                        http3Request("CONNECT", "server.test", "/chat") { headers = Http3Headers.of("content-type" to "text/plain") },
                        "test-capsules",
                    )
                assertFailsWith<IllegalStateException> { c.useCapsuleProtocol() }
            }
        }

    @Test fun capsuleProtocolFieldParsing() {
        fun enabled(vararg values: String) = CapsuleProtocol.isEnabled(Http3Headers(values.map { "capsule-protocol" to it }))
        assertTrue(enabled("?1"))
        assertTrue(enabled("?1;a=b"))
        assertTrue(enabled(" ?1 "))
        assertTrue(enabled("?1;a;b=?0;c=\"s;t\";d=12.5"))
        assertFalse(enabled("?0"))
        assertFalse(enabled("1"))
        assertFalse(enabled("\"?1\""))
        assertFalse(enabled("?1", "?1"))
        assertFalse(enabled("?1, ?1"))
        assertFalse(enabled("?1;"))
        assertFalse(enabled("?1;A=b"))
        assertFalse(enabled("?1x"))
        assertFalse(enabled(""))
        assertFalse(CapsuleProtocol.isEnabled(Http3Headers.Empty))
        assertTrue(CapsuleProtocol.isEnabled(Http3Headers.of(CapsuleProtocol.Enabled)))
        assertEquals("capsule-protocol" to "?1", CapsuleProtocol.Enabled)
    }

    @Test fun useTwiceFails() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                launch { p.server.acceptRequest().acceptConnect() }
                val c = p.client.connect(connectReq(), "test-capsules")
                c.useCapsuleProtocol()
                assertFailsWith<IllegalStateException> { c.useCapsuleProtocol() }
            }
        }

    @Test fun sendAfterCloseFails() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                launch { p.server.acceptRequest().acceptConnect() }
                val c = p.client.connect(connectReq(), "test-capsules").useCapsuleProtocol(known)
                c.close()
                c.close() // again: nothing more
                assertFailsWith<IllegalStateException> { c.send(Capsule(WT_TYPE, ByteArray(0))) }
                assertEquals(DatagramSendResult.Closed, c.trySendDatagram(byteArrayOf(1)))
            }
        }

    /** Asking the peer to stop sending ends the capsule flow with an error, so a collector never waits for capsules that will not come. */
    @Test fun stopSendingEndsCapsules() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                launch { p.server.acceptRequest().acceptConnect() }
                val c = p.client.connect(connectReq(), "test-capsules").useCapsuleProtocol(known)
                val collected = async { runCatching { c.capsules.toList() } }
                c.stream.stopSending(Http3ErrorCode.REQUEST_CANCELLED)
                assertTrue(withTimeout(5.seconds) { collected.await() }.isFailure)
            }
        }

    /** A connection that closes under a capsule stream fails the flow: a protocol on top must not read it as an orderly end. */
    @Test fun connectionCloseFailsCapsules() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                launch { p.server.acceptRequest().acceptConnect() }
                val c = p.client.connect(connectReq(), "test-capsules").useCapsuleProtocol(known)
                val collected = async { runCatching { c.capsules.toList() } }
                p.client.close()
                assertTrue(withTimeout(5.seconds) { collected.await() }.isFailure)
            }
        }

    /**
     * A terminal capsule (WebTransport's WT_CLOSE_SESSION, draft-ietf-webtrans-http3 section 6) is delivered; a capsule
     * after it, even of an unknown type, resets the stream with H3_MESSAGE_ERROR and fails the flow.
     */
    @Test fun negative_capsuleAfterTerminalCapsule() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                val terminal = CapsuleConfig(knownTypes = setOf(WT_TYPE), terminalTypes = setOf(WT_TYPE))
                val server =
                    async {
                        p.server
                            .acceptRequest()
                            .acceptConnect()
                            .useCapsuleProtocol(terminal)
                    }
                val c = p.client.connect(connectReq(), "test-capsules")
                launch {
                    peerMayHaveClosed {
                        c.output.writeFully(capsuleBytes(WT_TYPE, "close".encodeToByteArray()) + capsuleBytes(0x2a, ByteArray(4)))
                        c.output.flush()
                    }
                }
                val s = withTimeout(5.seconds) { server.await() }
                val got = ArrayList<Capsule>()
                assertFailsWith<Http3Exception.MessageError> { withTimeout(5.seconds) { s.capsules.collect { got += it } } }
                assertEquals(listOf(Capsule(WT_TYPE, "close".encodeToByteArray())), got)
                assertEquals(Http3ErrorCode.MESSAGE_ERROR, peerResetCode(c))
            }
        }

    /** A terminal capsule followed by the FIN is a clean end. */
    @Test fun terminalCapsuleThenFinEndsCleanly() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                val terminal =
                    capsuleConfig {
                        knownTypes = setOf(WT_TYPE)
                        terminalTypes = setOf(WT_TYPE)
                    }
                val server =
                    async {
                        p.server
                            .acceptRequest()
                            .acceptConnect()
                            .useCapsuleProtocol(terminal)
                    }
                val c = p.client.connect(connectReq(), "test-capsules").useCapsuleProtocol(terminal)
                c.send(Capsule(WT_TYPE, "close".encodeToByteArray()))
                c.close()
                val s = withTimeout(5.seconds) { server.await() }
                assertEquals(listOf(Capsule(WT_TYPE, "close".encodeToByteArray())), withTimeout(5.seconds) { s.capsules.toList() })
            }
        }

    /**
     * What a peer that reads nothing lets `send` accept is bounded, and resetting the stream ends a writer it holds:
     * the pending sends fail and close() fails instead of waiting.
     *
     * The bound is the sum of fixed limits: the capsule queue (32 x 60 KB), the HTTP/3 writer's channel (about 2 MiB of
     * ktor buffering, plus one batch of the queue), `QuicConfig.maxSendBuffer` (4 MiB), and on the peer its stream
     * window (512 KiB, at most `maxStreamWindow` = 6 MiB once tuned) plus its HTTP/3 layer's body channel (about 2 MiB):
     * under 19 MB, measured 8.7 to 9.7 MB on the JVM and macOS, with and without CPU load. The sender offers 30 MB, so
     * on a bounded build it cannot finish, whatever the timing. It starts UNDISPATCHED: a send queue that never
     * suspends would let every send return before `launch` does, and the test fails then. The reset follows an event
     * (the queue is full, which needs nothing from the peer), and the deadlines below only guard liveness.
     */
    @Test fun negative_capsuleSendsBoundedWhenPeerReadsNothing() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                launch { p.server.acceptRequest().acceptConnect() } // never reads
                val c = p.client.connect(connectReq(), "test-capsules").useCapsuleProtocol(known)
                val size = 60_000 + 4L // value plus the type and length varints
                val offered = 500 * size // 30 MB
                val bound = 20L shl 20 // 20 MiB, above the 19 MB sum of the limits
                val accepted = MutableStateFlow(0L)
                var outcome: Result<Unit>? = null
                val sender =
                    launch(start = CoroutineStart.UNDISPATCHED) {
                        outcome =
                            runCatching {
                                repeat(500) {
                                    c.send(Capsule(WT_TYPE, ByteArray(60_000)))
                                    accepted.value += size
                                }
                            }
                    }
                assertTrue(sender.isActive, "all ${accepted.value} bytes were accepted without a single send suspending")
                val queueFull = known.sendQueue * size
                withTimeoutOrNull(10.seconds) { accepted.first { it >= queueFull } }
                    ?: fail("the capsule queue never filled: ${accepted.value} bytes accepted")
                c.stream.reset(Http3ErrorCode.REQUEST_CANCELLED)
                withTimeoutOrNull(10.seconds) { sender.join() } ?: fail("a send stayed suspended after the stream was reset")
                assertTrue(outcome!!.isFailure, "the sender finished all $offered bytes though the peer read nothing")
                assertTrue(accepted.value <= bound, "${accepted.value} bytes accepted, above the bound of $bound")
                assertFails("close() succeeded after the reset") { withTimeout(10.seconds) { c.close() } }
            }
        }

    @Test fun capsuleEqualityAndConfigRanges() {
        assertEquals(Capsule(1, byteArrayOf(1, 2)), Capsule(1, byteArrayOf(1, 2)))
        assertEquals(Capsule(1, byteArrayOf(1, 2)).hashCode(), Capsule(1, byteArrayOf(1, 2)).hashCode())
        assertNotEquals(Capsule(1, byteArrayOf(1, 2)), Capsule(2, byteArrayOf(1, 2)))
        assertNotEquals(Capsule(1, byteArrayOf(1, 2)), Capsule(1, byteArrayOf(1, 3)))
        assertFailsWith<IllegalArgumentException> { Capsule(-1, ByteArray(0)) }
        assertFailsWith<IllegalArgumentException> { Capsule(1L shl 62, ByteArray(0)) }
        assertFailsWith<IllegalArgumentException> { CapsuleConfig(maxCapsuleLength = 0) }
        assertFailsWith<IllegalArgumentException> { CapsuleConfig(maxCapsuleLength = 1_048_577) }
        assertFailsWith<IllegalArgumentException> { CapsuleConfig(knownTypes = setOf(1L shl 62)) }
        assertFailsWith<IllegalArgumentException> { CapsuleConfig(receiveQueue = 0) }
        assertFailsWith<IllegalArgumentException> { CapsuleConfig(terminalTypes = setOf(WT_TYPE)) } // not a known type
        assertFailsWith<IllegalArgumentException> { CapsuleConfig(knownTypes = setOf(0), terminalTypes = setOf(0)) }
        val c =
            capsuleConfig {
                knownTypes = setOf(WT_TYPE)
                datagramFallback = false
            }
        assertEquals(setOf(WT_TYPE), c.knownTypes)
        assertFalse(c.datagramFallback)
        assertEquals(c.maxCapsuleLength, c.toBuilder().build().maxCapsuleLength)
    }
}
