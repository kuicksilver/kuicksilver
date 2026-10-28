// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Role
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.ControlFrames
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.awaitFinished
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * Starting HTTP/3 on a peer whose transport parameters allow fewer than the three unidirectional streams HTTP/3 needs
 * (RFC 9114 section 6.2: "the transport parameters sent by both clients and servers MUST allow the peer to create at least
 * three unidirectional streams"). Opening our critical streams waits for stream credit; such a peer never gives it.
 */
class SessionStartTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * The server side returns at once (its accept loop must never wait on one peer) and closes the connection with
     * H3_GENERAL_PROTOCOL_ERROR once the critical streams could not be opened in time. It waited forever in `openUni`.
     */
    @Test fun negative_serverStartDoesNotWaitForUniStreamCredit() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect(clientQuic = quicConfig { maxUniStreams = 2 })
                val server =
                    withTimeout(10.seconds) {
                        Http3Connection.start(s, Http3Role.Server, Http3Settings.Default, criticalStreamsDeadline = 100.milliseconds)
                    }
                val local = assertIs<Http3Exception.Protocol>(server.closed.await())
                assertEquals(Http3ErrorCode.GENERAL_PROTOCOL_ERROR, local.h3Code)
                assertEquals(Http3ErrorCode.GENERAL_PROTOCOL_ERROR, peerSawClose(c))
            }
        }

    /** The client side fails with the connection's error instead of hanging the caller of `connect`. */
    @Test fun negative_clientStartFailsWithoutUniStreamCredit() =
        h3Test {
            QuicPair.open(serverQuic = quicConfig { maxUniStreams = 2 }).use { q ->
                val (c, s) = q.connect()
                val e =
                    assertFailsWith<Http3Exception.Protocol> {
                        withTimeout(10.seconds) {
                            Http3Connection.start(c, Http3Role.Client, Http3Settings.Default, criticalStreamsDeadline = 100.milliseconds)
                        }
                    }
                assertEquals(Http3ErrorCode.GENERAL_PROTOCOL_ERROR, e.h3Code)
                assertEquals(Http3ErrorCode.GENERAL_PROTOCOL_ERROR, peerSawClose(s))
            }
        }

    /**
     * A server that is stopping sends GOAWAY before the client's own SETTINGS went out (here held back by the server's
     * stream credit), and the idle client closes at once (RFC 9114 section 5.2). Starting the client is not a failure of
     * the handshake or the protocol: the connection is returned with the GOAWAY, and a request on it fails with the
     * retry-safe [Http3Exception.RequestNotProcessed], never with the client's own H3_NO_ERROR close.
     */
    @Test fun goAwayBeforeTheClientSettingsLeaveRefusesRequestsAsNotProcessed() =
        h3Test {
            QuicPair.open(serverQuic = quicConfig { maxUniStreams = 2 }).use { q ->
                val (c, s) = q.connect()
                val raw = RawPeer(s)
                raw.openControl()
                raw.control.output.writeFully(raw.frame(FrameType.GOAWAY, ControlFrames.goAwayPayload(0)))
                raw.control.output.flush()
                val client = withTimeout(10.seconds) { Http3Connection.client(c) }
                assertEquals(0L, client.goAwayReceived.value)
                assertFailsWith<Http3Exception.RequestNotProcessed> { withTimeout(10.seconds) { client.request(get()) } }
            }
        }

    /**
     * RFC 9114 section 5.2 lets a stopping server close at once after its GOAWAY ("it MAY initiate an immediate closure of
     * the connection. An endpoint that completes a graceful shutdown SHOULD use the H3_NO_ERROR error code"). Its
     * H3_NO_ERROR close can come before the client's own idle close; here the client's waits until the transport is gone.
     * That graceful end is no failure of the start either: the connection is returned and requests are not processed.
     */
    @Test fun peerNoErrorCloseAfterGoAwayRefusesRequestsAsNotProcessed() =
        h3Test {
            val idleCloseDue = CompletableDeferred<Unit>()
            H3Session.beforeIdleCloseForTest = {
                idleCloseDue.complete(Unit) // the client read the GOAWAY and is about to close idle
                it.quic.closed.await()
            }
            try {
                QuicPair.open(serverQuic = quicConfig { maxUniStreams = 2 }).use { q ->
                    val (c, s) = q.connect()
                    val raw = RawPeer(s)
                    raw.openControl()
                    raw.control.output.writeFully(raw.frame(FrameType.GOAWAY, ControlFrames.goAwayPayload(0)))
                    raw.control.output.flush()
                    val client = async { runCatching { withTimeout(10.seconds) { Http3Connection.client(c) } } }
                    withTimeout(10.seconds) { idleCloseDue.await() }
                    s.close(Http3ErrorCode.NO_ERROR, "")
                    val conn = withTimeout(10.seconds) { client.await() }.getOrThrow()
                    val end = assertIs<Http3Exception.Protocol>(conn.closed.await())
                    assertEquals(Initiator.Peer, end.initiator, "the server's close came first")
                    assertEquals(0L, conn.goAwayReceived.value)
                    assertFailsWith<Http3Exception.RequestNotProcessed> { withTimeout(10.seconds) { conn.request(get()) } }
                }
            } finally {
                H3Session.beforeIdleCloseForTest = null
            }
        }

    /**
     * Only the client's own idle H3_NO_ERROR close after GOAWAY is no failure to report: a server that breaks the protocol
     * after its GOAWAY (a second SETTINGS, RFC 9114 section 7.2.4: "MUST treat receipt of a second SETTINGS frame as a
     * connection error of type H3_FRAME_UNEXPECTED") still makes starting the client fail with that error.
     */
    @Test fun negative_protocolErrorAfterGoAwayFailsTheStart() =
        h3Test {
            QuicPair.open(serverQuic = quicConfig { maxUniStreams = 2 }).use { q ->
                val (c, s) = q.connect()
                val raw = RawPeer(s)
                raw.openControl()
                raw.control.output.writeFully(
                    raw.frame(FrameType.GOAWAY, ControlFrames.goAwayPayload(0)) +
                        raw.frame(FrameType.SETTINGS, ByteArray(0)),
                )
                raw.control.output.flush()
                val e = assertFailsWith<Http3Exception.Protocol> { withTimeout(10.seconds) { Http3Connection.client(c) } }
                assertEquals(Http3ErrorCode.FRAME_UNEXPECTED, e.h3Code)
                assertEquals(Http3ErrorCode.FRAME_UNEXPECTED, peerSawClose(s))
            }
        }

    /**
     * A server that writes GOAWAY and closes with H3_NO_ERROR at once can have both arrive in one receive batch, and the
     * close can complete the session before the control reader has applied the GOAWAY. Here the reader holds the GOAWAY
     * frame it read until the session saw the server's close: the start still returns the connection with the GOAWAY (RFC
     * 9114 section 5.2, a graceful end) instead of failing with the peer's H3_NO_ERROR. Before, whether the start failed
     * depended on that order (red: it failed every time here).
     */
    @Test fun goAwayParsedAfterThePeersNoErrorCloseStillRefusesRequestsAsNotProcessed() =
        h3Test {
            val held = CompletableDeferred<Unit>()
            H3Session.beforeGoAwayForTest = {
                held.complete(Unit)
                it.closed.await() // the transport close went first
            }
            try {
                QuicPair.open(serverQuic = quicConfig { maxUniStreams = 2 }).use { q ->
                    val (c, s) = q.connect()
                    val raw = RawPeer(s)
                    raw.openControl()
                    raw.control.output.writeFully(raw.frame(FrameType.GOAWAY, ControlFrames.goAwayPayload(0)))
                    raw.control.output.flush()
                    val client = async { runCatching { withTimeout(10.seconds) { Http3Connection.client(c) } } }
                    withTimeout(10.seconds) { held.await() } // the client read the GOAWAY frame and has not applied it yet
                    s.close(Http3ErrorCode.NO_ERROR, "")
                    val conn = withTimeout(10.seconds) { client.await() }.getOrThrow()
                    val end = assertIs<Http3Exception.Protocol>(conn.closed.await())
                    assertEquals(Initiator.Peer, end.initiator)
                    assertEquals(Http3ErrorCode.NO_ERROR, end.h3Code)
                    assertEquals(0L, conn.goAwayReceived.value)
                    assertFailsWith<Http3Exception.RequestNotProcessed> { withTimeout(10.seconds) { conn.request(get()) } }
                }
            } finally {
                H3Session.beforeGoAwayForTest = null
            }
        }

    /**
     * The server's control stream (SETTINGS, GOAWAY and its end) and its H3_NO_ERROR close reach the client before the
     * client's accept loop took the stream (here held until the session saw the close): the accept loop still takes the
     * streams the peer opened before the loss, the GOAWAY is read, and the start returns the connection with it. Before,
     * the session's end cancelled the accept loop, and the start waited a second and failed with the peer's H3_NO_ERROR.
     */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    @Test
    fun goAwayOnAControlStreamAcceptedAfterThePeersCloseStillRefusesRequestsAsNotProcessed() =
        h3Test {
            H3Session.peerControlWaitTimedOutForTest = null
            val held = CompletableDeferred<Unit>()
            H3Session.beforeAcceptForTest = {
                if (held.complete(Unit)) it.closed.await() // the first accept waits for the close
            }
            try {
                QuicPair.open(serverQuic = quicConfig { maxUniStreams = 2 }).use { q ->
                    val (c, s) = q.connect()
                    val client = async { runCatching { withTimeout(10.seconds) { Http3Connection.client(c) } } }
                    withTimeout(10.seconds) { held.await() }
                    val raw = RawPeer(s)
                    raw.openControl()
                    raw.control.output.writeFully(raw.frame(FrameType.GOAWAY, ControlFrames.goAwayPayload(0)))
                    raw.control.output.flushAndClose()
                    withTimeout(10.seconds) { raw.control.awaitFinished() } // the client's transport has it all
                    s.close(Http3ErrorCode.NO_ERROR, "")
                    val conn = withTimeout(10.seconds) { client.await() }.getOrThrow()
                    assertEquals(0L, conn.goAwayReceived.value)
                    assertEquals(false, H3Session.peerControlWaitTimedOutForTest, "the GOAWAY ended the wait, not its bound")
                    assertFailsWith<Http3Exception.RequestNotProcessed> { withTimeout(10.seconds) { conn.request(get()) } }
                }
            } finally {
                H3Session.beforeAcceptForTest = null
            }
        }

    /**
     * The peer closes with H3_NO_ERROR before it opened any control stream: no GOAWAY can come, so the start fails at once
     * with the close, without waiting for one ([H3Session.DRAIN_GRACE]).
     */
    @Test fun negative_peerNoErrorCloseWithoutAControlStreamFailsTheStartWithoutWaiting() =
        h3Test {
            H3Session.peerControlWaitTimedOutForTest = null
            QuicPair.open(serverQuic = quicConfig { maxUniStreams = 2 }).use { q ->
                val (c, s) = q.connect()
                val client = async { runCatching { withTimeout(10.seconds) { Http3Connection.client(c) } } }
                s.close(Http3ErrorCode.NO_ERROR, "")
                val e = assertIs<Http3Exception.Protocol>(withTimeout(10.seconds) { client.await() }.exceptionOrNull())
                assertEquals(Http3ErrorCode.NO_ERROR, e.h3Code)
                assertEquals(Initiator.Peer, e.initiator)
                assertEquals(false, H3Session.peerControlWaitTimedOutForTest, "the start did not wait for a control stream that never came")
            }
        }

    /**
     * Re-review R4: the close of a rejected 0-RTT is no graceful end after GOAWAY. The server's GOAWAY is read (the start
     * waits for stream credit), and the transport then ends with [QuicException.ConnectionLost.ZeroRttRejected], as the
     * 0.2.1 transport reports a rejection: the start fails with it, so the caller reconnects without 0-RTT, instead of
     * returning a closed connection whose requests are "not processed". Control: the same end reported as an H3_NO_ERROR
     * close, which a close-on-rejection patch closing with H3_NO_ERROR would give, is passed over and the connection
     * returned; that is the behaviour the rejection must never get.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun negative_aRejectedZeroRttAfterGoAwayFailsTheStart() =
        h3Test {
            for (rejected in listOf(true, false)) {
                QuicPair.open(serverQuic = quicConfig { maxUniStreams = 2 }).use { q ->
                    val (c, s) = q.connect()
                    val end = CompletableDeferred<QuicException.ConnectionLost>()
                    val transport =
                        object : io.kuicksilver.quic.QuicConnection by c {
                            override val closed: kotlinx.coroutines.Deferred<QuicException.ConnectionLost> get() = end
                        }
                    H3Session.beforeIdleCloseForTest = {
                        // the GOAWAY was applied; the transport ends now, before the client's own idle close
                        end.complete(
                            if (rejected) {
                                QuicException.ConnectionLost.ZeroRttRejected()
                            } else {
                                QuicException.ConnectionLost.ApplicationClosed(Http3ErrorCode.NO_ERROR, "", Initiator.Local)
                            },
                        )
                        kotlinx.coroutines.awaitCancellation()
                    }
                    try {
                        val raw = RawPeer(s)
                        raw.openControl()
                        raw.control.output.writeFully(raw.frame(FrameType.GOAWAY, ControlFrames.goAwayPayload(0)))
                        raw.control.output.flush()
                        val started = withTimeout(10.seconds) { runCatching { Http3Connection.client(transport) } }
                        if (rejected) {
                            assertIs<QuicException.ConnectionLost.ZeroRttRejected>(started.exceptionOrNull(), "$started")
                        } else {
                            val conn = started.getOrThrow()
                            assertEquals(0L, conn.goAwayReceived.value, "control: an H3_NO_ERROR end is passed over")
                        }
                    } finally {
                        H3Session.beforeIdleCloseForTest = null
                        c.close(Http3ErrorCode.NO_ERROR, "")
                    }
                }
            }
        }

    /**
     * A request stream that reaches the server with the client's close (taken by the accept loop only after the loss, here
     * held until then) is dropped: no handler runs for it on the dead connection, and the application never sees it.
     */
    @Test fun aRequestStreamTakenAfterTheLossNeverReachesTheApplication() =
        h3Test {
            val held = CompletableDeferred<H3Session>()
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = withTimeout(10.seconds) { Http3Connection.server(s) }
                H3Session.beforeAcceptForTest = {
                    if (it === server.session && held.complete(it)) it.closed.await() // the next accept comes after the close
                }
                try {
                    // the server's accept loop is waiting in acceptStream: let it take one more turn into the hook
                    val warm = c.openUni()
                    warm.output.writeFully(byteArrayOf(0x21)) // a reserved stream type: discarded, no error
                    warm.output.flush()
                    val session = withTimeout(10.seconds) { held.await() }
                    val st = c.openBidi()
                    st.output.writeFully(byteArrayOf(0x01, 0x00)) // a HEADERS frame header, cut: what came does not matter
                    st.output.flush()
                    withTimeout(10.seconds) { while (c.stats.bytesInFlight > 0) kotlinx.coroutines.delay(5) } // the server has it
                    c.close(Http3ErrorCode.NO_ERROR, "")
                    withTimeout(10.seconds) { session.closed.await() }
                    assertFailsWith<Throwable> { withTimeout(10.seconds) { server.acceptRequest() } }
                    withTimeout(10.seconds) { while (session.bidiDroppedAfterLossForTest == 0) kotlinx.coroutines.delay(5) }
                    assertEquals(-1L, session.acceptedBidiUpToForTest, "no request stream was handed to request handling")
                } finally {
                    H3Session.beforeAcceptForTest = null
                }
            }
        }

    /** Without a GOAWAY the peer's H3_NO_ERROR close before our SETTINGS went out still fails the start. */
    @Test fun negative_peerNoErrorCloseWithoutGoAwayFailsTheStart() =
        h3Test {
            QuicPair.open(serverQuic = quicConfig { maxUniStreams = 2 }).use { q ->
                val (c, s) = q.connect()
                val raw = RawPeer(s)
                raw.openControl()
                raw.control.output.flush()
                s.close(Http3ErrorCode.NO_ERROR, "")
                val e = assertFailsWith<Http3Exception.Protocol> { withTimeout(10.seconds) { Http3Connection.client(c) } }
                assertEquals(Http3ErrorCode.NO_ERROR, e.h3Code)
                assertEquals(Initiator.Peer, e.initiator)
            }
        }

    /** Exactly three streams is enough: the critical streams open, and the GREASE stream after them is optional. */
    @Test fun threeUniStreamsAreEnough() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect(clientQuic = quicConfig { maxUniStreams = 3 })
                val client = Http3Connection.client(c)
                val server = withTimeout(10.seconds) { Http3Connection.server(s) }
                withTimeout(10.seconds) { client.session.awaitPeerSettings() }
                assertEquals(false, server.closed.isCompleted)
                client.close()
                server.close()
            }
        }
}
