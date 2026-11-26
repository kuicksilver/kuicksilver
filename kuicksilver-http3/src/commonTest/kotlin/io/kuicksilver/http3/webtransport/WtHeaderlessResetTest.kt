// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Fixtures
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.WebTransportException
import io.kuicksilver.http3.WebTransportReceiveStream
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.runtime.H3Session
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicStream
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * draft-ietf-webtrans-http3-02 section 4.3: "If a WebTransport implementation intentionally allows only one session over
 * a given HTTP/3 connection, it SHALL forward the error codes within WebTransport application error code range to the
 * application that owns the only session on that connection." A draft-02 connection carries one session (draft-02 has no
 * WebTransport flow control, and section 5.1 of draft-17 keeps a connection without it to one), so a stream the peer
 * resets before its header named a session reaches that session's application with the reset's code.
 */
class WtHeaderlessResetTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val draft02Only = setOf(SettingsId.WT_ENABLED_DRAFT17, SettingsId.WT_ENABLED_DRAFT16, SettingsId.WT_MAX_SESSIONS_DRAFT14)

    /**
     * A pair whose session runs draft-02 ([draft02]) or draft-17, and [block] with the client's and the server's session.
     * [resetStreamAt] turns `reset_stream_at` on for a draft-02 connection too, so a raw stream can keep the bytes of a
     * header it was reset in (draft-17 needs it anyway, section 3.1). [before] runs on the pair before the session exists.
     */
    private fun pair(
        draft02: Boolean,
        resetStreamAt: Boolean = !draft02,
        before: suspend (H3Pair) -> Unit = {},
        block: suspend CoroutineScope.(H3Pair, WebTransportSession, WebTransportSession) -> Unit,
    ) = h3Test {
        if (draft02) H3Session.createdForTest = { it.ourSettingsForTest = { l -> l.filter { (id, _) -> id !in draft02Only } } }
        try {
            // draft-02 without reset_stream_at, as browsers
            val quic = if (resetStreamAt) H3Fixtures.quic else QuicConfig.Default
            // no reserved streams: the server's count of dropped unidirectional streams is the test's alone
            val settings = wtOn.toBuilder().apply { expert { grease = false } }.build()
            H3Pair
                .open(clientSettings = settings, serverSettings = settings, serverQuic = quic, clientQuic = quic)
                .useScoped { p ->
                    before(p)
                    val (client, server) = sessions(p)
                    assertEquals(if (draft02) WtVersion.Draft02 else WtVersion.Draft17, (client as WtSessionImpl).version)
                    block(p, client, server)
                }
        } finally {
            H3Session.createdForTest = null
        }
    }

    /** The application code of the reset [s] reads. */
    private suspend fun resetCode(s: WebTransportReceiveStream): Long? =
        causeOf<WebTransportException.StreamReset> { withTimeout(10.seconds) { s.input.readAllBytes() } }.code

    /** A unidirectional stream reset before any byte, and one reset inside its type, reach the server's session. */
    @Test fun aUniStreamResetBeforeItsHeaderReachesTheOnlyDraft02Session() =
        pair(draft02 = true) { p, _, server ->
            p.client.quic
                .openUni()
                .reset(WtErrorCodes.toHttp3(7))
            assertEquals<Long?>(7L, resetCode(withTimeout(10.seconds) { server.acceptUni() }))
            val u = p.client.quic.openUni()
            u.output.writeFully(byteArrayOf(0x40)) // the first byte of the two-byte type 0x54
            u.output.flush()
            u.reset(WtErrorCodes.toHttp3(8))
            assertEquals<Long?>(8L, resetCode(withTimeout(10.seconds) { server.acceptUni() }))
        }

    /** A bidirectional stream reset before its signal reaches the server's session, not the request handler. */
    @Test fun aBidiStreamResetBeforeItsSignalReachesTheOnlyDraft02Session() =
        pair(draft02 = true) { p, _, server ->
            p.client.quic
                .openBidi()
                .reset(WtErrorCodes.toHttp3(9))
            assertEquals<Long?>(9L, resetCode(withTimeout(10.seconds) { server.acceptBidi() }))
        }

    /** The client's side: the server's streams reset before their header reach the client's session. */
    @Test fun theServersStreamsResetBeforeTheirHeaderReachTheOnlyDraft02Session() =
        pair(draft02 = true) { p, client, _ ->
            p.server.quic
                .openUni()
                .reset(WtErrorCodes.toHttp3(10))
            assertEquals<Long?>(10L, resetCode(withTimeout(10.seconds) { client.acceptUni() }))
            p.server.quic
                .openBidi()
                .reset(WtErrorCodes.toHttp3(11))
            assertEquals<Long?>(11L, resetCode(withTimeout(10.seconds) { client.acceptBidi() }))
        }

    /** A code outside the WebTransport range is no application's: the stream is dropped, as RFC 9114 section 6.2 lets it. */
    @Test fun negative_aResetBeforeTheHeaderWithAnHttp3CodeIsDropped() =
        pair(draft02 = true) { p, client, server ->
            p.client.quic
                .openUni()
                .reset(Http3ErrorCode.REQUEST_CANCELLED)
            nextUniIsTheWrittenOne(p.server, client, server)
        }

    /**
     * A draft-17 connection may carry several sessions (its flow control), so it has no only session to own the code; its
     * peer keeps the header with RESET_STREAM_AT anyway (section 4.4). The stream is dropped.
     */
    @Test fun negative_aResetBeforeTheHeaderOnADraft17ConnectionIsDropped() =
        pair(draft02 = false) { p, client, server ->
            p.client.quic
                .openUni()
                .reset(WtErrorCodes.toHttp3(7))
            nextUniIsTheWrittenOne(p.server, client, server)
        }

    /**
     * The route site: a unidirectional stream whose type arrived and the first byte of its two-byte Session ID, reset there
     * (RESET_STREAM_AT keeps the three bytes, so the server reads them before the reset), reaches the session.
     */
    @Test fun aUniStreamResetInsideItsSessionIdReachesTheOnlyDraft02Session() =
        pair(draft02 = true, resetStreamAt = true) { p, _, server ->
            val u = p.client.quic.openUni()
            u.output.writeFully(byteArrayOf(0x40, 0x54, 0x40))
            u.output.flush()
            u.resetAt(WtErrorCodes.toHttp3(12), 3)
            assertEquals<Long?>(12L, resetCode(withTimeout(10.seconds) { server.acceptUni() }))
        }

    /** The same on a bidirectional stream: its `WT_STREAM` signal (0x40 0x41) and a first Session ID byte, then the reset. */
    @Test fun aBidiStreamResetInsideItsSessionIdReachesTheOnlyDraft02Session() =
        pair(draft02 = true, resetStreamAt = true) { p, _, server ->
            val b = p.client.quic.openBidi()
            b.output.writeFully(byteArrayOf(0x40, 0x41, 0x40))
            b.output.flush()
            b.resetAt(WtErrorCodes.toHttp3(12), 3)
            assertEquals<Long?>(12L, resetCode(withTimeout(10.seconds) { server.acceptBidi() }))
        }

    /**
     * A type whose first byte already rules out 0x54 (0x41: a two-byte varint of at least 0x100) is visibly no
     * WebTransport stream: dropped.
     */
    @Test fun negative_aUniStreamOfAnotherTypeResetInsideItIsDropped() =
        pair(draft02 = true, resetStreamAt = true) { p, client, server ->
            val u = p.client.quic.openUni()
            u.output.writeFully(byteArrayOf(0x41))
            u.output.flush()
            u.resetAt(WtErrorCodes.toHttp3(7), 1)
            nextUniIsTheWrittenOne(p.server, client, server)
        }

    /**
     * A first byte of 0x80 with zero value bits starts a four-byte varint that can still be 0x54 (0x80 0x00 0x00 0x54:
     * RFC 9000 section 16 does not require the shortest encoding, and the critical types are read the same way), so the
     * reset in it reaches the session.
     */
    @Test fun aUniStreamResetInsideALongerEncodingOf0x54ReachesTheOnlyDraft02Session() =
        pair(draft02 = true, resetStreamAt = true) { p, _, server ->
            val u = p.client.quic.openUni()
            u.output.writeFully(byteArrayOf(0x80.toByte(), 0x00))
            u.output.flush()
            u.resetAt(WtErrorCodes.toHttp3(13), 2)
            assertEquals<Long?>(13L, resetCode(withTimeout(10.seconds) { server.acceptUni() }))
        }

    /** The server's request path: a client bidirectional stream reset with an HTTP/3 code before its first frame is no session's. */
    @Test fun negative_aBidiStreamResetWithAnHttp3CodeBeforeItsFirstFrameIsDropped() =
        pair(draft02 = true) { p, client, server ->
            val handled = spends(p.server)
            p.client.quic
                .openBidi()
                .reset(Http3ErrorCode.REQUEST_CANCELLED)
            withTimeout(10.seconds) { handled.await() } // the abandoned request was counted: the server is done with it
            nextBidiIsTheOpenedOne(client, server)
        }

    /**
     * A client bidirectional stream below the session's CONNECT stream was opened before the session: its reset, though
     * with a WebTransport code, is none of the session's (it stays the request it may have been).
     */
    @Test fun negative_aBidiStreamBelowTheConnectStreamIsNoneOfTheSessions() {
        var early: QuicStream? = null
        pair(draft02 = true, before = { early = it.client.quic.openBidi() }) { p, client, server ->
            val e = early!!
            assertTrue(e.id < client.sessionId, "${e.id} < ${client.sessionId}")
            val handled = spends(p.server)
            e.reset(WtErrorCodes.toHttp3(7))
            withTimeout(10.seconds) { handled.await() } // the abandoned request was counted: the server is done with it
            nextBidiIsTheOpenedOne(client, server)
        }
    }

    /** The client's path: a server bidirectional stream reset with an HTTP/3 code before its signal is dropped as a glitch. */
    @Test fun negative_aServerBidiStreamResetWithAnHttp3CodeIsDropped() =
        pair(draft02 = true) { p, client, server ->
            val glitched = spends(p.client)
            p.server.quic
                .openBidi()
                .reset(Http3ErrorCode.REQUEST_CANCELLED)
            withTimeout(10.seconds) { glitched.await() }
            val out = server.openBidi()
            out.output.writeFully("next".encodeToByteArray())
            out.output.flush()
            assertEquals(out.streamId, withTimeout(10.seconds) { client.acceptBidi() }.streamId)
        }

    /** draft-02 section 4.3 limits a stream's codes to 8 bits: 256 is refused on reset and STOP_SENDING, 255 goes. */
    @Test fun negative_aDraft02ResetAbove255IsRefused() =
        pair(draft02 = true) { _, client, server ->
            val out = client.openBidi()
            assertFailsWith<IllegalArgumentException> { out.reset(256) }
            assertFailsWith<IllegalArgumentException> { out.reset(256, reliableOffset = 0) }
            assertFailsWith<IllegalArgumentException> { out.stopSending(256) }
            out.output.writeFully("x".encodeToByteArray())
            out.output.flush()
            val st = withTimeout(10.seconds) { server.acceptBidi() }
            out.reset(255)
            assertEquals<Long?>(255L, resetCode(st))
        }

    /**
     * A peer's code above 255 on a draft-02 session is no application code there: a stream with its header reads it as
     * `StreamReset(null)`, and one reset before its header is dropped, as a code outside the range is.
     */
    @Test fun negative_aDraft02StreamCodeAbove255IsNoApplicationCode() =
        pair(draft02 = true) { p, client, server ->
            val u = p.client.quic.openUni()
            u.output.writeFully(VarInt.encode(StreamType.WT_UNI) + VarInt.encode(client.sessionId))
            u.output.flush()
            val st = withTimeout(10.seconds) { server.acceptUni() }
            u.reset(WtErrorCodes.toHttp3(256))
            assertNull(resetCode(st))
            p.client.quic
                .openUni()
                .reset(WtErrorCodes.toHttp3(256))
            nextUniIsTheWrittenOne(p.server, client, server)
        }

    /**
     * Completes when [h3] next spends a token of its glitch or reset budget (it reads its clock then): the evidence that a
     * stream it drops was handled, so a stream opened afterwards cannot overtake it.
     */
    private fun spends(h3: Http3Connection): CompletableDeferred<Unit> {
        val spent = CompletableDeferred<Unit>()
        val clock = h3.session.glitchClock
        h3.session.glitchClock = {
            spent.complete(Unit)
            clock()
        }
        return spent
    }

    /** Later drafts keep the 32-bit stream codes: 2^32-1 on a reset and 256 on STOP_SENDING read back as sent. */
    @Test fun negative_theEightBitLimitStaysOffDraft17() =
        pair(draft02 = false) { _, client, server ->
            assertEquals(0xffffffffL, client.maxStreamErrorCode)
            assertEquals(0xffffffffL, server.maxStreamErrorCode)
            val out = client.openBidi()
            out.output.writeFully("x".encodeToByteArray())
            out.output.flush()
            val st = withTimeout(10.seconds) { server.acceptBidi() }
            out.reset(0xffffffffL)
            assertEquals<Long?>(0xffffffffL, resetCode(st))
            val out2 = client.openBidi()
            out2.output.writeFully("y".encodeToByteArray())
            out2.output.flush()
            withTimeout(10.seconds) { server.acceptBidi() }.stopSending(256)
            val stopped =
                causeOf<WebTransportException.StreamStopped> {
                    withTimeout(10.seconds) {
                        while (true) {
                            out2.output.writeFully(ByteArray(1024))
                            out2.output.flush()
                        }
                    }
                }
            assertEquals<Long?>(256L, stopped.code)
        }

    /** A draft-02 session's close code is 32-bit (draft-02 section 5: "Application Error Code: A 32-bit error code"). */
    @Test fun aDraft02SessionClosesWithA32BitCode() =
        pair(draft02 = true) { _, client, server ->
            assertEquals(255L, client.maxStreamErrorCode)
            assertEquals(255L, server.maxStreamErrorCode)
            client.close(0xffffffffL, "bye")
            val info = withTimeout(10.seconds) { server.closed.await() }
            assertEquals(0xffffffffL, info.code)
            assertEquals("bye", info.reason)
        }

    /** The server's next bidirectional stream is one the client opens now: nothing before it reached the session. */
    private suspend fun nextBidiIsTheOpenedOne(
        client: WebTransportSession,
        server: WebTransportSession,
    ) {
        val out = client.openBidi()
        out.output.writeFully("next".encodeToByteArray())
        out.output.flush()
        assertEquals(out.streamId, withTimeout(10.seconds) { server.acceptBidi() }.streamId)
    }

    /** [h3] dropped the client's headerless stream: the server's next stream is one the client then writes. */
    private suspend fun nextUniIsTheWrittenOne(
        h3: Http3Connection,
        client: WebTransportSession,
        server: WebTransportSession,
    ) {
        withTimeout(10.seconds) { h3.session.discardedUniStreams.first { it >= 1 } }
        assertEquals(1, h3.session.discardedUniStreams.value)
        val out = client.openUni()
        out.output.writeFully("next".encodeToByteArray())
        out.output.flushAndClose()
        assertContentEquals("next".encodeToByteArray(), withTimeout(10.seconds) { server.acceptUni().input.readAllBytes() })
    }
}
