// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ClosedWriteChannelException
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.time.Duration.Companion.seconds

/**
 * How a session coroutine's failure ends the connection ([H3Session.guarded]): one caused by this session's own lost
 * transport leaves the end to the transport's close, any other is an H3_INTERNAL_ERROR of ours.
 */
class GuardedTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * The peer closed with H3_NO_ERROR and a session coroutine fails with ktor-io's wrapper of that loss (a
     * ClosedWriteChannelException) before the session's watcher of the transport ran: the end is the peer's H3_NO_ERROR,
     * not an H3_INTERNAL_ERROR of ours (which also made a client mark the alternative broken on a mere peer close). The
     * order is fixed: the failure runs on the session dispatcher, and the watcher, woken by the transport's end, is queued
     * behind it. Red before: the session closed with H3_INTERNAL_ERROR.
     */
    @Test fun aFailureCausedByThisSessionsLostTransportLeavesTheEndToTheTransport() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, _) = q.connect()
                val end = CompletableDeferred<QuicException.ConnectionLost>()
                val transport =
                    object : QuicConnection by c {
                        override val closed: Deferred<QuicException.ConnectionLost> get() = end
                    }
                val client = withTimeout(10.seconds) { Http3Connection.client(transport) }
                val session = client.session
                withContext(session.dispatcher) {
                    end.complete(QuicException.ConnectionLost.ApplicationClosed(Http3ErrorCode.NO_ERROR, "", Initiator.Peer))
                    session.guarded { throw ClosedWriteChannelException(end.getCompleted()) }
                }
                val e = assertIs<Http3Exception.Protocol>(withTimeout(10.seconds) { client.closed.await() })
                assertEquals(Http3ErrorCode.NO_ERROR, e.h3Code, "$e")
                assertEquals(Initiator.Peer, e.initiator)
                c.close(Http3ErrorCode.NO_ERROR, "")
            }
        }

    /**
     * A ConnectionLost that is not this session's (a handler relaying to another connection, whose loss it lets through)
     * while this session's transport is up is a failure of ours: the connection closes with H3_INTERNAL_ERROR, nothing is
     * left waiting unanswered.
     */
    @Test fun negative_aLostConnectionOfAnotherConnectionIsAnInternalError() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, _) = q.connect()
                val client = withTimeout(10.seconds) { Http3Connection.client(c) }
                client.session.guarded { throw ClosedWriteChannelException(QuicException.ConnectionLost.StatelessReset()) }
                val e = assertIs<Http3Exception.Protocol>(withTimeout(10.seconds) { client.closed.await() })
                assertEquals(Http3ErrorCode.INTERNAL_ERROR, e.h3Code, "$e")
                assertEquals(Initiator.Local, e.initiator)
            }
        }
}
