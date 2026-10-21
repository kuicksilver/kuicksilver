// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Role
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.quicConfig
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
