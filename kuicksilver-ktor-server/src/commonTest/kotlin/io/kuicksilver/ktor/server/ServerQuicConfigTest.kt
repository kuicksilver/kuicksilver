// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.quicConfig
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** How `quic` and `quicMaxIdleTimeout` combine into the HTTP/3 listeners' QUIC settings. */
class ServerQuicConfigTest {
    @Test fun quicMaxIdleTimeoutAppliesWhileQuicIsUnset() {
        val c = KuicksilverApplicationEngine.Configuration().apply { quicMaxIdleTimeout = 7.seconds }
        assertEquals(7.seconds, c.http3Quic().maxIdleTimeout)
    }

    /** Assigning [QuicConfig.Default] is setting `quic`: it carries its own timeout, as any other assigned value does. */
    @Test fun quicAssignedTheDefaultIsSetToo() {
        val c =
            KuicksilverApplicationEngine.Configuration().apply {
                quicMaxIdleTimeout = 7.seconds
                quic = QuicConfig.Default
            }
        assertEquals(QuicConfig.Default.maxIdleTimeout, c.http3Quic().maxIdleTimeout)
    }

    /** The order of the two assignments does not matter. */
    @Test fun quicSetBeforeOrAfterTheTimeoutWins() {
        val explicit = quicConfig { maxIdleTimeout = 20.seconds }
        val before =
            KuicksilverApplicationEngine.Configuration().apply {
                quic = explicit
                quicMaxIdleTimeout = 7.seconds
            }
        val after =
            KuicksilverApplicationEngine.Configuration().apply {
                quicMaxIdleTimeout = 7.seconds
                quic = explicit
            }
        assertEquals(20.seconds, before.http3Quic().maxIdleTimeout)
        assertEquals(20.seconds, after.http3Quic().maxIdleTimeout)
    }

    /**
     * HTTP/3 needs the client to be able to open three unidirectional streams (RFC 9114 section 6.2): a server whose QUIC
     * settings grant fewer does not start, unless it serves no HTTP/3.
     */
    @Test fun negative_fewerThanThreeUniStreamsAreRefused() =
        serverTest {
            val e =
                assertFailsWith<IllegalArgumentException> {
                    val (server, _) = tlsServer({ quic = quicConfig { maxUniStreams = 2 } }) {}
                    server.stop(100, 500)
                }
            assertTrue("RFC 9114 section 6.2" in e.message.orEmpty(), e.message)
            val (server, _) =
                tlsServer({
                    http3 = false
                    quic = quicConfig { maxUniStreams = 2 }
                }) {}
            server.stop(100, 500)
        }

    @Test fun nothingSetKeepsTheDefault() {
        assertEquals(QuicConfig.Default, KuicksilverApplicationEngine.Configuration().http3Quic())
    }
}
