// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.PREFERRED_SOCKET
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.endpoint.EndpointPair
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * RFC 9000 section 9.3: "An endpoint MAY skip validation of a peer address if that address has been seen recently." When a peer
 * address was last seen is the later of its validation and its latest packet; one of the two unknown ([TimeMark.NEVER]) is not a later
 * time. The server took an address validated or heard from just now for one never seen and validated it again.
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class PathSeenRecentlyTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun serverOf(p: EndpointPair): ConnectionCore {
        val c = p.connect()
        assertTrue(p.confirmed(c))
        repeat(5) { p.step() }
        return p.server.connections().single()
    }

    private fun addValidated(
        s: ConnectionCore,
        socket: PathId,
        a: InetSocketAddress,
    ): Path {
        val q = s.paths.add(socket, a, s.config.congestionController(), s.config.newPathInitialRtt, evict = false)!!
        q.state = PathState.Validated
        q.validatedAt = s.now
        q.lastReceivedAt = s.now
        s.paths.lastValidated = q
        return q
    }

    /**
     * A failed active path reverts to the last validated peer address (section 9.3.2) through the path already there for that pair,
     * whose first validation was under way and which the client's packets reached just now: the address is validated (on the other
     * path) and seen recently, so the path is taken as validated, with no PATH_CHALLENGE of the abandoned validation left pending.
     */
    @Test fun negative_aRevertToAnAddressHeardJustNowSkipsItsValidation() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)
            val failed = s.paths.active
            val a = InetSocketAddress("10.0.0.8", 40008)
            addValidated(s, PREFERRED_SOCKET, a)
            // hand-built: onPathFailed is called on the handshake path, which is Validated and runs no validation (a real failure
            // comes from a validation deadline); k stands for a path the client's packets just reached, its own validation under way
            val k = s.paths.add(failed.socket, a, s.config.congestionController(), s.config.newPathInitialRtt, evict = false)!!
            k.local = failed.local
            s.startValidation(k)
            k.lastReceivedAt = s.now // never validated on this pair: validatedAt is unknown
            s.onPathFailed(failed)
            assertSame(k, s.paths.active)
            assertEquals(PathState.Validated, k.state, "seen recently: not validated again")
            assertFalse(k.challengePending, "the abandoned validation's challenge is not sent on a validated path")
            assertEquals(TimeMark.NEVER, k.challengeDeadline)
        } finally {
            p.close()
        }
    }

    /**
     * The address of the failed active path was validated just now on the preferred-address socket, and no packet arrived on that path
     * since (its latest one is unknown): seen recently, the connection keeps it as validated rather than validating it again.
     */
    @Test fun negative_anAddressValidatedJustNowWithNoPacketSinceCountsAsSeenRecently() {
        val p = EndpointPair()
        try {
            val s = serverOf(p)
            val failed = s.paths.active
            val q = addValidated(s, PREFERRED_SOCKET, failed.remote)
            q.peerProbed = true
            // hand-built: a Validated path with no packet recorded on it (lastReceivedAt unknown); a path validated by a PATH_RESPONSE
            // has received that packet, so this isolates the comparison of an unknown time with a known one
            q.lastReceivedAt = TimeMark.NEVER
            s.startValidation(failed)
            s.onPathFailed(failed)
            assertSame(failed, s.paths.active)
            assertEquals(PathState.Validated, failed.state, "validated just now: taken as validated")
            assertFalse(failed.challengePending)
        } finally {
            p.close()
        }
    }
}
