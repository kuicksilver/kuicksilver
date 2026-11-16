// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(DelicateKuicksilverApi::class, ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.core.release
import io.kuicksilver.quic.endpoint.EndpointPair
import io.kuicksilver.tls.KslQuicCrypto
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The core fixtures fail their close() when a test leaks native state: [CorePair] and [EndpointPair] count every object
 * the crypto provider hands out ([LeakTrackingCrypto]) and the [PacketBuffer]s of the thread ([BufferWatch]).
 */
class FixtureLeakTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun aPairThatEndsCleanlyCloses() {
        val p = CorePair(crypto = KslQuicCrypto)
        assertTrue(p.handshake())
        p.close()
        p.close() // a second close checks nothing more
    }

    @Test fun overlappingPairsCloseInEitherOrder() {
        val a = CorePair()
        val b = EndpointPair()
        a.close() // b is still open, with its batch: the buffers of overlapping fixtures are not judged
        val c = CorePair()
        b.close()
        c.close()
    }

    @Test fun negative_aPairLeftOpenEarlierDoesNotHideALeak() {
        val earlier = CorePair() // an earlier test's pair, never closed
        val p = CorePair()
        val b = PacketBuffer.allocate(16)
        try {
            val e = assertFailsWith<AssertionError> { p.close() }
            assertContains(e.message.orEmpty(), "1 PacketBuffer(s) left open on this thread")
        } finally {
            b.close()
            earlier.close()
        }
    }

    @Test fun negative_aKeyLeftOpenFailsThePairsClose() {
        val p = CorePair(crypto = KslQuicCrypto)
        val key = p.leaks.newResetKey()
        try {
            val e = assertFailsWith<AssertionError> { p.close() }
            assertContains(e.message.orEmpty(), "reset key")
        } finally {
            key.close()
        }
    }

    @Test fun negative_aBufferLeftOpenFailsThePairsClose() {
        val p = CorePair()
        val b = PacketBuffer.allocate(16)
        try {
            val e = assertFailsWith<AssertionError> { p.close() }
            assertContains(e.message.orEmpty(), "1 PacketBuffer(s) left open on this thread")
        } finally {
            b.close()
        }
    }

    /** A connection taken out of its endpoint without its release keeps its TLS session and keys: the endpoints' close fails. */
    @Test fun negative_aRemovedConnectionNotReleasedFailsTheEndpointsClose() {
        val p = EndpointPair(crypto = KslQuicCrypto)
        val c = p.connect()
        assertTrue(p.confirmed(c))
        val s = p.server.connections().single()
        s.close(0, "", p.now)
        p.server.remove(s)
        try {
            val e = assertFailsWith<AssertionError> { p.close() }
            assertContains(e.message.orEmpty(), "session Server")
        } finally {
            s.release()
        }
    }

    @Test fun aRemovedConnectionReleasedThroughThePairCloses() {
        val p = EndpointPair(crypto = KslQuicCrypto)
        val c = p.connect()
        assertTrue(p.confirmed(c))
        val s = p.server.connections().single()
        s.close(0, "", p.now)
        p.remove(p.server, s)
        p.close()
    }
}
