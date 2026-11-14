// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.wire.ConnectionId
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The bounded memory of moved connections' IDs that get no Stateless Reset on the original address (RFC 9000 sections 9.6.2, 10.3). */
class LeftAddressIdsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val t0 = TimeMark(1_000_000_000L)

    private fun id(
        owner: Int,
        n: Int,
    ) = ConnectionId(ByteArray(8) { if (it == 0) owner.toByte() else n.toByte() })

    /** Looks [cid] up as a datagram's DCID would be: from a buffer, at an offset. */
    private fun LeftAddressIds.has(
        cid: ConnectionId,
        now: TimeMark = t0,
    ): Boolean {
        val bytes = byteArrayOf(0x40) + cid.toByteArray() + ByteArray(20)
        val b = PacketBuffer.of(bytes)
        try {
            return contains(b, 1, cid.length, now)
        } finally {
            b.close()
        }
    }

    @Test fun rememberedUntilItsDeadline() {
        val ids = LeftAddressIds(capacity = 16, perConnection = 4)
        val a = Any()
        ids.add(id(1, 1), a, t0 + 10.seconds, t0)
        assertTrue(ids.has(id(1, 1)))
        assertFalse(ids.has(id(1, 2)), "another ID")
        assertFalse(ids.has(id(1, 1), t0 + 10.seconds), "expired at its deadline")
        assertEquals(0, ids.size, "and forgotten")
    }

    @Test fun negative_oneConnectionCannotPushOutTheOthers() {
        // a moved client that retires ID after ID keeps at most perConnection of its own, its oldest going first; another connection's
        // IDs stay
        val ids = LeftAddressIds(capacity = 8, perConnection = 3)
        val victim = Any()
        val churner = Any()
        ids.add(id(1, 1), victim, t0 + 60.seconds, t0)
        for (n in 1..20) ids.add(id(2, n), churner, t0 + 60.seconds, t0)
        assertTrue(ids.has(id(1, 1)), "the other connection's ID is kept")
        assertEquals(4, ids.size)
        assertTrue((18..20).all { ids.has(id(2, it)) }, "the churner's newest three")
        assertFalse(ids.has(id(2, 17)), "its older ones went first")
    }

    @Test fun boundedInAll() {
        val ids = LeftAddressIds(capacity = 4, perConnection = 4)
        for (n in 1..6) ids.add(id(n, 1), Any(), t0 + 60.seconds, t0)
        assertEquals(4, ids.size)
        assertFalse(ids.has(id(1, 1)), "the oldest went first")
        assertTrue(ids.has(id(6, 1)))
    }

    @Test fun expiredIdsGoWhenOneIsAdded() {
        val ids = LeftAddressIds(capacity = 16, perConnection = 4)
        ids.add(id(1, 1), Any(), t0 + 1.seconds, t0)
        ids.add(id(2, 1), Any(), t0 + 1.seconds, t0)
        ids.add(id(3, 1), Any(), t0 + 60.seconds, t0 + 2.seconds)
        assertEquals(1, ids.size)
    }
}
