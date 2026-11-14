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
        length: Int = 8,
    ) = ConnectionId(ByteArray(length) { if (it == 0) owner.toByte() else n.toByte() })

    /** Looks [cid] up as a datagram's DCID would be: from a buffer, at an offset, [len] bytes. */
    private fun LeftAddressIds.has(
        cid: ConnectionId,
        now: TimeMark = t0,
        len: Int = cid.length,
    ): Boolean {
        val bytes = byteArrayOf(0x40) + cid.toByteArray() + ByteArray(32)
        val b = PacketBuffer.of(bytes)
        try {
            return contains(b, 1, len, now)
        } finally {
            b.close()
        }
    }

    private fun LeftAddressIds.add(
        cid: ConnectionId,
        owner: Long,
        until: TimeMark,
        ownerCap: Int = 8,
        primary: Boolean = false,
        now: TimeMark = t0,
    ) = add(cid, owner, ownerCap, primary, until, now)

    @Test fun rememberedUntilItsDeadline() {
        val ids = LeftAddressIds(capacity = 16)
        ids.add(id(1, 1), 1L, t0 + 10.seconds)
        assertTrue(ids.has(id(1, 1)))
        assertFalse(ids.has(id(1, 2)), "another ID")
        assertFalse(ids.has(id(1, 1), t0 + 10.seconds), "expired at its deadline")
        assertEquals(0, ids.size, "and forgotten")
    }

    @Test fun idsOfOtherLengthsAreOtherIds() {
        val ids = LeftAddressIds(capacity = 16)
        ids.add(id(1, 1, length = 8), 1L, t0 + 10.seconds)
        ids.add(id(1, 1, length = 4), 1L, t0 + 10.seconds)
        assertEquals(2, ids.size)
        assertTrue(ids.has(id(1, 1, length = 8)))
        assertTrue(ids.has(id(1, 1, length = 4)))
        assertFalse(ids.has(id(1, 1, length = 8), len = 6), "a prefix of a remembered ID")
        assertFalse(ids.has(id(1, 1, length = 12)), "a longer one")
    }

    @Test fun negative_lookupLongerThanAnIdIsRejected() {
        // RFC 9000 section 17.2: at most 20 bytes; a longer length (a header parsed with another ID length) never matches or overruns
        val ids = LeftAddressIds(capacity = 16)
        ids.add(id(1, 1, length = 20), 1L, t0 + 10.seconds)
        assertTrue(ids.has(id(1, 1, length = 20)))
        assertFalse(ids.has(id(1, 1, length = 20), len = 21), "21 bytes from the same buffer")
    }

    @Test fun negative_oneConnectionCannotPushOutTheOthers() {
        // a moved client that retires ID after ID keeps at most its cap of its own, its oldest going first; another connection's IDs stay
        val ids = LeftAddressIds(capacity = 8)
        ids.add(id(1, 1), 1L, t0 + 60.seconds)
        for (n in 1..20) ids.add(id(2, n), 2L, t0 + 60.seconds, ownerCap = 3)
        assertTrue(ids.has(id(1, 1)), "the other connection's ID is kept")
        assertEquals(4, ids.size)
        assertTrue((18..20).all { ids.has(id(2, it)) }, "the churner's newest three")
        assertFalse(ids.has(id(2, 17)), "its older ones went first")
    }

    @Test fun negative_aSnapshotOverEightKeepsItsOldPathId() {
        // a connection that moved holding 12 IDs (8 live and 4 retired still routing): all are kept, the cap is its snapshot's size;
        // and past the cap the primary (the client's ID on the original path) outlives the others
        val ids = LeftAddressIds(capacity = 64)
        ids.add(id(1, 0), 1L, t0 + 60.seconds, ownerCap = 12, primary = true)
        for (n in 1..11) ids.add(id(1, n), 1L, t0 + 60.seconds, ownerCap = 12)
        assertEquals(12, ids.size)
        assertTrue((0..11).all { ids.has(id(1, it)) })
        ids.add(id(1, 12), 1L, t0 + 60.seconds, ownerCap = 12)
        assertTrue(ids.has(id(1, 0)), "the primary stays")
        assertFalse(ids.has(id(1, 1)), "the oldest other one goes")
        assertEquals(12, ids.size)
    }

    @Test fun negative_aFullMemoryDropsAnExpiredIdBeforeALiveOne() {
        // lifetimes differ by connection: an expired ID behind a live one goes first when the memory is full
        val ids = LeftAddressIds(capacity = 2)
        ids.add(id(1, 1), 1L, t0 + 100.seconds)
        ids.add(id(2, 1), 2L, t0 + 1.seconds)
        ids.add(id(3, 1), 3L, t0 + 100.seconds, now = t0 + 2.seconds)
        assertEquals(2, ids.size)
        assertTrue(ids.has(id(1, 1), t0 + 2.seconds), "the older live one is kept")
        assertTrue(ids.has(id(3, 1), t0 + 2.seconds))
    }

    @Test fun boundedInAll() {
        val ids = LeftAddressIds(capacity = 4)
        for (n in 1..6) ids.add(id(n, 1), n.toLong(), t0 + 60.seconds)
        assertEquals(4, ids.size)
        assertFalse(ids.has(id(1, 1)), "the oldest went first")
        assertTrue(ids.has(id(6, 1)))
    }

    @Test fun expiredIdsGoWhenOneIsAdded() {
        val ids = LeftAddressIds(capacity = 16)
        ids.add(id(1, 1), 1L, t0 + 1.seconds)
        ids.add(id(2, 1), 2L, t0 + 1.seconds)
        ids.add(id(3, 1), 3L, t0 + 60.seconds, now = t0 + 2.seconds)
        assertEquals(1, ids.size)
    }
}
