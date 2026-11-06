// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.wire.ConnectionId
import java.lang.management.ManagementFactory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Every received datagram is routed through [ConnectionIdRegistry.lookup]: it allocates nothing, hit or miss (P.2). */
class ConnectionIdRegistryAllocationTest {
    @Test fun lookupAllocatesNothing() {
        val p = CorePair()
        val packet = PacketBuffer.allocate(64)
        try {
            val r = ConnectionIdRegistry(0x1234L, 0x5678L)
            // enough IDs that the hashes are spread over the whole long range (a boxed key above 127 is a new object)
            val ids = Array(200) { i -> ByteArray(8) { (it * 31 + i * 7).toByte() } }
            for (id in ids) r.add(ConnectionId(id), p.client)
            val mx = ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean

            fun round(): Int {
                var hits = 0
                for (k in ids.indices) { // indices, not an iterator: the loop itself allocates nothing
                    val id = ids[k]
                    packet.copyFrom(id, 0, 1, id.size)
                    if (r.lookup(packet, 1, id.size) === p.client) hits++
                    if (r.lookup(packet, 2, id.size) != null) hits-- // a miss
                }
                return hits
            }
            // one round to load and link the classes, no JIT warm-up: the endpoint's lookup sits in a large method where the JIT's
            // escape analysis does not remove a boxed key (JFR showed Long.valueOf per datagram), while in a small loop like this
            // one it does; measured cold, a box is a box
            round()
            val before = mx.currentThreadAllocatedBytes
            var hits = 0
            repeat(100) { hits += round() }
            val bytes = mx.currentThreadAllocatedBytes - before
            assertEquals(100 * ids.size, hits)
            // the JIT's tiering steps allocate a few hundred bytes now and then while the loop is compiled (seen as single rounds of
            // 64-900 bytes among zeros); a boxed key costs 16 bytes per lookup, 640 000 here
            assertTrue(bytes <= 4096, "allocated $bytes bytes over ${2 * ids.size * 100} lookups")
            assertSame(p.client, r.lookup(packet, 1, 8))
            assertNull(r.lookup(packet, 0, 8))
        } finally {
            packet.close()
            p.close()
        }
    }

    @Test fun closingAConnectionInALargeTableAllocatesLittle() {
        // EndpointCore.remove calls removeAll for every closed connection, whose IDs are still registered: it must not rebuild
        // the table (a 32 768-slot table is about 400 KB per rebuild here; an attacker can churn connections)
        val p = CorePair()
        val q = CorePair()
        try {
            val r = ConnectionIdRegistry(0x1234L, 0x5678L)
            repeat(10_000) { i -> r.add(ConnectionId(ByteArray(8) { (i shr (8 * (it % 4))).toByte() }.also { it[7] = 1 }), q.client) }
            val mine = Array(4) { k -> ConnectionId(ByteArray(8) { (k * 37 + it).toByte() }.also { it[7] = 2 }) }
            val mx = ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean
            fun close() {
                for (k in mine.indices) r.add(mine[k], p.client)
                r.removeAll(p.client)
            }
            repeat(3) { close() } // classes loaded, scratch sized
            val before = mx.currentThreadAllocatedBytes
            repeat(50) { close() }
            val perClose = (mx.currentThreadAllocatedBytes - before) / 50
            // re-adding four IDs makes their buckets and entries (well under 1 KB); a rebuild is the whole table
            assertTrue(perClose <= 2048, "$perClose bytes per close")
            assertEquals(10_000, r.size)
        } finally {
            p.close()
            q.close()
        }
    }
}
