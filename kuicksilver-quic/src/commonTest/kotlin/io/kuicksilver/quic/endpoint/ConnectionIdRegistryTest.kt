// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.wire.ConnectionId
import kotlin.test.Test
import kotlin.test.assertNull
import kotlin.test.assertSame

class ConnectionIdRegistryTest {
    @Test fun aKeyAddedFromTheIdIsFoundInsideAPacket() {
        // add keys from the ID's heap copy, lookup hashes the packet's bytes where its DCID sits (1 in a short header, 6 in a long one)
        val p = CorePair()
        try {
            val r = ConnectionIdRegistry(0x1234L, 0x5678L)
            for (len in 0..20) {
                val id = ByteArray(len) { (it * 13 + len).toByte() }
                r.add(ConnectionId(id), p.client)
                for (off in intArrayOf(1, 6)) {
                    val packet = PacketBuffer.allocate(off + len + 1)
                    try {
                        packet.copyFrom(id, 0, off, len)
                        assertSame(p.client, r.lookup(packet, off, len), "len $len at $off")
                        if (len > 0) assertNull(r.lookup(packet, off + 1, len), "len $len one byte later")
                    } finally {
                        packet.close()
                    }
                }
            }
        } finally {
            p.close()
        }
    }

    @Test fun addRemoveAndRemoveAllAgreeWithAModel() = agreesWithAModel(-1L)

    /** Every ID's 64-bit key reduced to 3 bits: IDs share a key and a bucket, as two whose SipHash collides would. */
    @Test fun idsSharingAKeyAgreeWithAModel() = agreesWithAModel(7L)

    private fun agreesWithAModel(keyMask: Long) {
        // the open-addressed table against a plain map: growth, backward-shift deletion and the rebuild in removeAll; 4-byte
        // IDs keep the table small enough that probe runs wrap and collide
        val p = CorePair()
        val q = CorePair()
        val packet = PacketBuffer.allocate(32)
        try {
            val r = ConnectionIdRegistry(0x1234L, 0x5678L, keyMask)
            val model = HashMap<List<Byte>, io.kuicksilver.quic.ConnectionCore>()
            val rnd = kotlin.random.Random(7)
            repeat(20_000) { step ->
                val id = ByteArray(4) { rnd.nextInt(0, 3).toByte() }.also { it[0] = rnd.nextInt(0, 40).toByte() }
                val core = if (rnd.nextBoolean()) p.client else q.client
                when (rnd.nextInt(10)) {
                    in 0..4 -> {
                        if (id.toList() !in model) {
                            r.add(ConnectionId(id), core)
                            model[id.toList()] = core
                        }
                    }

                    in 5..8 -> {
                        r.remove(ConnectionId(id))
                        model.remove(id.toList())
                    }

                    else -> {
                        if (step % 50 == 0) {
                            r.removeAll(core)
                            model.values.removeAll { it === core }
                        }
                    }
                }
                packet.copyFrom(id, 0, 3, 4)
                assertSame(model[id.toList()], r.lookup(packet, 3, 4), "step $step")
                kotlin.test.assertEquals(model.size, r.size, "size at step $step")
            }
            for ((k, v) in model) {
                packet.copyFrom(k.toByteArray(), 0, 3, 4)
                assertSame(v, r.lookup(packet, 3, 4))
            }
        } finally {
            packet.close()
            p.close()
            q.close()
        }
    }
}
