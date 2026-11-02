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
}
