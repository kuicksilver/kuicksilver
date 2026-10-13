// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.VersionProfile
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PacketHeaderTest {
    private val dcid = ConnectionId(ByteArray(8) { (it + 1).toByte() })
    private val scid = ConnectionId(ByteArray(5) { (0x10 + it).toByte() })

    private fun parse(
        bytes: ByteArray,
        off: Int = 0,
        shortDcid: Int = 8,
    ): PacketHeaderView? {
        val b = PacketBuffer.of(bytes)
        try {
            val v = PacketHeaderView()
            return if (PacketHeaderCodec.parse(b, off, bytes.size, shortDcid, v)) v else null
        } finally {
            b.close()
        }
    }

    private fun long(
        profile: VersionProfile,
        type: PacketType,
        token: ByteArray? = null,
        pnLength: Int = 1,
        payload: Int = 20,
        grease: Boolean = false,
    ): ByteArray {
        val b = PacketBuffer.allocate(256)
        try {
            val w = WireWriter(b, 0, b.capacity)
            val lenOff = PacketHeaderCodec.writeLong(w, profile, type, dcid, scid, token, pnLength, grease)
            val pnOff = w.pos
            VarInt.writeFixed(b, lenOff, (pnLength + payload).toLong(), 2)
            w.zero(pnLength + payload)
            assertEquals(lenOff + 2, pnOff)
            return ByteArray(w.pos).also { b.copyTo(it, 0, 0, w.pos) }
        } finally {
            b.close()
        }
    }

    private fun short(
        pnLength: Int = 2,
        payload: Int = 30,
        grease: Boolean = false,
    ): ByteArray {
        val b = PacketBuffer.allocate(256)
        try {
            val w = WireWriter(b, 0, b.capacity)
            val pnOff = PacketHeaderCodec.writeShort(w, dcid, pnLength, spin = true, keyPhase = true, greaseFixedBit = grease)
            assertEquals(1 + 8, pnOff)
            w.zero(pnLength + payload)
            return ByteArray(w.pos).also { b.copyTo(it, 0, 0, w.pos) }
        } finally {
            b.close()
        }
    }

    @Test fun longHeaderRoundTripV1() {
        val v = parse(long(VersionProfile.V1, PacketType.Initial, token = byteArrayOf(9, 9, 9), pnLength = 3))!!
        assertEquals(PacketType.Initial, v.type)
        assertEquals(1, v.version)
        assertEquals(8, v.dcidLen)
        assertEquals(5, v.scidLen)
        assertEquals(3, v.tokenLen)
        assertTrue(v.fixedBitSet)
        assertFalse(v.unsupportedVersion)
        assertEquals(1 + 4 + 1 + 8 + 1 + 5 + 1 + 3 + 2, v.pnOffset)
        assertEquals(v.pnOffset + 23, v.packetEnd)
        val h = parse(long(VersionProfile.V1, PacketType.Handshake))!!
        assertEquals(PacketType.Handshake, h.type)
        assertEquals(0, h.tokenLen)
    }

    @Test fun v2LongHeaderTypeBits() {
        val v2 = long(VersionProfile.V2, PacketType.Initial)
        assertEquals(0b1101, (v2[0].toInt() and 0xff) ushr 4)
        assertEquals(PacketType.Initial, parse(v2)!!.type)
        val v1 = long(VersionProfile.V1, PacketType.Initial)
        assertEquals(0b1100, (v1[0].toInt() and 0xff) ushr 4)
        assertEquals(PacketType.Handshake, parse(long(VersionProfile.V2, PacketType.Handshake))!!.type)
        assertEquals(PacketType.ZeroRtt, parse(long(VersionProfile.V2, PacketType.ZeroRtt))!!.type)
    }

    @Test fun coalescedPacketsSplitByLength() {
        val a = long(VersionProfile.V1, PacketType.Initial, payload = 10)
        val b = long(VersionProfile.V1, PacketType.Handshake, payload = 7)
        val c = short(payload = 5)
        val all = a + b + c
        val buf = PacketBuffer.of(all)
        try {
            val v = PacketHeaderView()
            assertTrue(PacketHeaderCodec.parse(buf, 0, all.size, 8, v))
            assertEquals(PacketType.Initial, v.type)
            assertEquals(a.size, v.packetEnd)
            assertTrue(PacketHeaderCodec.parse(buf, v.packetEnd, all.size, 8, v))
            assertEquals(PacketType.Handshake, v.type)
            assertEquals(a.size + b.size, v.packetEnd)
            assertTrue(PacketHeaderCodec.parse(buf, v.packetEnd, all.size, 8, v))
            assertEquals(PacketType.OneRtt, v.type)
            assertEquals(all.size, v.packetEnd)
            assertEquals(a.size + b.size + 9, v.pnOffset)
        } finally {
            buf.close()
        }
    }

    @Test fun lengthBeyondDatagramDropsRemainder() {
        val a = long(VersionProfile.V1, PacketType.Initial, payload = 10)
        assertNull(
            parse(
                a.copyOf(a.size - 1),
            ),
        )
    }

    @Test fun cidLongerThan20InV1Dropped() {
        val a = long(VersionProfile.V1, PacketType.Initial)
        a[5] = 21
        assertNull(parse(a))
    }

    @Test fun fixedBitZeroDroppedUnlessGreaseAdvertised() {
        val a = long(VersionProfile.V1, PacketType.Initial, grease = true)
        assertEquals(0, a[0].toInt() and 0x40)
        assertFalse(parse(a)!!.fixedBitSet)
        val s = short(grease = true)
        assertEquals(0, s[0].toInt() and 0x40)
        assertFalse(parse(s)!!.fixedBitSet)
        assertTrue(parse(short())!!.fixedBitSet)
    }

    @Test fun unknownVersionFlagged() {
        val a = long(VersionProfile.V1, PacketType.Initial)
        a[1] = 0x0a
        a[2] = 0x0a
        a[3] = 0x0a
        a[4] = 0x0a
        val v = parse(a)!!
        assertTrue(v.unsupportedVersion)
        assertEquals(0x0a0a0a0a, v.version)
        assertEquals(8, v.dcidLen)
        assertEquals(5, v.scidLen)
        assertNull(v.type)
    }

    @Test fun negative_emptyUdpDatagram() {
        val b = PacketBuffer.allocate(16)
        try {
            assertFalse(PacketHeaderCodec.parse(b, 0, 0, 8, PacketHeaderView()))
        } finally {
            b.close()
        }
    }

    @Test fun versionNegotiationFormat() {
        val out = PacketBuffer.allocate(1200)
        val d = PacketBuffer.of(dcid.toByteArray())
        val s = PacketBuffer.of(scid.toByteArray())
        try {
            val n = VersionNegotiationPacket.write(out, s, 0, 5, d, 0, 8, intArrayOf(0x00000001, 0x6b3343cf), 0x5a, 1200)
            assertEquals(1 + 4 + 1 + 5 + 1 + 8 + 8, n)
            assertEquals(0x80, out[0].toInt() and 0x80)
            assertEquals(
                0x5a and 0x7f,
                out[0].toInt() and 0x7f,
            )
            val v = PacketHeaderView()
            assertTrue(PacketHeaderCodec.parse(out, 0, n, 8, v))
            assertTrue(v.isVersionNegotiation)
            assertEquals(0, v.version)
            assertEquals(5, v.dcidLen)
            assertEquals(8, v.scidLen)
            assertContentEquals(
                intArrayOf(1, 0x6b3343cf),
                VersionNegotiationPacket.versions(
                    out,
                    v.scidOff + v.scidLen,
                    n,
                ),
            )
        } finally {
            out.close()
            d.close()
            s.close()
        }
    }

    @Test fun versionNegotiationNeverLongerThanIncoming() {
        val out = PacketBuffer.allocate(1200)
        val d = PacketBuffer.of(dcid.toByteArray())
        val s = PacketBuffer.of(scid.toByteArray())
        try {
            val n = VersionNegotiationPacket.write(out, s, 0, 5, d, 0, 8, IntArray(400) { it + 1 }, 0, 1200)
            assertTrue(n <= 1200)
            assertEquals(
                0,
                (n - 20) % 4,
            )
        } finally {
            out.close()
            d.close()
            s.close()
        }
    }
}
