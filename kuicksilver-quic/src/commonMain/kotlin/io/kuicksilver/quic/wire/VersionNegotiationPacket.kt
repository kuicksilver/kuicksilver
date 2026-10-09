// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

import io.kuicksilver.native.PacketBuffer

/** Version Negotiation packets (RFC 9000 section 17.2.1): version 0, CIDs echoed back swapped, then supported versions. */
internal object VersionNegotiationPacket {
    /** Writes a VN packet into [out]; [versions] are truncated so the packet never exceeds [maxLength]. Returns the length. */
    fun write(
        out: PacketBuffer,
        dcid: PacketBuffer,
        dcidOff: Int,
        dcidLen: Int,
        scid: PacketBuffer,
        scidOff: Int,
        scidLen: Int,
        versions: IntArray,
        firstByteRandom: Int,
        maxLength: Int,
    ): Int {
        val w = WireWriter(out, 0, minOf(out.capacity, maxLength))
        w.u8(0x80 or (firstByteRandom and 0x7f))
        w.u32(0)
        w.u8(dcidLen)
        w.copy(dcid, dcidOff, dcidLen)
        w.u8(scidLen)
        w.copy(scid, scidOff, scidLen)
        for (v in versions) {
            if (w.remaining < 4) break
            w.u32(v.toLong() and 0xffffffffL)
        }
        return w.pos
    }

    /** The versions listed after the CIDs of a VN packet. */
    fun versions(
        buf: PacketBuffer,
        off: Int,
        end: Int,
    ): IntArray {
        val n = (end - off) / 4
        val r = WireReader(buf, off, end)
        return IntArray(n) { r.u32().toInt() }
    }
}
