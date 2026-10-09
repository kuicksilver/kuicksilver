// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

import io.kuicksilver.native.PacketBuffer

/** The parsed header of one packet inside a datagram; reused by the receiver. */
internal class PacketHeaderView {
    /** Null for a Version Negotiation packet or an unsupported version. */
    var type: PacketType? = null
    var version: Int = 0
    var dcidOff: Int = 0
    var dcidLen: Int = 0
    var scidOff: Int = 0
    var scidLen: Int = 0
    var tokenOff: Int = 0
    var tokenLen: Int = 0

    /** Offset of the packet number field (header protection starts here). */
    var pnOffset: Int = 0

    /** End of this packet; the next coalesced packet starts here. */
    var packetEnd: Int = 0
    var fixedBitSet: Boolean = true
    var unsupportedVersion: Boolean = false
    var isVersionNegotiation: Boolean = false
    var keyPhase: Boolean = false
    var spin: Boolean = false

    /** Retry: offset of the 16-byte integrity tag. */
    var retryTagOff: Int = 0
}

/** Reads and writes long and short headers (RFC 9000 section 17; RFC 9369 section 3.2 type bits). */
internal object PacketHeaderCodec {
    private const val FORM_LONG = 0x80
    private const val FIXED_BIT = 0x40

    /**
     * Parses the packet starting at [off]. Returns false when the datagram (or the rest of it) must be dropped
     * silently: too short, a CID longer than 20 bytes, or a Length beyond the datagram.
     */
    fun parse(
        buf: PacketBuffer,
        off: Int,
        datagramEnd: Int,
        shortDcidLength: Int,
        out: PacketHeaderView,
    ): Boolean {
        if (off >= datagramEnd) return false
        val first = buf[off].toInt() and 0xff
        out.fixedBitSet = first and FIXED_BIT != 0
        out.unsupportedVersion = false
        out.isVersionNegotiation = false
        out.type = null
        out.tokenLen = 0
        out.tokenOff = 0
        if (first and FORM_LONG == 0) {
            if (datagramEnd - off < 1 + shortDcidLength + 1) return false
            out.type = PacketType.OneRtt
            out.version = 0
            out.dcidOff = off + 1
            out.dcidLen = shortDcidLength
            out.scidOff = out.dcidOff
            out.scidLen = 0
            out.spin = first and 0x20 != 0
            out.keyPhase = first and 0x04 != 0
            out.pnOffset = off + 1 + shortDcidLength
            out.packetEnd = datagramEnd
            return true
        }
        if (datagramEnd - off < 7) return false
        var p = off + 1
        val version =
            ((buf[p].toInt() and 0xff) shl 24) or ((buf[p + 1].toInt() and 0xff) shl 16) or ((buf[p + 2].toInt() and 0xff) shl 8) or
                (buf[p + 3].toInt() and 0xff)
        p += 4
        out.version = version
        val dcidLen = buf[p].toInt() and 0xff
        p++
        if (p + dcidLen + 1 > datagramEnd) return false
        out.dcidOff = p
        out.dcidLen = dcidLen
        p += dcidLen
        val scidLen = buf[p].toInt() and 0xff
        p++
        if (p + scidLen > datagramEnd) return false
        out.scidOff = p
        out.scidLen = scidLen
        p += scidLen
        if (version == 0) {
            out.isVersionNegotiation = true
            out.pnOffset = p
            out.packetEnd = datagramEnd
            return true
        }
        val profile = VersionProfile.of(version)
        if (profile == null) {
            out.unsupportedVersion = true
            out.pnOffset = p
            out.packetEnd = datagramEnd
            return true
        }
        if (dcidLen > 20 || scidLen > 20) return false
        val type = profile.typeOf((first ushr 4) and 0x03) ?: return false
        out.type = type
        val r = WireReader(buf, p, datagramEnd)
        try {
            if (type == PacketType.Initial) {
                val tl = r.length()
                out.tokenOff = r.pos
                out.tokenLen = tl
                r.pos += tl
            }
            if (type ==
                PacketType.Retry
            ) {
                out.tokenOff = r.pos
                out.tokenLen = maxOf(0, datagramEnd - r.pos - 16)
                out.retryTagOff =
                    datagramEnd - 16
                out.pnOffset = datagramEnd
                out.packetEnd = datagramEnd
                return out.tokenLen >= 0 &&
                    datagramEnd - r.pos >= 16
            }
            val length = r.varint()
            if (length > r.remaining) return false
            out.pnOffset = r.pos
            out.packetEnd = r.pos + length.toInt()
            return true
        } catch (_: QuicWireException) {
            return false
        }
    }

    /** Writes a long header with a 2-byte Length placeholder; returns the offset of the Length field (fill it with [VarInt.writeFixed]). */
    fun writeLong(
        w: WireWriter,
        profile: VersionProfile,
        type: PacketType,
        dcid: ConnectionId,
        scid: ConnectionId,
        token: ByteArray?,
        pnLength: Int,
        greaseFixedBit: Boolean,
    ): Int {
        require(pnLength in 1..4)
        w.u8(FORM_LONG or (if (greaseFixedBit) 0 else FIXED_BIT) or (profile.bitsOf(type) shl 4) or (pnLength - 1))
        w.u32(profile.version.toLong() and 0xffffffffL)
        w.u8(dcid.length)
        w.cid(dcid)
        w.u8(scid.length)
        w.cid(scid)
        if (type == PacketType.Initial) {
            if (token == null) {
                w.varint(0)
            } else {
                w.varint(token.size.toLong())
                w.bytes(token)
            }
        }
        val lengthOffset = w.pos
        w.u16(0x4000) // 2-byte varint placeholder
        return lengthOffset
    }

    /** Writes a short header; returns the packet number offset. */
    fun writeShort(
        w: WireWriter,
        dcid: ConnectionId,
        pnLength: Int,
        spin: Boolean,
        keyPhase: Boolean,
        greaseFixedBit: Boolean,
    ): Int {
        require(pnLength in 1..4)
        w.u8((if (greaseFixedBit) 0 else FIXED_BIT) or (if (spin) 0x20 else 0) or (if (keyPhase) 0x04 else 0) or (pnLength - 1))
        w.cid(dcid)
        return w.pos
    }
}
