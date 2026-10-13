// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.endpoint.ConstantTime
import io.kuicksilver.tls.QuicCrypto

/** Retry packets (RFC 9000 section 17.2.5, RFC 9001 section 5.8): header, token, 16-byte integrity tag over the Retry Pseudo-Packet. */
internal object RetryPacket {
    /** Writes a Retry into [out] at offset 0; [firstByteRandom] fills the four unused low bits. Returns the packet length. */
    fun write(
        out: PacketBuffer,
        profile: VersionProfile,
        dcid: ConnectionId,
        scid: ConnectionId,
        token: ByteArray,
        odcid: ConnectionId,
        crypto: QuicCrypto,
        firstByteRandom: Int,
    ): Int {
        val w = WireWriter(out, 0, out.capacity)
        w.u8(0x80 or 0x40 or (profile.bitsOf(PacketType.Retry) shl 4) or (firstByteRandom and 0x0f))
        w.u32(profile.version.toLong() and 0xffffffffL)
        w.u8(dcid.length)
        w.cid(dcid)
        w.u8(scid.length)
        w.cid(scid)
        w.bytes(token)
        val withoutTag = w.pos
        val pseudo = ByteArray(1 + odcid.length + withoutTag)
        pseudo[0] = odcid.length.toByte()
        odcid.copyToArray(pseudo, 1)
        out.copyTo(
            pseudo,
            0,
            1 + odcid.length,
            withoutTag,
        )
        w.bytes(crypto.retryIntegrityTag(profile.version, odcid.toByteArray(), pseudo))
        return w.pos
    }

    /** True when the tag of the Retry at `[off, end)` verifies for [odcid] (RFC 9001 section 5.8), compared in constant time. */
    fun verify(
        buf: PacketBuffer,
        off: Int,
        end: Int,
        odcid: ConnectionId,
        crypto: QuicCrypto,
    ): Boolean {
        if (end - off < 16 + 7) return false
        val version =
            ((buf[off + 1].toInt() and 0xff) shl 24) or
                ((buf[off + 2].toInt() and 0xff) shl 16) or
                ((buf[off + 3].toInt() and 0xff) shl 8) or
                (buf[off + 4].toInt() and 0xff)
        val bodyLen = end - 16 - off
        val pseudo = ByteArray(1 + odcid.length + bodyLen)
        pseudo[0] = odcid.length.toByte()
        odcid.copyToArray(pseudo, 1)
        buf.copyTo(
            pseudo,
            off,
            1 + odcid.length,
            bodyLen,
        )
        val tag = crypto.retryIntegrityTag(version, odcid.toByteArray(), pseudo)
        return ConstantTime.equals(buf, end - 16, tag, 0, 16)
    }
}
