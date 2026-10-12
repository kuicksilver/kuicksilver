// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.crypto

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.tls.Aead
import io.kuicksilver.tls.PacketProtectionException
import io.kuicksilver.tls.PacketProtector

/**
 * No-op protection for tests: a zero header mask and a 16-byte tag of eight zero bytes and the packet number (big-endian).
 * The tag stands in for the AEAD nonce (RFC 9001 section 5.3): a packet whose number is recovered wrongly — it arrived
 * more than half a packet-number window late (RFC 9000 appendix A.3) — fails to open, as with real keys, instead of
 * being acknowledged under a number the peer never sent.
 */
internal object NullPacketProtector : PacketProtector {
    override val aead: Aead = Aead.entries.first()

    override fun seal(
        packetNumber: Long,
        header: PacketBuffer,
        headerOffset: Int,
        headerLength: Int,
        payload: PacketBuffer,
        payloadOffset: Int,
        payloadLength: Int,
    ): Int {
        if (payloadOffset + payloadLength + 16 > payload.capacity) throw IndexOutOfBoundsException("no room for the tag")
        writeTag(payload, payloadOffset + payloadLength, packetNumber)
        return payloadLength + 16
    }

    override fun open(
        packetNumber: Long,
        header: PacketBuffer,
        headerOffset: Int,
        headerLength: Int,
        payload: PacketBuffer,
        payloadOffset: Int,
        payloadLength: Int,
    ): Int {
        if (payloadLength < 16 ||
            payloadOffset + payloadLength > payload.capacity
        ) {
            throw PacketProtectionException("null protector: payload shorter than the tag")
        }
        val tag = payloadOffset + payloadLength - 16
        for (i in 0 until 16) {
            if (payload[tag + i] != tagByte(packetNumber, i)) throw PacketProtectionException("null protector: tag mismatch")
        }
        return payloadLength - 16
    }

    override fun headerMask(
        sample: PacketBuffer,
        sampleOffset: Int,
        mask: ByteArray,
    ) {
        for (i in 0 until 5) mask[i] = 0
    }

    override fun next(): PacketProtector = this

    /** Byte [i] of the tag for [packetNumber]. */
    fun tagByte(
        packetNumber: Long,
        i: Int,
    ): Byte = if (i < 8) 0 else (packetNumber ushr (8 * (15 - i))).toByte()

    /** Writes the 16-byte tag for [packetNumber] at [offset]. */
    fun writeTag(
        buf: PacketBuffer,
        offset: Int,
        packetNumber: Long,
    ) {
        for (i in 0 until 16) buf[offset + i] = tagByte(packetNumber, i)
    }

    override fun close() {}
}
