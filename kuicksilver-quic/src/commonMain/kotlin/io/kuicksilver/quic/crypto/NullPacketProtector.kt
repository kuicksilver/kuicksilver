// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.crypto

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.tls.Aead
import io.kuicksilver.tls.PacketProtectionException
import io.kuicksilver.tls.PacketProtector

/** No-op protection for tests: a 16-byte zero tag, a zero header mask. */
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
        for (i in 0 until 16) payload[payloadOffset + payloadLength + i] = 0
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
        for (i in 0 until 16) {
            if (payload[payloadOffset + payloadLength - 16 + i].toInt() !=
                0
            ) {
                throw PacketProtectionException("null protector: tag mismatch")
            }
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

    override fun close() {}
}
