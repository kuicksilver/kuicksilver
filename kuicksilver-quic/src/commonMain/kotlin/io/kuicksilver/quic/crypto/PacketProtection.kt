// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.crypto

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.wire.PacketNumbers
import io.kuicksilver.tls.PacketProtectionException
import io.kuicksilver.tls.PacketProtector

/** Packet protection in place inside a datagram buffer (RFC 9001 section 5.3–5.4): AEAD then header protection. */
internal object PacketProtection {
    private const val TAG = 16
    private const val SAMPLE = 16

    /**
     * Writes the truncated packet number at [pnOffset], seals `[pnOffset + pnLength, payloadEnd)` with the header
     * `[headerStart, pnOffset + pnLength)` as AAD, then applies header protection. Returns the end of the packet.
     */
    fun protect(
        buf: PacketBuffer,
        headerStart: Int,
        pnOffset: Int,
        pnLength: Int,
        payloadEnd: Int,
        pn: Long,
        p: PacketProtector,
        mask: ByteArray,
    ): Int {
        for (i in 0 until pnLength) buf[pnOffset + i] = (pn ushr (8 * (pnLength - 1 - i))).toByte()
        val payloadStart = pnOffset + pnLength
        val end = payloadStart + p.seal(pn, buf, headerStart, payloadStart - headerStart, buf, payloadStart, payloadEnd - payloadStart)
        p.headerMask(buf, pnOffset + 4, mask)
        val first = buf[headerStart].toInt() and 0xff
        buf[headerStart] = (first xor (mask[0].toInt() and if (first and 0x80 != 0) 0x0f else 0x1f)).toByte()
        for (i in 0 until pnLength) buf[pnOffset + i] = (buf[pnOffset + i].toInt() xor mask[1 + i].toInt()).toByte()
        return end
    }

    /**
     * Removes header protection, recovers the packet number against [largestPn] (-1 for none) and opens the payload in
     * place. Returns the packet number, or -1 when the packet is too short for a sample or fails authentication; the
     * plaintext then spans `[pnOffset + pnLength, packetEnd - 16)` with `pnLength` read from the unmasked first byte.
     */
    fun unprotect(
        buf: PacketBuffer,
        headerStart: Int,
        pnOffset: Int,
        packetEnd: Int,
        largestPn: Long,
        p: PacketProtector,
        mask: ByteArray,
    ): Long {
        val pn = removeHeaderProtection(buf, headerStart, pnOffset, packetEnd, largestPn, p, mask)
        if (pn < 0) return -1
        return if (openPayload(buf, headerStart, pnOffset, packetEnd, pn, p)) pn else -1
    }

    /**
     * Step one of [unprotect]: removes header protection in place with [hp]'s HP key and recovers the packet number
     * against [largestPn]; -1 when the packet is too short for the sample or the tag. Afterwards the first byte is in
     * the clear (the Key Phase bit of a short header can be read) and the packet still has to pass [openPayload];
     * a packet that fails is dropped as a whole, so committing the header early is safe.
     */
    fun removeHeaderProtection(
        buf: PacketBuffer,
        headerStart: Int,
        pnOffset: Int,
        packetEnd: Int,
        largestPn: Long,
        hp: PacketProtector,
        mask: ByteArray,
    ): Long {
        if (pnOffset + 4 + SAMPLE > packetEnd) return -1
        hp.headerMask(buf, pnOffset + 4, mask)
        val masked = buf[headerStart].toInt() and 0xff
        val first = masked xor (mask[0].toInt() and if (masked and 0x80 != 0) 0x0f else 0x1f)
        val pnLength = (first and 0x03) + 1
        var truncated = 0L
        for (i in 0 until pnLength) {
            val b =
                (buf[pnOffset + i].toInt() xor mask[1 + i].toInt()) and 0xff
            truncated = (truncated shl 8) or b.toLong()
        }
        val pn = PacketNumbers.decode(largestPn, truncated, 8 * pnLength)
        if (pnOffset + pnLength + TAG > packetEnd) return -1
        buf[headerStart] = first.toByte()
        for (i in 0 until pnLength) buf[pnOffset + i] = (buf[pnOffset + i].toInt() xor mask[1 + i].toInt()).toByte()
        return pn
    }

    /** Step two: AEAD in place with [key]; false on a bad tag. The packet number length is read from the unmasked first byte. */
    fun openPayload(
        buf: PacketBuffer,
        headerStart: Int,
        pnOffset: Int,
        packetEnd: Int,
        pn: Long,
        key: PacketProtector,
    ): Boolean {
        val payloadStart = pnOffset + (buf[headerStart].toInt() and 0x03) + 1
        return try {
            key.open(pn, buf, headerStart, payloadStart - headerStart, buf, payloadStart, packetEnd - payloadStart)
            true
        } catch (
            _: PacketProtectionException,
        ) {
            false
        }
    }
}
