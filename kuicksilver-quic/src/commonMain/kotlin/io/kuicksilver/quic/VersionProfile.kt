// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.quic.wire.PacketType

/**
 * Wire constants of a QUIC version: QUIC v1 (RFC 9000/9001) and QUIC v2 (RFC 9369). v1 is the default; v2 is opt-in
 * through `QuicConfig.versions` and is negotiated per RFC 9368.
 */
public class VersionProfile private constructor(
    /** The 32-bit version number as it appears in long headers. */
    public val version: Int,
    internal val initialSalt: ByteArray,
    /** Long-header packet type bits for Initial, 0-RTT, Handshake and Retry, in that order (RFC 9369 section 3.2). */
    internal val longTypeBits: IntArray,
) {
    internal fun typeOf(bits: Int): PacketType? =
        when (bits) {
            longTypeBits[0] -> PacketType.Initial
            longTypeBits[1] -> PacketType.ZeroRtt
            longTypeBits[2] -> PacketType.Handshake
            longTypeBits[3] -> PacketType.Retry
            else -> null
        }

    internal fun bitsOf(type: PacketType): Int =
        when (type) {
            PacketType.Initial -> longTypeBits[0]
            PacketType.ZeroRtt -> longTypeBits[1]
            PacketType.Handshake -> longTypeBits[2]
            PacketType.Retry -> longTypeBits[3]
            PacketType.OneRtt -> throw IllegalArgumentException("short header")
        }

    override fun toString(): String = "VersionProfile(0x${version.toUInt().toString(16).padStart(8, '0')})"

    override fun equals(other: Any?): Boolean = other is VersionProfile && other.version == version

    override fun hashCode(): Int = version

    /** The versions this stack implements, [V1] and [V2], and [of] to look one up by number. */
    public companion object {
        private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        /** QUIC version 1 (RFC 9000). */
        public val V1: VersionProfile =
            VersionProfile(0x00000001, hex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), intArrayOf(0b00, 0b01, 0b10, 0b11))

        /** QUIC version 2 (RFC 9369), version number 0x6b3343cf. */
        public val V2: VersionProfile =
            VersionProfile(0x6b3343cf, hex("0dede3def700a6db819381be6e269dcbf9bd2ed9"), intArrayOf(0b01, 0b10, 0b11, 0b00))

        /** The profile of a version number, or null for a version this stack does not implement. */
        public fun of(version: Int): VersionProfile? =
            when (version) {
                V1.version -> V1
                V2.version -> V2
                else -> null
            }
    }
}
