// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.crypto.NullPacketProtector
import io.kuicksilver.tls.PacketProtector
import io.kuicksilver.tls.QuicCrypto
import io.kuicksilver.tls.QuicTlsSession
import io.kuicksilver.tls.ResetKey
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TokenKey

/**
 * A [QuicCrypto] with no cryptography at all, for deterministic tests, simulators and fuzzing: packets carry
 * a zero tag, header protection is the identity and the handshake is a scripted exchange without certificates.
 * Never use it on a network.
 */
@DelicateKuicksilverApi
@InternalKuicksilverApi
public object NullCryptoProvider : QuicCrypto {
    override fun newSession(config: TlsConfig): QuicTlsSession = NullTlsSession(config)

    override fun initialProtectors(
        dcid: ByteArray,
        version: Int,
        role: TlsRole,
    ): Pair<PacketProtector, PacketProtector> = NullPacketProtector to NullPacketProtector

    override fun retryIntegrityTag(
        version: Int,
        odcid: ByteArray,
        retryPseudoPacket: ByteArray,
    ): ByteArray = ByteArray(16)

    /** Token "AEAD" with a zero tag, like the Null packet protection: deterministic, never for a network. */
    override fun newTokenKey(): TokenKey =
        object : TokenKey {
            override fun seal(
                nonce: Long,
                aad: ByteArray,
                plaintext: ByteArray,
            ): ByteArray = plaintext + ByteArray(16)

            override fun open(
                nonce: Long,
                aad: ByteArray,
                sealed: ByteArray,
            ): ByteArray? {
                if (sealed.size <
                    16
                ) {
                    return null
                }
                for (i in sealed.size - 16 until sealed.size) {
                    if (sealed[i] !=
                        0.toByte()
                    ) {
                        return null
                    }
                }
                return sealed.copyOf(sealed.size - 16)
            }

            override fun close() {}
        }

    /** Deterministic reset tokens (SipHash with a fixed key) so simulator runs reproduce byte for byte. */
    override fun newResetKey(): ResetKey =
        object : ResetKey {
            override fun token(
                cid: PacketBuffer,
                offset: Int,
                length: Int,
                out: ByteArray,
                outOffset: Int,
            ) {
                val a =
                    io.kuicksilver.quic.endpoint.SipHash
                        .hash24(0x6e756c6c5f726573L, 0x65745f6b65795f31L, cid, offset, length)
                val b =
                    io.kuicksilver.quic.endpoint.SipHash
                        .hash24(0x6e756c6c5f726573L, 0x65745f6b65795f32L, cid, offset, length)
                for (i in 0 until 8) {
                    out[outOffset + i] = (a ushr (8 * i)).toByte()
                    out[outOffset + 8 + i] = (b ushr (8 * i)).toByte()
                }
            }

            override fun close() {}
        }
}
