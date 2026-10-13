// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.crypto.PacketProtection
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.quic.wire.FrameEncoder
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.quic.wire.VarInt
import io.kuicksilver.quic.wire.WireWriter
import io.kuicksilver.tls.QuicCrypto
import io.kuicksilver.tls.TlsRole

/** A server's stateless Initial CONNECTION_CLOSE (RFC 9000 section 10.2.3) for an Initial it will not serve, e.g. INVALID_TOKEN (section 8.1.3). */
internal object StatelessClose {
    /** [clientDcid]/[clientScid] are the fields of the client's Initial; the server's Initial keys follow from [clientDcid]. Returns the packet length. */
    fun writeInitialClose(
        out: PacketBuffer,
        profile: VersionProfile,
        clientDcid: ConnectionId,
        clientScid: ConnectionId,
        code: Long,
        crypto: QuicCrypto,
    ): Int {
        val mask = ByteArray(5) // per call: several endpoint loops write stateless closes at once
        // both protectors hold a native key: the read one is never used here but must be freed too
        val (read, write) = crypto.initialProtectors(clientDcid.toByteArray(), profile.version, TlsRole.Server)
        try {
            val w = WireWriter(out, 0, out.capacity)
            val lengthOff =
                PacketHeaderCodec.writeLong(
                    w,
                    profile,
                    PacketType.Initial,
                    clientScid,
                    clientDcid,
                    null,
                    pnLength = 1,
                    greaseFixedBit = false,
                )
            val pnOff = w.pos
            w.zero(1)
            val payloadStart = w.pos
            FrameEncoder.connectionClose(w, application = false, code = code, frameType = 0, reason = ByteArray(0))
            w.zero(3) // RFC 9000 section 17.2: packet number length + payload at least 4 bytes before the sample
            VarInt.writeFixed(out, lengthOff, (1 + (w.pos - payloadStart) + 16).toLong(), 2)
            return PacketProtection.protect(out, 0, pnOff, 1, w.pos, 0, write, mask)
        } finally {
            read.close()
            write.close()
        }
    }
}
