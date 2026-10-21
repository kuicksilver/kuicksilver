// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.crypto

import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.Rfc9001Packets
import io.kuicksilver.quic.Rfc9369Packets
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.quic.wire.VarInt
import io.kuicksilver.quic.wire.WireWriter
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.TlsRole
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class PacketProtectionTest {
    // ---- header protection and AEAD as two steps (the Key Phase bit is read in between) ----
    @Test fun splitUnprotectEqualsK2Unprotect() =
        with(Rfc9001Packets) {
            val (r, _) = KslQuicCrypto.initialProtectors(DCID, VersionProfile.V1.version, TlsRole.Server)
            val a = PacketBuffer.of(A2_PROTECTED)
            val b = PacketBuffer.of(A2_PROTECTED)
            try {
                val v = PacketHeaderView()
                check(PacketHeaderCodec.parse(a, 0, A2_PROTECTED.size, 8, v))
                val pnWhole = PacketProtection.unprotect(a, 0, v.pnOffset, v.packetEnd, -1, r, mask)
                val pnSplit = PacketProtection.removeHeaderProtection(b, 0, v.pnOffset, v.packetEnd, -1, r, mask)
                assertEquals(pnWhole, pnSplit)
                assertEquals(a[0], b[0], "unmasked first byte")
                assertEquals(true, PacketProtection.openPayload(b, 0, v.pnOffset, v.packetEnd, pnSplit, r))
                assertContentEquals(a.toByteArray(v.packetEnd - 16), b.toByteArray(v.packetEnd - 16))
            } finally {
                a.close()
                b.close()
                r.close()
            }
        }

    @Test fun keyPhaseBitReadableAfterHeaderProtectionRemoved() {
        val (_, clientWrite) = KslQuicCrypto.initialProtectors(ByteArray(8) { 9 }, VersionProfile.V1.version, TlsRole.Client)
        val (serverRead, _) = KslQuicCrypto.initialProtectors(ByteArray(8) { 9 }, VersionProfile.V1.version, TlsRole.Server)
        val buf = PacketBuffer.allocate(200)
        try {
            val w = WireWriter(buf, 0, 200)
            PacketHeaderCodec.writeShort(
                w,
                ConnectionId(ByteArray(8) { 1 }),
                pnLength = 2,
                spin = false,
                keyPhase = true,
                greaseFixedBit = false,
            )
            val pnOff = w.pos
            w.zero(2)
            w.bytes(ByteArray(40) { 7 })
            val end = PacketProtection.protect(buf, 0, pnOff, 2, w.pos, 77, clientWrite, mask)
            val pn = PacketProtection.removeHeaderProtection(buf, 0, pnOff, end, -1, serverRead, mask)
            assertEquals(77L, pn)
            assertEquals(0x04, buf[0].toInt() and 0x04, "Key Phase bit visible once header protection is off")
            assertEquals(true, PacketProtection.openPayload(buf, 0, pnOff, end, pn, serverRead))
        } finally {
            buf.close()
            clientWrite.close()
            serverRead.close()
        }
    }

    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val mask = ByteArray(5)

    /** Builds and protects an Initial like the RFC appendix: returns the datagram bytes. */
    private fun initial(
        profile: VersionProfile,
        dcid: ByteArray,
        scid: ByteArray,
        pn: Long,
        pnLength: Int,
        payload: ByteArray,
        padTo: Int,
        role: TlsRole,
        keyDcid: ByteArray,
    ): ByteArray {
        val (_, w) = KslQuicCrypto.initialProtectors(keyDcid, profile.version, role)
        val buf = PacketBuffer.allocate(1500)
        try {
            val wr = WireWriter(buf, 0, buf.capacity)
            val lenOff =
                PacketHeaderCodec.writeLong(
                    wr,
                    profile,
                    PacketType.Initial,
                    ConnectionId(dcid),
                    ConnectionId(scid),
                    null,
                    pnLength,
                    false,
                )
            val pnOff = wr.pos
            val payloadLen = maxOf(payload.size, padTo)
            VarInt.writeFixed(buf, lenOff, (pnLength + payloadLen + 16).toLong(), 2)
            wr.zero(pnLength)
            wr.bytes(payload)
            wr.zero(payloadLen - payload.size)
            val end = PacketProtection.protect(buf, 0, pnOff, pnLength, wr.pos, pn, w, mask)
            return buf.toByteArray(end)
        } finally {
            buf.close()
            w.close()
        }
    }

    private fun unprotect(
        profile: VersionProfile,
        packet: ByteArray,
        role: TlsRole,
        keyDcid: ByteArray,
        cut: Int = 0,
    ): Pair<Long, ByteArray?> {
        val (r, _) = KslQuicCrypto.initialProtectors(keyDcid, profile.version, role)
        val buf = PacketBuffer.of(packet)
        try {
            val v = PacketHeaderView()
            check(PacketHeaderCodec.parse(buf, 0, packet.size, 8, v))
            assertEquals(PacketType.Initial, v.type)
            val pn = PacketProtection.unprotect(buf, 0, v.pnOffset, v.packetEnd - cut, -1, r, mask)
            if (pn < 0) return pn to null
            val pnLen = (buf[0].toInt() and 0x03) + 1
            return pn to buf.toByteArray(v.packetEnd - 16).copyOfRange(v.pnOffset + pnLen, v.packetEnd - 16)
        } finally {
            buf.close()
            r.close()
        }
    }

    @Test fun rfc9001A2ClientInitialBytes() =
        with(Rfc9001Packets) {
            val out = initial(VersionProfile.V1, DCID, ByteArray(0), A2_PN, 4, A2_CRYPTO, 1162, TlsRole.Client, DCID)
            assertContentEquals(
                A2_HEADER,
                out.copyOfRange(0, A2_HEADER.size).also {
                    // header before protection equals the RFC's unprotected header modulo PN
                    it[0] =
                        A2_HEADER[0]
                    A2_HEADER.copyInto(it, 18, 18, 22)
                },
            )
            assertContentEquals(A2_PROTECTED, out)
        }

    @Test fun rfc9001A3ServerInitialBytes() =
        with(Rfc9001Packets) {
            assertContentEquals(
                A3_PROTECTED,
                initial(VersionProfile.V1, ByteArray(0), A3_SCID, A3_PN, 2, A3_PAYLOAD, 0, TlsRole.Server, DCID),
            )
        }

    @Test fun rfc9001ServerUnprotectsA2() =
        with(Rfc9001Packets) {
            val (pn, payload) = unprotect(VersionProfile.V1, A2_PROTECTED, TlsRole.Server, DCID)
            assertEquals(A2_PN, pn)
            assertContentEquals(A2_CRYPTO + ByteArray(1162 - A2_CRYPTO.size), payload)
        }

    @Test fun rfc9369A2ClientInitialBytes() =
        with(Rfc9369Packets) {
            assertContentEquals(
                A2_PROTECTED,
                initial(VersionProfile.V2, DCID, ByteArray(0), A2_PN, 4, A2_CRYPTO, 1162, TlsRole.Client, DCID),
            )
        }

    @Test fun rfc9369A3ServerInitialBytes() =
        with(Rfc9369Packets) {
            assertContentEquals(
                A3_PROTECTED,
                initial(VersionProfile.V2, ByteArray(0), A3_SCID, A3_PN, 2, A3_PAYLOAD, 0, TlsRole.Server, DCID),
            )
        }

    @Test fun rfc9369ClientUnprotectsA3() =
        with(Rfc9369Packets) {
            val (pn, payload) = unprotect(VersionProfile.V2, A3_PROTECTED, TlsRole.Client, DCID)
            assertEquals(A3_PN, pn)
            assertContentEquals(A3_PAYLOAD, payload)
        }

    @Test fun retryTagsV1V2() {
        for ((v, p) in listOf(1 to Rfc9001Packets.A4_RETRY, 0x6b3343cf to Rfc9369Packets.A4_RETRY)) {
            val pseudo = byteArrayOf(8) + Rfc9001Packets.DCID + p.copyOfRange(0, p.size - 16)
            assertContentEquals(p.copyOfRange(p.size - 16, p.size), KslQuicCrypto.retryIntegrityTag(v, Rfc9001Packets.DCID, pseudo))
        }
    }

    @Test fun sampleOffsetIsPnOffsetPlus4() =
        with(Rfc9001Packets) {
            val buf = PacketBuffer.of(A2_PROTECTED)
            try {
                val v = PacketHeaderView()
                PacketHeaderCodec.parse(buf, 0, A2_PROTECTED.size, 8, v)
                assertContentEquals(
                    A2_SAMPLE,
                    buf.toByteArray(v.pnOffset + 20).copyOfRange(v.pnOffset + 4, v.pnOffset + 20),
                )
            } finally {
                buf.close()
            }
        }

    @Test fun packetTooShortForSampleDropped() =
        with(Rfc9001Packets) {
            val short = A2_PROTECTED.copyOf(22 + 19) // header 22 + pn/payload 19 < 4 + 16
            val buf = PacketBuffer.of(short)
            val (r, _) = KslQuicCrypto.initialProtectors(DCID, 1, TlsRole.Server)
            try {
                assertEquals(-1L, PacketProtection.unprotect(buf, 0, 22, short.size, -1, r, mask))
            } finally {
                buf.close()
                r.close()
            }
        }

    @Test fun aeadFailureReturnsMinusOne() =
        with(Rfc9001Packets) {
            val bad = A2_PROTECTED.copyOf()
            bad[100] = (bad[100].toInt() xor 1).toByte()
            assertEquals(-1L, unprotect(VersionProfile.V1, bad, TlsRole.Server, DCID).first)
        }
}
