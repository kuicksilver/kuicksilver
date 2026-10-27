// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

import io.kotest.property.Arb
import io.kotest.property.arbitrary.boolean
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.arbitrary.long
import io.kotest.property.checkAll
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.Arbs
import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TransportParametersTest {
    private fun raw(vararg params: Pair<Long, ByteArray>): ByteArray {
        val b = PacketBuffer.allocate(4096)
        try {
            val w = WireWriter(b, 0, b.capacity)
            for ((id, v) in params) {
                w.varint(id)
                w.varint(v.size.toLong())
                w.bytes(v)
            }
            return ByteArray(w.pos).also { b.copyTo(it, 0, 0, w.pos) }
        } finally {
            b.close()
        }
    }

    private fun vi(v: Long): ByteArray {
        val b = PacketBuffer.allocate(8)
        try {
            val n = VarInt.write(b, 0, v)
            return ByteArray(n).also { b.copyTo(it, 0, 0, n) }
        } finally {
            b.close()
        }
    }

    private fun expect(
        code: Long,
        bytes: ByteArray,
        sender: TlsRole = TlsRole.Server,
    ) {
        val e = assertFailsWith<QuicWireException> { TransportParametersCodec.decode(bytes, sender) }
        assertEquals(code, e.code)
    }

    @Test fun rfcDefaultsWhenAbsent() {
        val tp = TransportParametersCodec.decode(raw(), TlsRole.Server)
        assertEquals(65527L, tp.maxUdpPayloadSize)
        assertEquals(3, tp.ackDelayExponent)
        assertEquals(25L, tp.maxAckDelayMs)
        assertEquals(2L, tp.activeConnectionIdLimit)
        assertEquals(0L, tp.maxIdleTimeoutMs)
        assertEquals(0L, tp.initialMaxData)
        assertFalse(tp.disableActiveMigration)
        assertNull(tp.availableVersions)
        assertEquals(0L, tp.maxDatagramFrameSize)
    }

    /**
     * 300 random parameter sets per role survive encode and decode. A plain seeded loop rather than Kotest's checkAll:
     * Android 7.0's ART aborted the test process in its garbage collector on proptest's frame ("Found invalid root",
     * CI emulator API 24), a runtime bug no change to the codec could avoid.
     */
    @Test fun roundTripAllParameters() {
        val rnd = kotlin.random.Random(0x7E5E_A11L)

        fun varint() = rnd.nextLong(0L, VarInt.MAX + 1)
        for (iteration in 0 until 300) {
            for (server in listOf(false, true)) {
                val tp = TransportParameters()
                val cid = { rnd.nextBytes(rnd.nextInt(0, 21)) }
                tp.initialSourceConnectionId = ConnectionId(cid())
                if (server) {
                    tp.originalDestinationConnectionId = ConnectionId(cid())
                    tp.retrySourceConnectionId = ConnectionId(cid())
                    tp.statelessResetToken =
                        rnd.nextBytes(16)
                    tp.preferredAddressPresent = false
                }
                tp.maxIdleTimeoutMs = varint()
                tp.maxUdpPayloadSize = rnd.nextLong(1200L, 65528L)
                tp.initialMaxData =
                    varint()
                tp.initialMaxStreamDataBidiLocal = varint()
                tp.initialMaxStreamDataBidiRemote = varint()
                tp.initialMaxStreamDataUni =
                    varint()
                tp.initialMaxStreamsBidi = rnd.nextLong(0L, (1L shl 60) + 1)
                tp.initialMaxStreamsUni = rnd.nextLong(0L, (1L shl 60) + 1)
                tp.ackDelayExponent =
                    rnd.nextInt(0, 21)
                tp.maxAckDelayMs = rnd.nextLong(0L, 16384L)
                tp.disableActiveMigration = rnd.nextBoolean()
                tp.activeConnectionIdLimit =
                    rnd.nextLong(2L, 101L)
                tp.maxDatagramFrameSize = varint()
                tp.greaseQuicBit = rnd.nextBoolean()
                if (rnd.nextBoolean()) {
                    tp.chosenVersion = 1
                    tp.availableVersions = intArrayOf(1, 0x6b3343cf)
                }
                val role = if (server) TlsRole.Server else TlsRole.Client
                val back = TransportParametersCodec.decode(TransportParametersCodec.encode(tp, role, 27), role)
                assertEquals(tp.initialSourceConnectionId, back.initialSourceConnectionId)
                assertEquals(tp.originalDestinationConnectionId, back.originalDestinationConnectionId)
                assertEquals(tp.retrySourceConnectionId, back.retrySourceConnectionId)
                assertContentEquals(tp.statelessResetToken, back.statelessResetToken)
                assertEquals(tp.maxIdleTimeoutMs, back.maxIdleTimeoutMs)
                assertEquals(tp.maxUdpPayloadSize, back.maxUdpPayloadSize)
                assertEquals(tp.initialMaxData, back.initialMaxData)
                assertEquals(tp.initialMaxStreamDataBidiLocal, back.initialMaxStreamDataBidiLocal)
                assertEquals(tp.initialMaxStreamDataBidiRemote, back.initialMaxStreamDataBidiRemote)
                assertEquals(tp.initialMaxStreamDataUni, back.initialMaxStreamDataUni)
                assertEquals(tp.initialMaxStreamsBidi, back.initialMaxStreamsBidi)
                assertEquals(tp.initialMaxStreamsUni, back.initialMaxStreamsUni)
                assertEquals(tp.ackDelayExponent, back.ackDelayExponent)
                assertEquals(tp.maxAckDelayMs, back.maxAckDelayMs)
                assertEquals(tp.disableActiveMigration, back.disableActiveMigration)
                assertEquals(tp.activeConnectionIdLimit, back.activeConnectionIdLimit)
                assertEquals(tp.maxDatagramFrameSize, back.maxDatagramFrameSize)
                assertEquals(tp.greaseQuicBit, back.greaseQuicBit)
                assertEquals(tp.chosenVersion, back.chosenVersion)
                assertEquals(tp.availableVersions?.toList(), back.availableVersions?.toList())
            }
        }
    }

    /**
     * Found by the `rememberedTicket` fuzz target: a server may list many versions in version_information (the decoder takes
     * any multiple of 4 bytes), and encoding such parameters again overflowed the encoder's fixed 1024-byte buffer.
     */
    @Test fun negative_manyAvailableVersionsEncodeAgain() {
        val tp = TransportParameters()
        tp.chosenVersion = 1
        tp.availableVersions = IntArray(300) { it + 1 }
        val back = TransportParametersCodec.decode(TransportParametersCodec.encode(tp, TlsRole.Server, 27), TlsRole.Server)
        assertEquals(tp.availableVersions?.toList(), back.availableVersions?.toList())
    }

    @Test fun negative_duplicateTransportParameter() = expect(0x08, raw(0x01L to vi(10), 0x01L to vi(20)))

    @Test fun serverOnlyParametersFromClientRejected() {
        expect(0x08, raw(0x00L to ByteArray(8)), TlsRole.Client)
        expect(0x08, raw(0x02L to ByteArray(16)), TlsRole.Client)
        expect(0x08, raw(0x0dL to ByteArray(41)), TlsRole.Client)
        expect(0x08, raw(0x10L to ByteArray(4)), TlsRole.Client)
    }

    @Test fun maxUdpPayloadBelow1200Rejected() = expect(0x08, raw(0x03L to vi(1199)))

    @Test fun ackDelayExponentAbove20Rejected() = expect(0x08, raw(0x0aL to vi(21)))

    @Test fun maxAckDelayAtLeast2Pow14Rejected() = expect(0x08, raw(0x0bL to vi(16384)))

    @Test fun activeConnectionIdLimitBelow2Rejected() = expect(0x08, raw(0x0eL to vi(1)))

    @Test fun maxStreamsAbove2Pow60Rejected() {
        expect(0x08, raw(0x08L to vi((1L shl 60) + 1)))
        expect(
            0x08,
            raw(0x09L to vi((1L shl 60) + 1)),
        )
    }

    @Test fun statelessResetTokenNot16BytesRejected() = expect(0x08, raw(0x02L to ByteArray(15)))

    @Test fun greaseQuicBitWithValueRejected() = expect(0x08, raw(0x2ab2L to byteArrayOf(1)))

    @Test fun reservedParametersIgnored() {
        val tp = TransportParametersCodec.decode(raw(182L to byteArrayOf(1, 2, 3), 0x04L to vi(5)), TlsRole.Server)
        assertEquals(5L, tp.initialMaxData)
    }

    @Test fun truncatedValueRejected() = expect(0x08, raw(0x04L to vi(5)).dropLast(1).toByteArray())

    @Test fun negative_preferredAddressIgnored() {
        val pa = ByteArray(4 + 2 + 16 + 2 + 1 + 8 + 16).also { it[24] = 8 }
        for (i in 0 until 8) pa[25 + i] = (i + 1).toByte()
        pa[25 + 8] = 0x5a
        val tp = TransportParametersCodec.decode(raw(0x0dL to pa), TlsRole.Server)
        assertTrue(tp.preferredAddressPresent)
        assertEquals(ConnectionId(ByteArray(8) { (it + 1).toByte() }), tp.preferredAddressCid, "the sequence-1 ID is kept")
        assertEquals(0x5a.toByte(), tp.preferredAddressToken!![0])
    }

    /** Review finding 14, RFC 9000 section 18.2: "a server MUST NOT include a zero-length connection ID in this transport parameter." */
    @Test fun negative_preferredAddressWithZeroLengthCid() = expect(0x08, raw(0x0dL to ByteArray(41)))

    /** Review finding 14: the Connection ID Length must agree with the parameter's length (and stay within 20 bytes). */
    @Test fun negative_preferredAddressLengthMismatch() {
        expect(0x08, raw(0x0dL to ByteArray(4 + 2 + 16 + 2 + 1 + 8 + 16).also { it[24] = 9 }))
        expect(0x08, raw(0x0dL to ByteArray(4 + 2 + 16 + 2 + 1 + 21 + 16).also { it[24] = 21 }))
    }

    /** Review finding 14, RFC 9000 section 18.2: "A server that chooses a zero-length connection ID MUST NOT provide a preferred address." */
    @Test fun negative_preferredAddressFromZeroLengthCidServer() =
        expect(0x08, raw(0x0fL to ByteArray(0), 0x0dL to ByteArray(4 + 2 + 16 + 2 + 1 + 8 + 16).also { it[24] = 8 }))
}
