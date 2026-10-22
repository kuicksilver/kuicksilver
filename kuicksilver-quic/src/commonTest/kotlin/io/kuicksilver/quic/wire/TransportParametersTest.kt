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

    @Test fun roundTripAllParameters() =
        runTest {
            checkAll(300, Arb.boolean()) { server ->
                val tp = TransportParameters()
                val cid = { Arb.list(Arb.byte(), 0..20).bind().toByteArray() }
                tp.initialSourceConnectionId = ConnectionId(cid())
                if (server) {
                    tp.originalDestinationConnectionId = ConnectionId(cid())
                    tp.retrySourceConnectionId = ConnectionId(cid())
                    tp.statelessResetToken =
                        ByteArray(16) { Arb.byte().bind() }
                    tp.preferredAddressPresent = false
                }
                tp.maxIdleTimeoutMs = Arbs.varint().bind()
                tp.maxUdpPayloadSize = Arb.long(1200L..65527L).bind()
                tp.initialMaxData =
                    Arbs.varint().bind()
                tp.initialMaxStreamDataBidiLocal = Arbs.varint().bind()
                tp.initialMaxStreamDataBidiRemote = Arbs.varint().bind()
                tp.initialMaxStreamDataUni =
                    Arbs.varint().bind()
                tp.initialMaxStreamsBidi = Arb.long(0L..(1L shl 60)).bind()
                tp.initialMaxStreamsUni = Arb.long(0L..(1L shl 60)).bind()
                tp.ackDelayExponent =
                    Arb.int(0..20).bind()
                tp.maxAckDelayMs = Arb.long(0L..16383L).bind()
                tp.disableActiveMigration = Arb.boolean().bind()
                tp.activeConnectionIdLimit =
                    Arb.long(2L..100L).bind()
                tp.maxDatagramFrameSize = Arbs.varint().bind()
                tp.greaseQuicBit = Arb.boolean().bind()
                tp.resetStreamAt = Arb.boolean().bind()
                if (Arb.boolean().bind()) {
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
                assertEquals(tp.resetStreamAt, back.resetStreamAt)
                assertEquals(tp.chosenVersion, back.chosenVersion)
                assertEquals(tp.availableVersions?.toList(), back.availableVersions?.toList())
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

    /** draft-ietf-quic-reliable-stream-reset-11 section 3: 0x1d; the pre-IANA 0x17f7586d2cb571 (Chrome, quiche) is accepted too. */
    @Test fun resetStreamAtBothCodepoints() {
        for (id in listOf(0x1dL, 0x17f7586d2cb571L)) {
            assertTrue(TransportParametersCodec.decode(raw(id to ByteArray(0)), TlsRole.Server).resetStreamAt, "0x${id.toString(16)}")
            expect(0x08, raw(id to byteArrayOf(1)))
        }
        val tp = TransportParameters().also { it.resetStreamAt = true }
        val sent = TransportParametersCodec.encode(tp, TlsRole.Client, 27)
        // both go out: 0x1d for current peers (quic-go, neqo), the old one for Chrome and quiche
        assertTrue(TransportParametersCodec.decode(sent, TlsRole.Client).resetStreamAt)
        assertTrue(sent.toList().windowed(2).any { it == listOf(0x1d.toByte(), 0.toByte()) })
    }

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
