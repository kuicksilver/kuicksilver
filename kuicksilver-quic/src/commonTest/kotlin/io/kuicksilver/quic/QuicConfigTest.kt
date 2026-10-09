// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.quic.wire.localTransportParameters
import io.kuicksilver.tls.TlsRole
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

class QuicConfigTest {
    @Test fun defaultsMatchSpec() {
        val c = QuicConfig.Default
        assertEquals(30.seconds, c.maxIdleTimeout)
        assertEquals(10.seconds, c.handshakeTimeout)
        assertNull(c.keepAlive)
        assertEquals(524_288L, c.initialStreamWindow)
        assertEquals(786_432L, c.initialConnectionWindow)
        assertEquals(6_291_456L, c.maxStreamWindow)
        assertEquals(15_728_640L, c.maxConnectionWindow)
        assertEquals(100L, c.maxBidiStreams)
        assertEquals(100L, c.maxUniStreams)
        assertEquals(4_194_304L, c.maxSendBuffer)
        assertEquals(25.milliseconds, c.maxAckDelay)
        assertEquals(3, c.ackDelayExponent)
        assertEquals(4, c.activeConnectionIdLimit)
        assertEquals(8, c.connectionIdLength)
        assertEquals(1452, c.maxUdpPayloadSize)
        assertEquals(listOf(VersionProfile.V1), c.versions)
        assertEquals(333.milliseconds, c.initialRtt)
        assertEquals(0L, c.defaultStreamErrorCode)
        assertNull(c.qlog)
        assertTrue(c.greaseQuicBit)
        assertEquals(65_536, c.limits.cryptoOutOfOrderPerLevel)
        assertEquals(65_536, c.limits.cryptoPostHandshake)
        assertEquals(32, c.limits.undecryptablePackets)
        assertEquals(64, c.limits.ackRanges)
        assertEquals(256, c.limits.reassemblyRangesPerStream)
        assertEquals(4096, c.limits.reassemblyRangesPerConnection)
        assertEquals(32, c.limits.retiredConnectionIds)
        assertEquals(67_108_864L, c.limits.qlogBytes)
    }

    @Test fun defaultControllerIsCubic() {
        assertIs<io.kuicksilver.quic.Cubic>(QuicConfig.Default.congestionController())
        assertIs<io.kuicksilver.quic.NewReno>(
            quicConfig {
                congestionController =
                    { io.kuicksilver.quic.NewReno() }
            }.congestionController(),
        )
    }

    @Test fun keepAliveAboveThreeQuartersIdleRejected() {
        assertFailsWith<IllegalArgumentException> { quicConfig { keepAlive = 23.seconds } }
        assertEquals(22.seconds, quicConfig { keepAlive = 22.seconds }.keepAlive)
    }

    @Test fun localTransportParametersFromDefaults() {
        val scid = ConnectionId(ByteArray(8) { 1 })
        val tp = QuicConfig.Default.localTransportParameters(TlsRole.Client, scid, null)
        assertEquals(786_432L, tp.initialMaxData)
        assertEquals(524_288L, tp.initialMaxStreamDataBidiLocal)
        assertEquals(524_288L, tp.initialMaxStreamDataBidiRemote)
        assertEquals(524_288L, tp.initialMaxStreamDataUni)
        assertEquals(100L, tp.initialMaxStreamsBidi)
        assertEquals(100L, tp.initialMaxStreamsUni)
        assertEquals(30_000L, tp.maxIdleTimeoutMs)
        assertEquals(4L, tp.activeConnectionIdLimit)
        assertEquals(1452L, tp.maxUdpPayloadSize)
        assertTrue(tp.greaseQuicBit)
        assertEquals(scid, tp.initialSourceConnectionId)
        assertNull(tp.originalDestinationConnectionId)
        assertEquals(25L, tp.maxAckDelayMs)
        assertEquals(3, tp.ackDelayExponent)
        assertEquals(1, tp.chosenVersion)
        assertEquals(listOf(1), tp.availableVersions!!.toList()) // version_information is always sent (RFC 9368 section 3)
        val odcid = ConnectionId(ByteArray(8) { 2 })
        val s = QuicConfig.Default.localTransportParameters(TlsRole.Server, scid, odcid)
        assertEquals(odcid, s.originalDestinationConnectionId)
        assertFalse(s.disableActiveMigration, "spec 4.5: migration is allowed unless allowMigration = false")
        assertNull(s.statelessResetToken)
    }

    @Test fun versionsOptInV1V2() {
        val c = quicConfig { versions = listOf(VersionProfile.V1, VersionProfile.V2) }
        assertEquals(listOf(1, 0x6b3343cf), c.versions.map { it.version })
        val tp = c.localTransportParameters(TlsRole.Client, ConnectionId(ByteArray(8)), null)
        assertEquals(1, tp.chosenVersion)
        assertEquals(listOf(1, 0x6b3343cf), tp.availableVersions!!.toList())
        assertFailsWith<IllegalArgumentException> { quicConfig { versions = emptyList() } }
    }

    @Test fun initialVersionSeparatesFirstFlightFromPreference() {
        // RFC 9368 section 3: the client's Available Versions are ordered by preference, the Chosen Version is the first flight's
        val c =
            quicConfig {
                versions = listOf(VersionProfile.V2, VersionProfile.V1)
                initialVersion = VersionProfile.V1
            }
        assertEquals(VersionProfile.V1, c.firstVersion)
        val tp = c.localTransportParameters(TlsRole.Client, ConnectionId(ByteArray(8)), null)
        assertEquals(1, tp.chosenVersion)
        assertEquals(listOf(0x6b3343cf, 1), tp.availableVersions!!.toList())
        assertEquals(
            VersionProfile.V2,
            quicConfig {
                versions = listOf(VersionProfile.V2, VersionProfile.V1)
            }.firstVersion,
        ) // default: the preferred one
        assertFailsWith<IllegalArgumentException> { quicConfig { initialVersion = VersionProfile.V2 } } // not among versions
    }
}
