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
import kotlin.time.Duration
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

    @Test fun negative_initialRttMustBePositive() {
        // RFC 9002 section 6.2.2: the initial RTT seeds the PTO; zero or negative would make it fire at once and forever, and an
        // absurd value would leave a lost first flight unrepaired for minutes
        for (bad in listOf(Duration.ZERO, (-1).milliseconds, 10.seconds + 1.milliseconds, Duration.INFINITE)) {
            val e = assertFailsWith<IllegalArgumentException>("initialRtt = $bad") { quicConfig { initialRtt = bad } }
            assertEquals("initialRtt must be positive and at most 10 s", e.message)
        }
        assertEquals(1.milliseconds, quicConfig { initialRtt = 1.milliseconds }.initialRtt)
        assertEquals(10.seconds, quicConfig { initialRtt = 10.seconds }.initialRtt)
    }

    @Test fun keepAliveAboveThreeQuartersIdleRejected() {
        assertFailsWith<IllegalArgumentException> { quicConfig { keepAlive = 23.seconds } }
        assertEquals(22.seconds, quicConfig { keepAlive = 22.seconds }.keepAlive)
    }

    @Test fun negative_handshakeTimeoutMustBePositive() {
        for (bad in listOf(Duration.ZERO, (-1).milliseconds)) {
            val e = assertFailsWith<IllegalArgumentException>("handshakeTimeout = $bad") { quicConfig { handshakeTimeout = bad } }
            assertEquals("handshakeTimeout must be positive", e.message)
        }
        assertEquals(1.milliseconds, quicConfig { handshakeTimeout = 1.milliseconds }.handshakeTimeout)
        assertEquals(Duration.INFINITE, quicConfig { handshakeTimeout = Duration.INFINITE }.handshakeTimeout)
    }

    @Test fun negative_maxSendBufferMustBePositive() {
        for (bad in listOf(0L, -1L, (1L shl 62) + 1)) {
            val e = assertFailsWith<IllegalArgumentException>("maxSendBuffer = $bad") { quicConfig { maxSendBuffer = bad } }
            assertEquals("maxSendBuffer must be 1..2^62", e.message)
        }
        assertEquals(1L, quicConfig { maxSendBuffer = 1 }.maxSendBuffer)
    }

    @Test fun negative_maxIdleTimeoutMustBeZeroOrFinite() {
        for (bad in listOf((-1).milliseconds, Duration.INFINITE)) {
            val e = assertFailsWith<IllegalArgumentException>("maxIdleTimeout = $bad") { quicConfig { maxIdleTimeout = bad } }
            assertEquals("maxIdleTimeout must be zero (none) or a positive finite duration", e.message)
        }
    }

    @Test fun negative_keepAliveMustBePositiveAndFinite() {
        for (bad in listOf(Duration.ZERO, (-1).seconds, Duration.INFINITE)) {
            val e =
                assertFailsWith<IllegalArgumentException>("keepAlive = $bad") {
                    quicConfig {
                        maxIdleTimeout = Duration.ZERO
                        keepAlive = bad
                    }
                }
            assertEquals("keepAlive must be positive and finite, or null", e.message)
        }
    }

    /** Our idle timeout off still leaves the peer's (RFC 9000 section 10.1): keep-alive is what holds the connection then. */
    @Test fun keepAliveWithIdleTimeoutDisabledIsAllowed() {
        val c =
            quicConfig {
                maxIdleTimeout = Duration.ZERO
                keepAlive = 15.seconds
            }
        assertEquals(15.seconds, c.keepAlive)
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

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun toBuilderKeepsEverySetting() {
        val sink =
            object : QlogSink {
                override fun open(
                    odcidHex: String,
                    role: TlsRole,
                ): QlogTrace? = null
            }
        val c =
            quicConfig {
                maxIdleTimeout = 5.seconds
                keepAlive = 1.seconds
                maxBidiStreams = 7
                versions = listOf(VersionProfile.V2, VersionProfile.V1)
                maxDatagramFrameSize = 0
                greaseQuicBit = false
            }
        val copy = c.toBuilder().apply { qlog = sink }.build()
        assertEquals(5.seconds, copy.maxIdleTimeout)
        assertEquals(1.seconds, copy.keepAlive)
        assertEquals(7L, copy.maxBidiStreams)
        assertEquals(c.versions, copy.versions)
        assertEquals(0L, copy.maxDatagramFrameSize)
        assertFalse(copy.greaseQuicBit)
        assertTrue(copy.qlog === sink && c.qlog == null)
        assertTrue(copy.limits === c.limits)
    }
}
