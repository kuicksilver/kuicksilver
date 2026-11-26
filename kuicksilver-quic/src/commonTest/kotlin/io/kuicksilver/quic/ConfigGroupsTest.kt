// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.quic

import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.Dispatchers
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * The grouped builders of [QuicConfig] and [QuicEndpointConfig] (ADR-0026): every option reaches the configuration it builds,
 * "off" is null, and the options a layer above derives are recorded when assigned.
 */
class ConfigGroupsTest {
    private val sink =
        object : QlogSink {
            override fun open(
                odcidHex: String,
                role: TlsRole,
            ): QlogTrace? = null
        }

    /** One non-default value per option of every group: each lands in the built QuicConfig (and survives toBuilder). */
    @Test fun everyQuicOptionReachesTheConfig() {
        val cc = { NewReno() }
        val c =
            quicConfig {
                maxIdleTimeout = 41.seconds
                handshakeTimeout = 7.seconds
                keepAlive = 9.seconds
                maxBidiStreams = 17
                versions = listOf(VersionProfile.V2, VersionProfile.V1)
                congestionController = cc
                flowControl {
                    initialStreamWindow = 1_001
                    initialConnectionWindow = 2_002
                    maxStreamWindow = 3_003
                    maxConnectionWindow = 4_004
                    maxSendBuffer = 5_005
                }
                pathMtu {
                    maxReceive = 1_400
                    initial = 1_300
                    maxSend = 1_372
                    discovery = false
                    icmpHints = false
                }
                datagrams {
                    maxFrameSize = 1_111
                    receiveQueue = 11
                    sendQueue = 12
                    sendQueueBytes = 13
                }
                migration {
                    allow = false
                    allowToLoopback = true
                    followPreferredAddress = false
                }
                expert {
                    maxUniStreams = 21
                    maxAckDelay = 22.milliseconds
                    ackDelayExponent = 5
                    activeConnectionIdLimit = 6
                    initialVersion = VersionProfile.V1
                    initialRtt = 100.milliseconds
                    cancelErrorCode = 0x42
                    greaseQuicBit = false
                    glitchProtection = false
                    resetStreamAt = true
                }
            }
        for (q in listOf(c, c.toBuilder().build())) {
            assertEquals(41.seconds, q.maxIdleTimeout)
            assertEquals(7.seconds, q.handshakeTimeout)
            assertEquals(9.seconds, q.keepAlive)
            assertEquals(17L, q.maxBidiStreams)
            assertEquals(listOf(VersionProfile.V2, VersionProfile.V1), q.versions)
            assertSame(cc, q.congestionController)
            assertEquals(1_001L, q.initialStreamWindow)
            assertEquals(2_002L, q.initialConnectionWindow)
            assertEquals(3_003L, q.maxStreamWindow)
            assertEquals(4_004L, q.maxConnectionWindow)
            assertEquals(5_005L, q.maxSendBuffer)
            assertEquals(1_400, q.maxUdpPayloadSize)
            assertEquals(1_300, q.initialUdpPayloadSize)
            assertEquals(1_372, q.maxSendUdpPayloadSize)
            assertEquals(false, q.pmtud)
            assertEquals(false, q.pmtudIcmpHints)
            assertEquals(1_111L, q.maxDatagramFrameSize)
            assertEquals(11, q.datagramReceiveQueue)
            assertEquals(12, q.datagramSendQueue)
            assertEquals(13L, q.datagramSendQueueBytes)
            assertEquals(false, q.allowMigration)
            assertEquals(true, q.allowMigrationToLoopback)
            assertEquals(false, q.followPreferredAddress)
            assertEquals(21L, q.maxUniStreams)
            assertEquals(22.milliseconds, q.maxAckDelay)
            assertEquals(5, q.ackDelayExponent)
            assertEquals(6, q.activeConnectionIdLimit)
            assertEquals(VersionProfile.V1, q.initialVersion)
            assertEquals(100.milliseconds, q.initialRtt)
            assertEquals(0x42L, q.defaultStreamErrorCode)
            assertEquals(false, q.greaseQuicBit)
            assertEquals(false, q.glitchProtection)
            assertEquals(true, q.resetStreamAt)
        }
    }

    /** "No idle timeout" is null; Duration.ZERO, the 0.2.x spelling of it, is refused with a message that names null. */
    @Test fun negative_zeroIdleTimeoutIsRefusedNullIsNone() {
        val e = assertFailsWith<IllegalArgumentException> { quicConfig { maxIdleTimeout = Duration.ZERO } }
        assertTrue("null" in e.message.orEmpty(), e.message)
        val none = quicConfig { maxIdleTimeout = null }
        assertEquals(Duration.ZERO, none.maxIdleTimeout) // the core's "not announced"
        assertNull(none.toBuilder().maxIdleTimeout)
    }

    /** "No datagrams" is null; 0, the 0.2.x spelling of it, is refused. */
    @Test fun negative_zeroDatagramFrameSizeIsRefusedNullIsOff() {
        val e = assertFailsWith<IllegalArgumentException> { quicConfig { datagrams { maxFrameSize = 0 } } }
        assertTrue("null" in e.message.orEmpty(), e.message)
        assertFailsWith<IllegalArgumentException> { quicConfig { datagrams { maxFrameSize = 65_536 } } }
        val off = quicConfig { datagrams { maxFrameSize = null } }
        assertEquals(0L, off.maxDatagramFrameSize)
        assertNull(off.toBuilder().datagrams.maxFrameSize)
    }

    /** The options a Ktor engine derives are recorded when assigned, so the engine can refuse them; a copy records nothing. */
    @Test fun derivedOptionsAreRecordedWhenAssigned() {
        val b = QuicConfig.Builder()
        assertEquals(emptySet(), b.assignedOptions())
        b.maxIdleTimeout = 1.minutes // not a derived one
        b.flowControl { maxSendBuffer = 1 }
        assertEquals(emptySet(), b.assignedOptions())
        b.handshakeTimeout = 3.seconds
        b.expert {
            maxUniStreams = 3
            resetStreamAt = true
            cancelErrorCode = 1
        }
        assertEquals(
            setOf("handshakeTimeout", "expert.maxUniStreams", "expert.resetStreamAt", "expert.cancelErrorCode"),
            b.assignedOptions(),
        )
        assertEquals(emptySet(), b.build().toBuilder().assignedOptions())
    }

    /** The endpoint is the one place for the connection ID length and the qlog sink: its server's QuicConfig gets both. */
    @Test fun endpointAppliesItsConnectionIdLengthAndQlogToTheServer() {
        val server = quicServerConfig(CoreFixtures.server()) {}
        val e =
            quicEndpointConfig {
                this.server = server
                connectionIdLength = 12
                observability { qlog = sink }
            }
        assertEquals(12, e.connectionIdLength)
        assertEquals(12, e.server!!.quic.connectionIdLength)
        assertSame(sink, e.server.quic.qlog)
        assertSame(sink, e.qlog)
        // the caller's server configuration is not changed
        assertEquals(8, server.quic.connectionIdLength)
        assertNull(server.quic.qlog)
    }

    /** A client connection takes the endpoint's length and sink whatever its own QuicConfig says. */
    @Test fun endpointAppliesItsConnectionIdLengthAndQlogToClientConnections() {
        val core =
            EndpointCore(
                quicEndpointConfig {
                    connectionIdLength = 16
                    observability { qlog = sink }
                    runtime { crypto = NullCryptoProvider }
                },
                kotlin.random.Random(1),
            )
        val c =
            core.connect(
                quicClientConfig(CoreFixtures.client()) {},
                io.ktor.network.sockets
                    .InetSocketAddress("10.0.0.2", 443),
                TimeMark(1_000_000_000L),
            )
        assertEquals(16, c.config.connectionIdLength)
        assertSame(sink, c.config.qlog)
        assertEquals(16, c.localCid.length)
    }

    /** One non-default value per option of the endpoint's groups: each lands in the built configuration and survives toBuilder. */
    @Test fun everyEndpointOptionReachesTheConfig() {
        val listener = object : ConnectionListener {}
        val logger = KuicksilverLogger.stderr(LogLevel.Debug)
        val dispatcher = Dispatchers.Unconfined
        val e =
            quicEndpointConfig {
                connectionIdLength = 10
                maxConnections = 31
                maxConnectionsPerIp = null
                acceptQueue = 32
                maxConnectionLifetime = 33.seconds
                observability {
                    this.logger = logger
                    qlog = sink
                    connectionListener = listener
                }
                runtime {
                    this.dispatcher = dispatcher
                    crypto = NullCryptoProvider
                }
                expert {
                    initialAdmissionQueue = 34
                    rejectInitialFromReflectivePorts = false
                    statelessPerAddressPerSecond = 35
                    statelessTotalPerSecond = 36
                }
            }
        for (q in listOf(e, e.toBuilder().build())) {
            assertEquals(10, q.connectionIdLength)
            assertEquals(31, q.maxConnections)
            assertNull(q.maxConnectionsPerIp)
            assertEquals(32, q.acceptQueue)
            assertEquals(33.seconds, q.maxConnectionLifetime)
            assertSame(logger, q.logger)
            assertSame(sink, q.qlog)
            assertSame(listener, q.listener)
            assertSame(dispatcher, q.dispatcher)
            assertSame(NullCryptoProvider, q.crypto)
            assertEquals(34, q.initialQueueCap)
            assertEquals(false, q.rejectInitialFromReflectivePorts)
            assertEquals(35, q.statelessPerAddressPerSecond)
            assertEquals(36, q.statelessTotalPerSecond)
        }
    }

    @Test fun serverAcceptEarlyDataReachesTheConfig() {
        assertEquals(true, quicServerConfig(CoreFixtures.server()) { acceptEarlyData = true }.acceptEarlyData)
        assertEquals(false, quicServerConfig(CoreFixtures.server()) {}.acceptEarlyData)
    }

    /** The options only a server endpoint takes (loops, admission, QUIC-LB) land in the built configuration and survive toBuilder. */
    @Test fun everyServerEndpointOptionReachesTheConfig() {
        val admission = ConnectionAdmission.AlwaysRetry
        val lb =
            QuicLbConfig(
                2,
                byteArrayOf(1, 2, 3, 4),
                4,
                io.kuicksilver.quic.endpoint.QuicLbFixtures
                    .key(),
            )
        val e =
            quicEndpointConfig {
                server = quicServerConfig(CoreFixtures.server()) {}
                connectionIdLength = 9
                loops = 3
                this.admission = admission
                loadBalancer = lb
            }
        for (q in listOf(e, e.toBuilder().build())) {
            assertEquals(3, q.loops)
            assertSame(admission, q.admission)
            assertSame(lb, q.loadBalancer)
        }
    }

    /** Every option of the QUIC client and server configurations lands in what they build (earlyDataContext: by its limit). */
    @Test fun everyClientAndServerOptionReachesTheConfig() {
        val store = MemoryTokenStore()
        val c =
            quicClientConfig(CoreFixtures.client()) {
                earlyData = io.kuicksilver.tls.EarlyDataState.Allowed
                tokenStore = store
            }
        assertEquals(io.kuicksilver.tls.EarlyDataState.Allowed, c.earlyData)
        assertSame(store, c.tokenStore)
        val preferred =
            PreferredAddress(
                io.ktor.network.sockets
                    .InetSocketAddress("10.0.0.3", 4433),
                null,
            )
        val s =
            quicServerConfig(CoreFixtures.server()) {
                newTokenLifetime = 1.minutes
                newTokenReplayCapacity = 4096
                preferredAddress = preferred
                earlyDataContext = ByteArray(256)
            }
        assertEquals(1.minutes, s.newTokenLifetime)
        assertEquals(4096, s.newTokenReplayCapacity)
        assertSame(preferred, s.preferredAddress)
        assertFailsWith<IllegalArgumentException> { quicServerConfig(CoreFixtures.server()) { earlyDataContext = ByteArray(257) } }
    }
}
