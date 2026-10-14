// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.KuicksilverDsl
import io.kuicksilver.quic.VersionProfile
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** Per-connection ceilings (threat-model 3.2); refusal happens before memory is allocated. Overridden only by tests. */
internal class QuicLimits(
    val cryptoOutOfOrderPerLevel: Int = 65_536,
    val cryptoPostHandshake: Int = 65_536,
    /** Where the Initial and Handshake CRYPTO streams end (ngtcp2: 64 KiB each; Handshake here leaves room for large chains). */
    val cryptoInitialMax: Long = 65_536,
    val cryptoHandshakeMax: Long = 262_144,
    val undecryptablePackets: Int = 32,
    val ackRanges: Int = 64,
    val reassemblyRangesPerStream: Int = 256,
    val reassemblyRangesPerConnection: Int = 4096,
    val retiredConnectionIds: Int = 32,
    val qlogBytes: Long = 67_108_864,
    /** RFC 9001 section 6.6: packets sealed with one AES-GCM key before a key update is forced (ChaCha20's 2^62 is unreachable); authentication failures over the connection's life before AEAD_LIMIT_REACHED. */
    val confidentialityLimitAesGcm: Long = 1L shl 23,
    val integrityLimitAesGcm: Long = 1L shl 52,
    val integrityLimitChaCha: Long = 1L shl 36,
    /** Glitch token bucket (after ngtcp2; docs/guide/quic.md, "Glitch protection"): tokens and refill per second; exhaustion closes with PROTOCOL_VIOLATION. */
    val glitchTokens: Int = 1000,
    val glitchRefillPerSecond: Int = 33,
    /** Rotate to an unused peer connection ID after this many 1-RTT packets (RFC 9000 section 9.5). */
    val cidRotationPackets: Int = 10_000,
)

/** Transport settings of a connection (docs/guide/quic.md, "Configuration"); build one with [quicConfig]. */
public class QuicConfig private constructor(
    /**
     * Our `max_idle_timeout` (RFC 9000 section 10.1): a connection idle for the smaller of both peers' values (never less than 3 x PTO)
     * closes silently with a [TimeoutKind.Idle] timeout; [Duration.ZERO] advertises none and leaves the timeout to the peer.
     * Zero or a positive finite duration.
     */
    public val maxIdleTimeout: Duration,
    /**
     * A connection whose handshake has not completed after this long closes silently with a [TimeoutKind.Handshake] timeout.
     * Positive; [Duration.INFINITE] leaves only the idle timeout.
     */
    public val handshakeTimeout: Duration,
    /**
     * PING interval while the application is quiet; null disables keep-alive. Positive and finite, and at most 3/4 of
     * [maxIdleTimeout] unless that is [Duration.ZERO] (then only the peer's idle timeout applies, and keep-alive is what holds
     * the connection). PINGs go out at least every half of the effective idle timeout, so a peer with a shorter timeout than
     * this interval does not close the connection (as quic-go's `KeepAlivePeriod`).
     */
    public val keepAlive: Duration?,
    /**
     * Receive window of each stream at its start, in bytes (`initial_max_stream_data_*`, RFC 9000 section 4.1); it doubles up to
     * [maxStreamWindow] while the application reads faster than the window allows.
     */
    public val initialStreamWindow: Long,
    /**
     * Receive window of the whole connection at its start, in bytes (`initial_max_data`); grows up to [maxConnectionWindow] and stays at
     * least 1.5 x the largest stream window.
     */
    public val initialConnectionWindow: Long,
    /** Ceiling of a stream's receive window in bytes: the most data one stream can hold unread. */
    public val maxStreamWindow: Long,
    /** Ceiling of the connection's receive window in bytes: the most unread stream data the whole connection can hold. */
    public val maxConnectionWindow: Long,
    /**
     * Bidirectional streams the peer may have open at once (`initial_max_streams_bidi`, RFC 9000 section 4.6), at most 2^60; MAX_STREAMS
     * raises the limit as they close.
     */
    public val maxBidiStreams: Long,
    /** Unidirectional streams the peer may have open at once (`initial_max_streams_uni`, RFC 9000 section 4.6), at most 2^60. */
    public val maxUniStreams: Long,
    /**
     * Bytes the connection buffers for sending over all its streams until they are acknowledged, 1..2^62; a writer waits for
     * room beyond it.
     */
    public val maxSendBuffer: Long,
    /** Our `max_ack_delay` (RFC 9000 section 18.2): the longest we hold back an acknowledgement; below 2^14 ms. */
    public val maxAckDelay: Duration,
    /** Our `ack_delay_exponent` (RFC 9000 section 18.2), 0..20: the scale of the ACK Delay field in our ACK frames. */
    public val ackDelayExponent: Int,
    /**
     * Our `active_connection_id_limit` (RFC 9000 section 5.1.1), at least 2: how many connection IDs of the peer we keep for migration and
     * rotation.
     */
    public val activeConnectionIdLimit: Int,
    /**
     * Length in bytes (4..20) of the connection IDs we issue; behind a [QuicEndpoint] it must equal
     * `QuicEndpointConfig.connectionIdLength`.
     */
    public val connectionIdLength: Int,
    /** Advertised `max_udp_payload_size`; datagrams stay at 1200 bytes until PMTUD (K3). The coroutine runtime ([QuicEndpoint]) handles datagrams of up to 1500 bytes and refuses a larger value at `bind`/`connect`; the sans-IO core takes up to 65527 with batches sized for it. */
    public val maxUdpPayloadSize: Int,
    /** Versions in preference order (RFC 9368 section 3: the client's Available Versions). Default is v1 only. */
    public val versions: List<VersionProfile>,
    /**
     * The version of a client's first flight (its Chosen Version); null means the first of [versions]. Lets a client
     * prefer v2 while still starting in v1 and upgrading through compatible negotiation (RFC 9368 section 2.3).
     */
    public val initialVersion: VersionProfile?,
    /**
     * RTT assumed before the first sample (RFC 9002 section 6.2.2), in (0, 10 s]: the first PTO is 3 x this (999 ms at the 333 ms
     * default, then 2 s, 4 s ...), and a path validation lasts at least 6 x this (RFC 9000 section 8.2.4). Lower recovers a lost
     * first flight sooner at the price of spurious retransmissions on slow links; see docs/guide/quic.md, "Configuration". A client
     * endpoint that already finished a connection to the same server address on its own socket starts from that connection's final
     * smoothed RTT instead (RFC 9002 section 6.2.2).
     */
    public val initialRtt: Duration,
    /** Error code sent in STOP_SENDING / RESET_STREAM when a channel is cancelled or closed with a cause. */
    public val defaultStreamErrorCode: Long,
    /**
     * Receives a qlog trace per connection (docs/guide/quic.md, "qlog"); null traces nothing. A failing sink disables tracing for that
     * connection only.
     */
    public val qlog: QlogSink?,
    /** Builds the congestion controller of each path; [Cubic] with HyStart++ by default, [NewReno] or the experimental [Bbr] as alternatives. */
    public val congestionController: () -> CongestionController,
    /** Send the fixed bit as random when the peer allows it (RFC 9287). */
    public val greaseQuicBit: Boolean,
    /** Close a connection whose peer keeps doing useless work (no-op flow-control updates, PING floods, duplicate data; glitch bucket: 1000 tokens, 33/s). On by default. */
    public val glitchProtection: Boolean,
    /** Server: follow a client that moves to another address (RFC 9000 section 9); false advertises `disable_active_migration` and drops datagrams from new addresses. */
    public val allowMigration: Boolean,
    /** Server: accept a move to a loopback or link-local address when the connection did not start on one (off by default: such a "client" is a reflection target). */
    public val allowMigrationToLoopback: Boolean,
    /** Probe the path MTU above 1200 bytes with DPLPMTUD (RFC 8899) on sockets that set DF; off keeps 1200. */
    public val pmtud: Boolean,
    /** `max_datagram_frame_size` we advertise (RFC 9221 section 3); 0 does not advertise it and refuses DATAGRAM frames. */
    public val maxDatagramFrameSize: Long,
    /** Received datagrams the core holds for the application; a full queue drops the oldest. */
    public val datagramReceiveQueue: Int,
    /** Datagrams the coroutine API queues for sending, in count and in bytes (32 / 1 MiB by default). */
    public val datagramSendQueue: Int,
    /** Byte ceiling of the same send queue; whichever of the two limits is reached first applies the [DatagramPolicy]. */
    public val datagramSendQueueBytes: Long,
    internal val limits: QuicLimits,
) {
    init {
        require(versions.isNotEmpty()) { "at least one QUIC version" }
        require(versions.distinct().size == versions.size) { "duplicate versions" }
        require(initialVersion == null || initialVersion in versions) { "initialVersion must be one of versions" }
        require(!maxIdleTimeout.isNegative() && maxIdleTimeout.isFinite()) {
            "maxIdleTimeout must be zero (none) or a positive finite duration"
        }
        require(handshakeTimeout.isPositive()) { "handshakeTimeout must be positive" }
        require(keepAlive == null || (keepAlive.isPositive() && keepAlive.isFinite())) { "keepAlive must be positive and finite, or null" }
        // with our idle timeout off (ZERO) only the peer's applies, and the interval follows it at run time
        require(keepAlive == null || maxIdleTimeout == Duration.ZERO || keepAlive <= maxIdleTimeout * 3 / 4) {
            "keepAlive must be at most 3/4 of maxIdleTimeout"
        }
        require(maxSendBuffer in 1..(1L shl 62)) { "maxSendBuffer must be 1..2^62" }
        require(connectionIdLength in 4..20) { "connectionIdLength must be 4..20" }
        require(maxUdpPayloadSize in 1200..65527) { "maxUdpPayloadSize must be 1200..65527" }
        require(activeConnectionIdLimit >= 2) { "activeConnectionIdLimit must be at least 2" }
        require(ackDelayExponent in 0..20) { "ackDelayExponent must be 0..20" }
        require(maxAckDelay < 16384.milliseconds) { "maxAckDelay must be below 2^14 ms" }
        require(initialRtt > Duration.ZERO && initialRtt <= 10.seconds) { "initialRtt must be positive and at most 10 s" }
        require(initialStreamWindow in 1..maxStreamWindow && initialConnectionWindow in 1..maxConnectionWindow) { "windows out of range" }
        require(maxBidiStreams in 0..(1L shl 60) && maxUniStreams in 0..(1L shl 60)) { "stream limits must be at most 2^60" }
        require(maxDatagramFrameSize in 0..65_535L) { "maxDatagramFrameSize must be 0..65535" }
        require(datagramReceiveQueue >= 1) { "datagramReceiveQueue must be positive" }
        require(datagramSendQueue >= 1 && datagramSendQueueBytes >= 1) { "datagram send queue limits must be positive" }
        require(defaultStreamErrorCode in 0..((1L shl 62) - 1)) { "error code must be 0..2^62-1" }
    }

    /**
     * The configured [initialRtt], kInitialRtt for a new path (RFC 9000 sections 8.2.4 and 9.4): a client endpoint's remembered RTT
     * ([withInitialRtt]) belongs to the first path's network, so it neither shortens path validation nor seeds another path's estimator.
     */
    internal var newPathInitialRtt: Duration = initialRtt
        private set

    /** This configuration with another [initialRtt] (a client endpoint's remembered RTT to the same server, RFC 9002 section 6.2.2). */
    internal fun withInitialRtt(rtt: Duration): QuicConfig =
        QuicConfig(
            maxIdleTimeout,
            handshakeTimeout,
            keepAlive,
            initialStreamWindow,
            initialConnectionWindow,
            maxStreamWindow,
            maxConnectionWindow,
            maxBidiStreams,
            maxUniStreams,
            maxSendBuffer,
            maxAckDelay,
            ackDelayExponent,
            activeConnectionIdLimit,
            connectionIdLength,
            maxUdpPayloadSize,
            versions,
            initialVersion,
            rtt,
            defaultStreamErrorCode,
            qlog,
            congestionController,
            greaseQuicBit,
            glitchProtection,
            allowMigration,
            allowMigrationToLoopback,
            pmtud,
            maxDatagramFrameSize,
            datagramReceiveQueue,
            datagramSendQueue,
            datagramSendQueueBytes,
            limits,
        ).also { it.newPathInitialRtt = newPathInitialRtt }

    /** The version a client starts with: [initialVersion] or the first of [versions]. */
    public val firstVersion: VersionProfile get() = initialVersion ?: versions[0]

    /**
     * The mutable side of [QuicConfig] behind [quicConfig]; [build] validates every value and throws IllegalArgumentException for one out
     * of range.
     */
    @KuicksilverDsl
    public class Builder {
        /** Default 30 s; see [QuicConfig.maxIdleTimeout]. [Duration.ZERO] leaves the idle timeout to the peer. */
        public var maxIdleTimeout: Duration = 30.seconds

        /** Default 10 s, positive; see [QuicConfig.handshakeTimeout]. */
        public var handshakeTimeout: Duration = 10.seconds

        /**
         * Default null (no keep-alive); a positive PING interval of at most 3/4 of [maxIdleTimeout] (any, when that is
         * [Duration.ZERO]) keeps a quiet connection open. See [QuicConfig.keepAlive].
         */
        public var keepAlive: Duration? = null

        /** Default 512 KiB; see [QuicConfig.initialStreamWindow]. */
        public var initialStreamWindow: Long = 524_288

        /** Default 768 KiB; see [QuicConfig.initialConnectionWindow]. */
        public var initialConnectionWindow: Long = 786_432

        /** Default 6 MiB; must be at least [initialStreamWindow]. See [QuicConfig.maxStreamWindow]. */
        public var maxStreamWindow: Long = 6_291_456

        /** Default 15 MiB; must be at least [initialConnectionWindow]. See [QuicConfig.maxConnectionWindow]. */
        public var maxConnectionWindow: Long = 15_728_640

        /** Default 100 concurrent bidirectional streams the peer may open; see [QuicConfig.maxBidiStreams]. */
        public var maxBidiStreams: Long = 100

        /** Default 100 concurrent unidirectional streams the peer may open; see [QuicConfig.maxUniStreams]. */
        public var maxUniStreams: Long = 100

        /** Default 4 MiB of unacknowledged send data per connection; see [QuicConfig.maxSendBuffer]. */
        public var maxSendBuffer: Long = 4_194_304

        /** Default 25 ms (the RFC 9000 default); see [QuicConfig.maxAckDelay]. */
        public var maxAckDelay: Duration = 25.milliseconds

        /** Default 3 (the RFC 9000 default); see [QuicConfig.ackDelayExponent]. */
        public var ackDelayExponent: Int = 3

        /** Default 4; see [QuicConfig.activeConnectionIdLimit]. */
        public var activeConnectionIdLimit: Int = 4

        /** Default 8 bytes, the endpoint's default too; see [QuicConfig.connectionIdLength]. */
        public var connectionIdLength: Int = 8

        /** Default 1452 bytes (1200..65527); see [QuicConfig.maxUdpPayloadSize]. A [QuicEndpoint] refuses more than 1500. */
        public var maxUdpPayloadSize: Int = 1452

        /**
         * Default `listOf(VersionProfile.V1)`; `listOf(VersionProfile.V2, VersionProfile.V1)` opts into QUIC v2 (RFC 9368/9369). Non-empty,
         * no duplicates.
         */
        public var versions: List<VersionProfile> = listOf(VersionProfile.V1)

        /** Default null (the first of [versions]); must be one of [versions]. See [QuicConfig.initialVersion]. */
        public var initialVersion: VersionProfile? = null

        /** Default 333 ms (RFC 9002 section 6.2.2), at most 10 s; see [QuicConfig.initialRtt]. */
        public var initialRtt: Duration = 333.milliseconds

        /** Default 0; see [QuicConfig.defaultStreamErrorCode]. Must fit a varint (0..2^62-1). */
        public var defaultStreamErrorCode: Long = 0

        /** Default null (no qlog); see [QuicConfig.qlog]. */
        public var qlog: QlogSink? = null

        /** Default `{ Cubic() }` (CUBIC with HyStart++, RFC 9438/9406); called once per path, so return a fresh controller each time. */
        @OptIn(ExperimentalKuicksilverApi::class)
        public var congestionController: () -> CongestionController = { Cubic() }

        /** Default true; see [QuicConfig.greaseQuicBit] (RFC 9287). */
        public var greaseQuicBit: Boolean = true

        /** Default true; see [QuicConfig.glitchProtection]. */
        public var glitchProtection: Boolean = true

        /** Default true; see [QuicConfig.allowMigration]. */
        public var allowMigration: Boolean = true

        /** Default false; see [QuicConfig.allowMigrationToLoopback]. */
        public var allowMigrationToLoopback: Boolean = false

        /** Default true; see [QuicConfig.pmtud] (RFC 8899). */
        public var pmtud: Boolean = true

        /** Default 65 535, the largest allowed; 0 turns datagrams off (RFC 9221 section 3). See [QuicConfig.maxDatagramFrameSize]. */
        public var maxDatagramFrameSize: Long = 65_535

        /** Default 128 received datagrams, at least 1; see [QuicConfig.datagramReceiveQueue]. */
        public var datagramReceiveQueue: Int = 128

        /** Default 32 datagrams, at least 1; see [QuicConfig.datagramSendQueue]. */
        public var datagramSendQueue: Int = 32

        /** Default 1 MiB, at least 1; see [QuicConfig.datagramSendQueueBytes]. */
        public var datagramSendQueueBytes: Long = 1_048_576
        internal var limits: QuicLimits = QuicLimits()

        /** An immutable [QuicConfig] from the current values; IllegalArgumentException names the first value out of range. */
        public fun build(): QuicConfig =
            QuicConfig(
                maxIdleTimeout,
                handshakeTimeout,
                keepAlive,
                initialStreamWindow,
                initialConnectionWindow,
                maxStreamWindow,
                maxConnectionWindow,
                maxBidiStreams,
                maxUniStreams,
                maxSendBuffer,
                maxAckDelay,
                ackDelayExponent,
                activeConnectionIdLimit,
                connectionIdLength,
                maxUdpPayloadSize,
                versions.toList(),
                initialVersion,
                initialRtt,
                defaultStreamErrorCode,
                qlog,
                congestionController,
                greaseQuicBit,
                glitchProtection,
                allowMigration,
                allowMigrationToLoopback,
                pmtud,
                maxDatagramFrameSize,
                datagramReceiveQueue,
                datagramSendQueue,
                datagramSendQueueBytes,
                limits,
            )
    }

    /** A builder pre-filled with these values, for a layer above that adjusts one setting (a Ktor engine adding its qlog sink). */
    @ExperimentalKuicksilverApi
    public fun toBuilder(): Builder =
        Builder().also {
            it.maxIdleTimeout = maxIdleTimeout
            it.handshakeTimeout = handshakeTimeout
            it.keepAlive = keepAlive
            it.initialStreamWindow = initialStreamWindow
            it.initialConnectionWindow = initialConnectionWindow
            it.maxStreamWindow = maxStreamWindow
            it.maxConnectionWindow = maxConnectionWindow
            it.maxBidiStreams = maxBidiStreams
            it.maxUniStreams = maxUniStreams
            it.maxSendBuffer = maxSendBuffer
            it.maxAckDelay = maxAckDelay
            it.ackDelayExponent = ackDelayExponent
            it.activeConnectionIdLimit = activeConnectionIdLimit
            it.connectionIdLength = connectionIdLength
            it.maxUdpPayloadSize = maxUdpPayloadSize
            it.initialVersion = initialVersion
            it.initialRtt = initialRtt
            it.defaultStreamErrorCode = defaultStreamErrorCode
            it.qlog = qlog
            it.congestionController = congestionController
            it.greaseQuicBit = greaseQuicBit
            it.glitchProtection = glitchProtection
            it.allowMigration = allowMigration
            it.allowMigrationToLoopback = allowMigrationToLoopback
            it.pmtud = pmtud
            it.maxDatagramFrameSize = maxDatagramFrameSize
            it.datagramReceiveQueue = datagramReceiveQueue
            it.datagramSendQueue = datagramSendQueue
            it.datagramSendQueueBytes = datagramSendQueueBytes
            it.limits = limits
            it.versions = versions.toList()
        }

    /** Holds [Default]. */
    public companion object {
        /** The default ceilings. */
        public val Default: QuicConfig = Builder().build()
    }
}

/** Builds a [QuicConfig] from the defaults. */
public inline fun quicConfig(block: QuicConfig.Builder.() -> Unit): QuicConfig = QuicConfig.Builder().apply(block).build()
