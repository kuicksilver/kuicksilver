// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.quic

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.annotations.KuicksilverDsl
import io.kuicksilver.annotations.SecuritySensitive
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** Per-connection ceilings (threat-model 3.2); refusal happens before memory is allocated. Overridden only by tests. */
internal class QuicLimits(
    val cryptoOutOfOrderPerLevel: Int = 65_536,
    /**
     * Post-handshake CRYPTO bytes TLS has not read yet (RFC 9000 section 7.5), within [cryptoOutOfOrderPerLevel] (the default is the
     * same, so only a smaller value narrows it); what TLS read and retransmissions of it cost nothing.
     */
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
     * closes silently with a [TimeoutKind.Idle] timeout; [Duration.ZERO] (the builder's null) advertises none and leaves the
     * timeout to the peer.
     */
    @property:InternalKuicksilverApi
    public val maxIdleTimeout: Duration,
    /**
     * A connection whose handshake has not completed after this long closes silently with a [TimeoutKind.Handshake] timeout.
     * Positive; [Duration.INFINITE] leaves only the idle timeout.
     */
    @property:InternalKuicksilverApi
    public val handshakeTimeout: Duration,
    /**
     * PING interval while the application is quiet; null disables keep-alive. Positive and finite, and at most 3/4 of
     * [maxIdleTimeout][QuicConfig.maxIdleTimeout] unless that is [Duration.ZERO] (then only the peer's idle timeout applies, and keep-alive is what holds
     * the connection). PINGs go out at least every half of the effective idle timeout, so a peer with a shorter timeout than
     * this interval does not close the connection (as quic-go's `KeepAlivePeriod`).
     */
    @property:InternalKuicksilverApi
    public val keepAlive: Duration?,
    /**
     * Receive window of each stream at its start, in bytes (`initial_max_stream_data_*`, RFC 9000 section 4.1); it doubles up to
     * [maxStreamWindow][QuicConfig.maxStreamWindow] while the application reads faster than the window allows.
     */
    @property:InternalKuicksilverApi
    public val initialStreamWindow: Long,
    /**
     * Receive window of the whole connection at its start, in bytes (`initial_max_data`); grows up to [maxConnectionWindow][QuicConfig.maxConnectionWindow] and stays at
     * least 1.5 x the largest stream window.
     */
    @property:InternalKuicksilverApi
    public val initialConnectionWindow: Long,
    /** Ceiling of a stream's receive window in bytes: the most data one stream can hold unread. */
    @property:InternalKuicksilverApi
    public val maxStreamWindow: Long,
    /** Ceiling of the connection's receive window in bytes: the most unread stream data the whole connection can hold. */
    @property:InternalKuicksilverApi
    public val maxConnectionWindow: Long,
    /**
     * Bidirectional streams the peer may have open at once (`initial_max_streams_bidi`, RFC 9000 section 4.6), at most 2^60; MAX_STREAMS
     * raises the limit as they close.
     */
    @property:InternalKuicksilverApi
    public val maxBidiStreams: Long,
    /** Unidirectional streams the peer may have open at once (`initial_max_streams_uni`, RFC 9000 section 4.6), at most 2^60. */
    @property:InternalKuicksilverApi
    public val maxUniStreams: Long,
    /**
     * Bytes the connection buffers for sending over all its streams until they are acknowledged, 1..2^62; a writer waits for
     * room beyond it.
     */
    @property:InternalKuicksilverApi
    public val maxSendBuffer: Long,
    /** Our `max_ack_delay` (RFC 9000 section 18.2): the longest we hold back an acknowledgement; 0..2^14-1 whole ms. */
    @property:InternalKuicksilverApi
    public val maxAckDelay: Duration,
    /** Our `ack_delay_exponent` (RFC 9000 section 18.2), 0..20: the scale of the ACK Delay field in our ACK frames. */
    @property:InternalKuicksilverApi
    public val ackDelayExponent: Int,
    /**
     * Our `active_connection_id_limit` (RFC 9000 section 5.1.1), at least 2: how many connection IDs of the peer we keep for migration and
     * rotation.
     */
    @property:InternalKuicksilverApi
    public val activeConnectionIdLimit: Int,
    /** Length in bytes (4..20) of the connection IDs we issue: the endpoint's `connectionIdLength`, set by [withEndpoint]. */
    internal val connectionIdLength: Int,
    /**
     * Advertised `max_udp_payload_size` (RFC 9000 section 18.2), also a ceiling of the datagrams we send
     * ([initialUdpPayloadSize][QuicConfig.initialUdpPayloadSize] and DPLPMTUD stay at or below it). The coroutine
     * runtime ([QuicEndpoint]) handles datagrams of up to 1500 bytes and refuses a larger value at `bind`/`connect`;
     * the sans-IO core takes up to 65527 with batches sized for it.
     */
    @property:InternalKuicksilverApi
    public val maxUdpPayloadSize: Int,
    /**
     * The UDP payload size, in bytes, a connection's first path starts with, Initial padding included (RFC 9000 section
     * 14: "Datagrams containing Initial packets MAY exceed 1200 bytes if the sender believes that the network path and
     * peer both support the size that it chooses"). 1200..65527, 1200 by default; it takes effect only on a socket that
     * sets DF, and is lowered to [maxSendUdpPayloadSize][QuicConfig.maxSendUdpPayloadSize],
     * [maxUdpPayloadSize][QuicConfig.maxUdpPayloadSize] and the peer's `max_udp_payload_size` (the one a 0-RTT ticket
     * remembers until the peer's arrive). The size is not trusted: DPLPMTUD's black-hole detection watches it from the
     * first datagram (a PTO while nothing was acknowledged, two in a row afterwards, with a datagram above 1200
     * unanswered, during the handshake too; or three lost large datagrams) and drops the path to 1200 when it does not
     * get through. With [pmtud][QuicConfig.pmtud] off it is also the most the path ever sends. A new path to another IP
     * address starts at 1200 (its MTU is unknown).
     */
    @property:InternalKuicksilverApi
    public val initialUdpPayloadSize: Int,
    /**
     * The largest UDP payload, in bytes, this endpoint sends (RFC 8899 section 4.4: "The MAX_PLPMTU MAY be reduced by
     * an application that sets a maximum to the size of datagrams it will send"), 1200..65527: a cap on
     * [initialUdpPayloadSize][QuicConfig.initialUdpPayloadSize] and on DPLPMTUD, below
     * [maxUdpPayloadSize][QuicConfig.maxUdpPayloadSize] when only the sending side should be limited (a tunnel). 65527
     * by default: no cap beyond [maxUdpPayloadSize][QuicConfig.maxUdpPayloadSize] and the peer's
     * `max_udp_payload_size`.
     */
    @property:InternalKuicksilverApi
    public val maxSendUdpPayloadSize: Int,
    /** Versions in preference order (RFC 9368 section 3: the client's Available Versions). Default is v1 only. */
    @property:InternalKuicksilverApi
    public val versions: List<VersionProfile>,
    /**
     * The version of a client's first flight (its Chosen Version); null means the first of [versions][QuicConfig.versions]. Lets a client
     * prefer v2 while still starting in v1 and upgrading through compatible negotiation (RFC 9368 section 2.3).
     */
    @property:InternalKuicksilverApi
    public val initialVersion: VersionProfile?,
    /**
     * RTT assumed before the first sample (RFC 9002 section 6.2.2), in (0, 10 s]: the first PTO is 3 x this (999 ms at the 333 ms
     * default, then 2 s, 4 s ...), and a path validation lasts at least 6 x this (RFC 9000 section 8.2.4). Lower recovers a lost
     * first flight sooner at the price of spurious retransmissions on slow links; see docs/guide/quic.md, "Configuration". A client
     * endpoint that already finished a connection to the same server address on its own socket starts from that connection's final
     * smoothed RTT instead (RFC 9002 section 6.2.2).
     */
    @property:InternalKuicksilverApi
    public val initialRtt: Duration,
    /** Error code sent in STOP_SENDING / RESET_STREAM when a channel is cancelled or closed with a cause. */
    @property:InternalKuicksilverApi
    public val defaultStreamErrorCode: Long,
    /** Receives a qlog trace per connection: the endpoint's `observability { qlog }`, set by [withEndpoint]. */
    internal val qlog: QlogSink?,
    /** Builds the congestion controller of each path; [Cubic] with HyStart++ by default, [NewReno] or the experimental [Bbr] as alternatives. */
    @property:InternalKuicksilverApi
    public val congestionController: () -> CongestionController,
    /** Send the fixed bit as random when the peer allows it (RFC 9287). */
    @property:InternalKuicksilverApi
    public val greaseQuicBit: Boolean,
    /** Close a connection whose peer keeps doing useless work (no-op flow-control updates, PING floods, duplicate data; glitch bucket: 1000 tokens, 33/s). On by default. */
    @property:InternalKuicksilverApi
    public val glitchProtection: Boolean,
    /** Server: follow a client that moves to another address (RFC 9000 section 9); false advertises `disable_active_migration` and drops datagrams from new addresses. */
    @property:InternalKuicksilverApi
    public val allowMigration: Boolean,
    /** Server: accept a move to a loopback or link-local address when the connection did not start on one (off by default: such a "client" is a reflection target). */
    @property:InternalKuicksilverApi
    public val allowMigrationToLoopback: Boolean,
    /**
     * Search for a larger path MTU with DPLPMTUD (RFC 8899) on sockets that set DF, from
     * [initialUdpPayloadSize][QuicConfig.initialUdpPayloadSize] up to
     * [maxSendUdpPayloadSize][QuicConfig.maxSendUdpPayloadSize], [maxUdpPayloadSize][QuicConfig.maxUdpPayloadSize] and
     * the peer's limit. Off, no path sends more than [initialUdpPayloadSize][QuicConfig.initialUdpPayloadSize] (1200 by
     * default); above 1200 its black-hole detection still runs, and probes go from 1200 up to that size, never above
     * it: after a fall back, and on a new path to another IP address, which starts at 1200.
     */
    @property:InternalKuicksilverApi
    public val pmtud: Boolean,
    /** Let validated ICMP Packet Too Big messages and EMSGSIZE speed up DPLPMTUD as hints; see [Builder.PathMtu.icmpHints]. */
    @property:InternalKuicksilverApi
    public val pmtudIcmpHints: Boolean,
    /** Client: move to the server's preferred address after the handshake; see [Builder.followPreferredAddress]. */
    @property:InternalKuicksilverApi
    public val followPreferredAddress: Boolean,
    /** `max_datagram_frame_size` we advertise (RFC 9221 section 3); 0 (the builder's null) does not advertise it and refuses DATAGRAM frames. */
    @property:InternalKuicksilverApi
    public val maxDatagramFrameSize: Long,
    /** Received datagrams the core holds for the application; a full queue drops the oldest. */
    @property:InternalKuicksilverApi
    public val datagramReceiveQueue: Int,
    /** Datagrams the coroutine API queues for sending, in count and in bytes (32 / 1 MiB by default). */
    @property:InternalKuicksilverApi
    public val datagramSendQueue: Int,
    /** Byte ceiling of the same send queue; whichever of the two limits is reached first applies the [DatagramPolicy]. */
    @property:InternalKuicksilverApi
    public val datagramSendQueueBytes: Long,
    internal val limits: QuicLimits,
    /**
     * Advertise `reset_stream_at` (draft-ietf-quic-reliable-stream-reset): the peer may reset a stream with
     * RESET_STREAM_AT, and [QuicStream.resetAt] uses the frame when the peer advertised it too. Off by default.
     */
    @property:InternalKuicksilverApi
    public val resetStreamAt: Boolean = false,
) {
    init {
        require(versions.isNotEmpty()) { "at least one QUIC version" }
        require(versions.distinct().size == versions.size) { "duplicate versions" }
        require(initialVersion == null || initialVersion in versions) { "expert { initialVersion } must be one of versions" }
        require(!maxIdleTimeout.isNegative() && maxIdleTimeout.isFinite()) {
            "maxIdleTimeout must be positive and finite, or null (none)"
        }
        // RFC 9000 section 18.2: transport parameters carry milliseconds, and the deadlines run on the advertised value
        require(maxIdleTimeout.isWholeMilliseconds()) { "maxIdleTimeout must be a whole number of milliseconds, not $maxIdleTimeout" }
        require(handshakeTimeout.isPositive()) { "handshakeTimeout must be positive" }
        require(keepAlive == null || (keepAlive.isPositive() && keepAlive.isFinite())) { "keepAlive must be positive and finite, or null" }
        // with our idle timeout off (ZERO) only the peer's applies, and the interval follows it at run time
        require(keepAlive == null || maxIdleTimeout == Duration.ZERO || keepAlive <= maxIdleTimeout * 3 / 4) {
            "keepAlive must be at most 3/4 of maxIdleTimeout"
        }
        require(maxSendBuffer in 1..(1L shl 62)) { "flowControl { maxSendBuffer } must be 1..2^62" }
        require(connectionIdLength in 4..20) { "connectionIdLength must be 4..20" }
        require(maxUdpPayloadSize in 1200..65527) { "pathMtu { maxReceive } must be 1200..65527" }
        // RFC 9000 section 14: "QUIC MUST NOT be used if the network path cannot support a maximum datagram size of at least 1200
        // bytes"; section 14.1: datagrams carrying Initial packets are at least 1200 bytes
        require(initialUdpPayloadSize in 1200..65527) { "pathMtu { initial } must be 1200..65527" }
        require(maxSendUdpPayloadSize in 1200..65527) { "pathMtu { maxSend } must be 1200..65527" }
        require(activeConnectionIdLimit >= 2) { "expert { activeConnectionIdLimit } must be at least 2" }
        require(ackDelayExponent in 0..20) { "expert { ackDelayExponent } must be 0..20" }
        require(!maxAckDelay.isNegative() && maxAckDelay < 16384.milliseconds) { "expert { maxAckDelay } must be 0..2^14-1 ms" }
        require(maxAckDelay.isWholeMilliseconds()) {
            "expert { maxAckDelay } must be a whole number of milliseconds (max_ack_delay is advertised in them), not $maxAckDelay"
        }
        require(initialRtt > Duration.ZERO && initialRtt <= 10.seconds) { "expert { initialRtt } must be positive and at most 10 s" }
        require(initialStreamWindow in 1..maxStreamWindow && initialConnectionWindow in 1..maxConnectionWindow) {
            "flowControl windows out of range: initial windows must be 1..their max"
        }
        require(maxStreamWindow <= MAX_WINDOW && maxConnectionWindow <= MAX_WINDOW) {
            "flowControl { maxStreamWindow } and { maxConnectionWindow } must be at most 2^60 (MAX_WINDOW), not " +
                "$maxStreamWindow and $maxConnectionWindow"
        }
        require(maxBidiStreams in 0..(1L shl 60) && maxUniStreams in 0..(1L shl 60)) {
            "maxBidiStreams and expert { maxUniStreams } must be 0..2^60"
        }
        require(maxDatagramFrameSize in 0..65_535L) { "datagrams { maxFrameSize } must be 1..65535, or null (no datagrams)" }
        require(datagramReceiveQueue >= 1) { "datagrams { receiveQueue } must be positive" }
        require(datagramSendQueue >= 1 && datagramSendQueueBytes >= 1) { "datagrams { sendQueue } and { sendQueueBytes } must be positive" }
        require(defaultStreamErrorCode in 0..((1L shl 62) - 1)) { "expert { cancelErrorCode } must be 0..2^62-1" }
    }

    /**
     * The configured [initialRtt], kInitialRtt for a new path (RFC 9000 sections 8.2.4 and 9.4): a client endpoint's remembered RTT
     * ([withInitialRtt]) belongs to the first path's network, so it neither shortens path validation nor seeds another path's estimator.
     */
    internal var newPathInitialRtt: Duration = initialRtt
        private set

    /** This configuration with another [initialRtt] (a client endpoint's remembered RTT to the same server, RFC 9002 section 6.2.2). */
    internal fun withInitialRtt(rtt: Duration): QuicConfig = copy(initialRtt = rtt).also { it.newPathInitialRtt = newPathInitialRtt }

    /**
     * This configuration with the endpoint's connection ID length and qlog sink: the one place for both is the endpoint
     * (`QuicEndpointConfig.connectionIdLength` and `observability { qlog }`), which applies them to every connection.
     */
    internal fun withEndpoint(
        connectionIdLength: Int,
        endpointQlog: QlogSink?,
    ): QuicConfig {
        // a sink of the connection's own is set only by this module's tests; the endpoint's wins
        val qlog = endpointQlog ?: this.qlog
        return if (connectionIdLength == this.connectionIdLength && qlog === this.qlog) {
            this
        } else {
            copy(connectionIdLength = connectionIdLength, qlog = qlog).also { it.newPathInitialRtt = newPathInitialRtt }
        }
    }

    private fun copy(
        initialRtt: Duration = this.initialRtt,
        connectionIdLength: Int = this.connectionIdLength,
        qlog: QlogSink? = this.qlog,
    ): QuicConfig =
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
            initialUdpPayloadSize,
            maxSendUdpPayloadSize,
            versions,
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
            pmtudIcmpHints,
            followPreferredAddress,
            maxDatagramFrameSize,
            datagramReceiveQueue,
            datagramSendQueue,
            datagramSendQueueBytes,
            limits,
            resetStreamAt,
        )

    /** The version a client starts with: [initialVersion][QuicConfig.initialVersion] or the first of [versions][QuicConfig.versions]. */
    @InternalKuicksilverApi
    public val firstVersion: VersionProfile get() = initialVersion ?: versions[0]

    /**
     * The mutable side of [QuicConfig] behind [quicConfig], in groups: the options most applications touch at the top,
     * [flowControl], [pathMtu], [datagrams] and [migration] for tuning, and [expert] (experimental) for RFC knobs and
     * interop. [build] validates every value and throws IllegalArgumentException naming the first one out of range.
     *
     * The connection ID length and the qlog sink are no options here: the endpoint sets both for all its connections
     * (`QuicEndpointConfig.Builder.connectionIdLength`, `observability { qlog }`).
     */
    @KuicksilverDsl
    public class Builder {
        /**
         * The options assigned explicitly (`handshakeTimeout`, `expert.maxUniStreams`, ...): a layer above refuses those it
         * derives, and derives a default of its own for the others it tracks.
         */
        internal val assigned: MutableSet<String> = mutableSetOf()

        /**
         * Default 30 s; null advertises no `max_idle_timeout` (RFC 9000 section 10.1) and leaves the idle timeout to the
         * peer. Positive, finite and a whole number of milliseconds otherwise (the parameter carries milliseconds): a connection idle for the smaller of both peers' values (never less than 3 x
         * PTO) closes silently with a [TimeoutKind.Idle] timeout.
         */
        public var maxIdleTimeout: Duration? = 30.seconds

        /**
         * Default 10 s, positive: a connection whose handshake has not completed after this long closes silently with a
         * [TimeoutKind.Handshake] timeout; [Duration.INFINITE] leaves only the idle timeout. The Ktor client derives it from its
         * `connectTimeout`.
         */
        public var handshakeTimeout: Duration = 10.seconds
            set(value) {
                field = value
                assigned += "handshakeTimeout"
            }

        /**
         * Default null (no keep-alive): the PING interval while the application is quiet. Positive and finite, and at most
         * 3/4 of [maxIdleTimeout] (any, when that is null: then only the peer's idle timeout applies, and keep-alive is what
         * holds the connection). PINGs go out at least every half of the effective idle timeout, so a peer with a shorter
         * timeout than this interval does not close the connection (as quic-go's `KeepAlivePeriod`).
         */
        public var keepAlive: Duration? = null

        /**
         * Default 100: bidirectional streams the peer may have open at once (`initial_max_streams_bidi`, RFC 9000 section
         * 4.6), at most 2^60; MAX_STREAMS raises the limit as they close. For HTTP/3, the requests a client may have in flight;
         * a Ktor engine raises the default to fit its WebTransport sessions.
         */
        public var maxBidiStreams: Long = 100
            set(value) {
                field = value
                assigned += "maxBidiStreams"
            }

        /**
         * Default `listOf(VersionProfile.V1)`: versions in preference order (RFC 9368 section 3: the client's Available
         * Versions); `listOf(VersionProfile.V2, VersionProfile.V1)` opts into QUIC v2 (RFC 9368/9369). Non-empty, no duplicates.
         */
        public var versions: List<VersionProfile> = listOf(VersionProfile.V1)

        /**
         * Default `{ Cubic() }` (CUBIC with HyStart++, RFC 9438/9406); [NewReno] or the experimental [Bbr] as alternatives.
         * Called once per path, so return a fresh controller each time.
         */
        @OptIn(ExperimentalKuicksilverApi::class)
        public var congestionController: () -> CongestionController = { Cubic() }

        /** Receive windows and the send buffer: how much data a connection holds unread or unacknowledged. */
        public val flowControl: FlowControl = FlowControl(assigned)

        /** Sets the [flowControl] options. */
        public fun flowControl(block: FlowControl.() -> Unit) {
            flowControl.block()
        }

        /** Datagram sizes: what a connection advertises, starts with and searches for (DPLPMTUD, RFC 8899). */
        public val pathMtu: PathMtu = PathMtu()

        /** Sets the [pathMtu] options. */
        public fun pathMtu(block: PathMtu.() -> Unit) {
            pathMtu.block()
        }

        /** Unreliable datagrams (RFC 9221): whether they are offered, and the queues of the coroutine API. */
        public val datagrams: Datagrams = Datagrams()

        /** Sets the [datagrams] options. */
        public fun datagrams(block: Datagrams.() -> Unit) {
            datagrams.block()
        }

        /** Connection migration (RFC 9000 section 9): what a server accepts and whether a client follows a preferred address. */
        public val migration: Migration = Migration()

        /** Sets the [migration] options. */
        public fun migration(block: Migration.() -> Unit) {
            migration.block()
        }

        /** RFC knobs and interop switches few applications need; experimental. */
        @ExperimentalKuicksilverApi
        public val expert: Expert = Expert(assigned)

        /** Sets the [expert] options. */
        @ExperimentalKuicksilverApi
        public fun expert(block: Expert.() -> Unit) {
            expert.block()
        }

        /** Set only by this module (its tests, and [toBuilder]); the endpoint applies its own with [QuicConfig.withEndpoint]. */
        internal var connectionIdLength: Int = 8
        internal var qlog: QlogSink? = null
        internal var limits: QuicLimits = QuicLimits()

        /** The receive windows and the send buffer of a [Builder]. */
        @KuicksilverDsl
        public class FlowControl internal constructor(
            private val assigned: MutableSet<String>,
        ) {
            /**
             * Default 512 KiB: the receive window of each stream at its start, in bytes (`initial_max_stream_data_*`, RFC 9000
             * section 4.1); it doubles up to [maxStreamWindow] while the application reads faster than the window allows.
             */
            public var initialStreamWindow: Long = 524_288

            /**
             * Default 768 KiB: the receive window of the whole connection at its start, in bytes (`initial_max_data`); grows up
             * to [maxConnectionWindow] and stays at least 1.5 x the largest stream window.
             */
            public var initialConnectionWindow: Long = 786_432

            /** Default 6 MiB, at least [initialStreamWindow], at most [MAX_WINDOW]: the most data one stream can hold unread. */
            public var maxStreamWindow: Long = 6_291_456

            /**
             * Default 15 MiB, at least [initialConnectionWindow], at most [MAX_WINDOW]: the most unread stream data the whole
             * connection can hold.
             * A Ktor engine raises the default to fit its WebTransport sessions.
             */
            public var maxConnectionWindow: Long = 15_728_640
                set(value) {
                    field = value
                    assigned += "flowControl.maxConnectionWindow"
                }

            /**
             * Default 4 MiB, 1..2^62: bytes the connection buffers for sending over all its streams until they are
             * acknowledged; a writer waits for room beyond it. A write also takes no byte beyond the peer's credit for the
             * stream or the connection (RFC 9000 section 4.1), so a stream whose peer stops reading it never fills the
             * buffer the other streams need.
             */
            public var maxSendBuffer: Long = 4_194_304
        }

        /** The datagram sizes of a [Builder] (RFC 9000 section 14, RFC 8899). */
        @KuicksilverDsl
        public class PathMtu internal constructor() {
            /**
             * Default 1452 bytes (1200..65527): the advertised `max_udp_payload_size` (RFC 9000 section 18.2), the largest
             * datagram this endpoint receives, and also a ceiling of the datagrams it sends ([initial] and DPLPMTUD stay at
             * or below it). The coroutine runtime ([QuicEndpoint]) handles datagrams of up to 1500 bytes and refuses a larger
             * value at `bind`/`connect`; the sans-IO core takes up to 65527 with batches sized for it.
             */
            public var maxReceive: Int = 1452

            /**
             * Default 1200 bytes (1200..65527; less is refused): the UDP payload size a connection's first path starts with,
             * Initial padding included, e.g. 1350 on a path known to carry it (RFC 9000 section 14: "Datagrams containing
             * Initial packets MAY exceed 1200 bytes if the sender believes that the network path and peer both support the size
             * that it chooses"). It takes effect only on a socket that sets DF, and is lowered to [maxSend], [maxReceive] and the
             * peer's `max_udp_payload_size` (the one a 0-RTT ticket remembers until the peer's arrive). The size is not
             * trusted: DPLPMTUD's black-hole detection watches it from the first datagram (a PTO while nothing was acknowledged,
             * two in a row afterwards, with a datagram above 1200 unanswered, during the handshake too; or three lost large
             * datagrams) and drops the path to 1200 when it does not get through. With [discovery] off it is also the most the
             * path ever sends. A new path to another IP address starts at 1200 (its MTU is unknown).
             */
            public var initial: Int = 1200

            /**
             * Default 65527 (no cap of its own; 1200..65527): the largest UDP payload this endpoint sends, e.g. 1372 inside a
             * WireGuard tunnel (RFC 8899 section 4.4: "The MAX_PLPMTU MAY be reduced by an application that sets a maximum to
             * the size of datagrams it will send"): a cap on [initial] and on DPLPMTUD, below [maxReceive] when only the
             * sending side should be limited.
             */
            public var maxSend: Int = 65527

            /**
             * Default true: search for a larger path MTU with DPLPMTUD (RFC 8899) on sockets that set DF, from [initial] up to
             * [maxSend], [maxReceive] and the peer's limit. False: no path sends more than [initial] (1200 by default); above
             * 1200 its black-hole detection still runs, and probes go from 1200 up to that size, never above it: after a fall
             * back, and on a new path to another IP address, which starts at 1200.
             */
            public var discovery: Boolean = true

            /**
             * Default true. Where the socket reports them, an ICMP Packet Too Big (Linux and Android with the accelerated
             * socket) and a send the kernel refused as too large (EMSGSIZE, every accelerated socket) speed up DPLPMTUD as hints
             * (RFC 8899 section 4.6, RFC 9000 section 14.2.1): a Packet Too Big must quote one of this connection's packets on
             * its active path and report at least 1200 bytes of payload, at most 64 a second per endpoint are looked at, and it
             * only ends larger probes early or drops the MTU to 1200 provisionally: a probe of the old size that is
             * acknowledged restores it and suspends Packet Too Big processing for 600 s. Without such a socket it changes
             * nothing; false ignores them.
             */
            public var icmpHints: Boolean = true
        }

        /** The datagram options of a [Builder] (RFC 9221). */
        @KuicksilverDsl
        public class Datagrams internal constructor() {
            /**
             * Default 65 535, the largest allowed: the `max_datagram_frame_size` advertised (RFC 9221 section 3), 1..65535;
             * null does not advertise it and refuses DATAGRAM frames (no datagrams).
             */
            public var maxFrameSize: Long? = 65_535

            /** Default 128, at least 1: received datagrams the core holds for the application; a full queue drops the oldest. */
            public var receiveQueue: Int = 128

            /** Default 32, at least 1: datagrams the coroutine API queues for sending. */
            public var sendQueue: Int = 32

            /**
             * Default 1 MiB, at least 1: the byte ceiling of the same send queue; whichever of the two limits is reached first
             * applies the [DatagramPolicy].
             */
            public var sendQueueBytes: Long = 1_048_576
        }

        /** The connection migration options of a [Builder] (RFC 9000 section 9). */
        @KuicksilverDsl
        public class Migration internal constructor() {
            /**
             * Default true. Server: follow a client that moves to another address (RFC 9000 section 9); false advertises
             * `disable_active_migration` and drops datagrams from new addresses.
             */
            public var allow: Boolean = true

            /**
             * Default false. Server: accept a move to a loopback or link-local address when the connection did not start on one
             * (such a "client" is a reflection target). True only weakens the default.
             */
            @DelicateKuicksilverApi
            @SecuritySensitive
            public var allowToLoopback: Boolean = false

            /**
             * Default true (RFC 9000 section 9.6: a client SHOULD). A client whose server advertises a preferred address of the
             * family it uses validates a path there once the handshake is confirmed, with the server's sequence-1 connection ID,
             * and moves the connection there when the server answers ([PathChangeReason.PreferredAddress]); the original path
             * then closes. Until then only probes go there, and a failed validation leaves the connection where it is. A public
             * server's preferred address on a loopback, link-local or private address, or any unspecified, multicast or
             * broadcast one, is ignored (threat-model 3.14). The server's `disable_active_migration` does not stop the move, and
             * after it the client may migrate. False stays put.
             */
            public var followPreferredAddress: Boolean = true
        }

        /** The expert options of a [Builder]: RFC knobs and interop switches; experimental. */
        @ExperimentalKuicksilverApi
        @KuicksilverDsl
        public class Expert internal constructor(
            private val assigned: MutableSet<String>,
        ) {
            /**
             * Default 100: unidirectional streams the peer may have open at once (`initial_max_streams_uni`, RFC 9000 section
             * 4.6), at most 2^60. HTTP/3 needs at least 3 (RFC 9114 section 6.2); a Ktor engine raises the default to fit its
             * WebTransport sessions.
             */
            public var maxUniStreams: Long = 100
                set(value) {
                    field = value
                    assigned += "expert.maxUniStreams"
                }

            /**
             * Default 25 ms (the RFC 9000 default), 0..2^14-1 ms in whole milliseconds: our `max_ack_delay` (RFC 9000 section
             * 18.2), the longest we hold back an acknowledgement; the advertised value and the ACK deadline are the same.
             */
            public var maxAckDelay: Duration = 25.milliseconds

            /** Default 3 (the RFC 9000 default), 0..20: our `ack_delay_exponent` (RFC 9000 section 18.2), the scale of the ACK Delay field. */
            public var ackDelayExponent: Int = 3

            /**
             * Default 4, at least 2: our `active_connection_id_limit` (RFC 9000 section 5.1.1), how many connection IDs of the
             * peer we keep for migration and rotation.
             */
            public var activeConnectionIdLimit: Int = 4

            /**
             * Default null (the first of `versions`); must be one of them: the version of a client's first flight (its Chosen
             * Version). Lets a client prefer v2 while still starting in v1 and upgrading through compatible negotiation (RFC
             * 9368 section 2.3).
             */
            public var initialVersion: VersionProfile? = null

            /**
             * Default 333 ms (RFC 9002 section 6.2.2), in (0, 10 s]: the RTT assumed before the first sample. The first PTO is
             * 3 x this (999 ms at the default, then 2 s, 4 s ...), and a path validation lasts at least 6 x this (RFC 9000
             * section 8.2.4). Lower recovers a lost first flight sooner at the price of spurious retransmissions on slow links;
             * see docs/guide/quic.md, "Configuration". A client endpoint that already finished a connection to the same server
             * address on its own socket starts from that connection's final smoothed RTT instead (RFC 9002 section 6.2.2).
             */
            public var initialRtt: Duration = 333.milliseconds

            /**
             * Default 0, 0..2^62-1: the error code sent in STOP_SENDING / RESET_STREAM when a channel is cancelled or closed
             * with a cause. HTTP/3 uses H3_REQUEST_CANCELLED, so a Ktor engine sets it itself.
             */
            public var cancelErrorCode: Long = 0
                set(value) {
                    field = value
                    assigned += "expert.cancelErrorCode"
                }

            /** Default true: send the fixed bit as random when the peer allows it (RFC 9287). */
            public var greaseQuicBit: Boolean = true

            /**
             * Default true: close a connection whose peer keeps doing useless work (no-op flow-control updates, PING floods,
             * duplicate data; glitch bucket: 1000 tokens, 33/s). False only weakens the default.
             */
            @DelicateKuicksilverApi
            @SecuritySensitive
            public var glitchProtection: Boolean = true

            /**
             * Default false: advertise `reset_stream_at` (draft-ietf-quic-reliable-stream-reset): the peer may reset a stream
             * with RESET_STREAM_AT, and [QuicStream.resetAt] uses the frame when the peer advertised it too. HTTP/3 turns it on
             * for WebTransport itself.
             */
            public var resetStreamAt: Boolean = false
                set(value) {
                    field = value
                    assigned += "expert.resetStreamAt"
                }
        }

        /** The tracked options assigned explicitly here, such as `expert.maxUniStreams`: a layer above refuses or keeps them. */
        @InternalKuicksilverApi
        public fun assignedOptions(): Set<String> = assigned.toSet()

        /** An immutable [QuicConfig] from the current values; IllegalArgumentException names the first value out of range. */
        @OptIn(DelicateKuicksilverApi::class)
        public fun build(): QuicConfig {
            val idle = maxIdleTimeout
            require(idle == null || (idle.isPositive() && idle.isFinite())) {
                "maxIdleTimeout must be positive and finite, or null (none): Duration.ZERO is no longer \"none\""
            }
            // below 1 ms it would be advertised as 0, which is "no idle timeout" (RFC 9000 section 18.2)
            require(idle == null || idle.isWholeMilliseconds()) {
                "maxIdleTimeout must be a whole number of milliseconds (max_idle_timeout is advertised in them), not $idle"
            }
            val frame = datagrams.maxFrameSize
            require(frame == null || frame in 1..65_535L) { "datagrams { maxFrameSize } must be 1..65535, or null (no datagrams)" }
            return QuicConfig(
                idle ?: Duration.ZERO,
                handshakeTimeout,
                keepAlive,
                flowControl.initialStreamWindow,
                flowControl.initialConnectionWindow,
                flowControl.maxStreamWindow,
                flowControl.maxConnectionWindow,
                maxBidiStreams,
                expert.maxUniStreams,
                flowControl.maxSendBuffer,
                expert.maxAckDelay,
                expert.ackDelayExponent,
                expert.activeConnectionIdLimit,
                connectionIdLength,
                pathMtu.maxReceive,
                pathMtu.initial,
                pathMtu.maxSend,
                versions.toList(),
                expert.initialVersion,
                expert.initialRtt,
                expert.cancelErrorCode,
                qlog,
                congestionController,
                expert.greaseQuicBit,
                expert.glitchProtection,
                migration.allow,
                migration.allowToLoopback,
                pathMtu.discovery,
                pathMtu.icmpHints,
                migration.followPreferredAddress,
                frame ?: 0,
                datagrams.receiveQueue,
                datagrams.sendQueue,
                datagrams.sendQueueBytes,
                limits,
                expert.resetStreamAt,
            )
        }
    }

    /**
     * A builder pre-filled with these values, to change some of them: `config.toBuilder().apply { keepAlive = 15.seconds }.build()`.
     * Nothing counts as assigned explicitly in it (a layer above that refuses derived options accepts a copy).
     */
    @OptIn(DelicateKuicksilverApi::class)
    public fun toBuilder(): Builder =
        Builder().also {
            it.maxIdleTimeout = maxIdleTimeout.takeIf { t -> t != Duration.ZERO }
            it.handshakeTimeout = handshakeTimeout
            it.keepAlive = keepAlive
            it.maxBidiStreams = maxBidiStreams
            it.versions = versions.toList()
            it.congestionController = congestionController
            it.flowControl.initialStreamWindow = initialStreamWindow
            it.flowControl.initialConnectionWindow = initialConnectionWindow
            it.flowControl.maxStreamWindow = maxStreamWindow
            it.flowControl.maxConnectionWindow = maxConnectionWindow
            it.flowControl.maxSendBuffer = maxSendBuffer
            it.pathMtu.maxReceive = maxUdpPayloadSize
            it.pathMtu.initial = initialUdpPayloadSize
            it.pathMtu.maxSend = maxSendUdpPayloadSize
            it.pathMtu.discovery = pmtud
            it.pathMtu.icmpHints = pmtudIcmpHints
            it.datagrams.maxFrameSize = maxDatagramFrameSize.takeIf { n -> n > 0 }
            it.datagrams.receiveQueue = datagramReceiveQueue
            it.datagrams.sendQueue = datagramSendQueue
            it.datagrams.sendQueueBytes = datagramSendQueueBytes
            it.migration.allow = allowMigration
            it.migration.allowToLoopback = allowMigrationToLoopback
            it.migration.followPreferredAddress = followPreferredAddress
            it.expert.maxUniStreams = maxUniStreams
            it.expert.maxAckDelay = maxAckDelay
            it.expert.ackDelayExponent = ackDelayExponent
            it.expert.activeConnectionIdLimit = activeConnectionIdLimit
            it.expert.initialVersion = initialVersion
            it.expert.initialRtt = initialRtt
            it.expert.cancelErrorCode = defaultStreamErrorCode
            it.expert.greaseQuicBit = greaseQuicBit
            it.expert.glitchProtection = glitchProtection
            it.expert.resetStreamAt = resetStreamAt
            it.connectionIdLength = connectionIdLength
            it.qlog = qlog
            it.limits = limits
            it.assigned.clear()
        }

    /** Holds [Default] and [MAX_WINDOW]. */
    public companion object {
        /** The default ceilings. */
        public val Default: QuicConfig = Builder().build()

        /**
         * The largest `flowControl { maxStreamWindow }` and `{ maxConnectionWindow }`: 2^60 bytes. The limits a window
         * advertises (MAX_DATA, MAX_STREAM_DATA) are variable-length integers of at most 2^62-1 (RFC 9000 section 16), and
         * a window of at most 2^60 leaves the received count three times that before the clamp at 2^62-1 has to act; the
         * window doubling of the auto-tuning cannot overflow below it. No memory holds such a window: it is a bound of the
         * arithmetic, not a tuning value.
         */
        public const val MAX_WINDOW: Long = 1L shl 60
    }
}

/** Whether this finite duration is a whole number of milliseconds, as a transport parameter carries it (RFC 9000 section 18.2). */
private fun Duration.isWholeMilliseconds(): Boolean = inWholeMilliseconds.milliseconds == this

/** Builds a [QuicConfig] from the defaults. */
public inline fun quicConfig(block: QuicConfig.Builder.() -> Unit): QuicConfig = QuicConfig.Builder().apply(block).build()
