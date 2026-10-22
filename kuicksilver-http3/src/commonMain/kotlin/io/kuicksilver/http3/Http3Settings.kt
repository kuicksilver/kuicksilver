// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.KuicksilverDsl

/** Local HTTP/3 settings: what we advertise in SETTINGS (RFC 9114 section 7.2.4) and our own resource limits; build with [http3Settings]. */
public class Http3Settings private constructor(
    /** `SETTINGS_QPACK_MAX_TABLE_CAPACITY` we advertise: how much of our decoder's table the peer may fill (0 by default; [Builder.enableQpackDynamicTable] raises it). */
    public val qpackMaxTableCapacity: Long,
    /** `SETTINGS_QPACK_BLOCKED_STREAMS` we advertise (0 by default). */
    public val qpackBlockedStreams: Long,
    /** Ceiling of our own encoder's dynamic table, whatever the peer allows; 4096 by default, 0..2^30. */
    public val encoderMaxTableCapacity: Long,
    /**
     * Largest decoded field section (headers or trailers) we accept, advertised as `SETTINGS_MAX_FIELD_SECTION_SIZE`;
     * 64 KiB by default, 1..2^30.
     */
    public val maxFieldSectionSize: Long,
    /** Advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 9220): servers that accept Extended CONNECT turn it on. */
    public val enableConnectProtocol: Boolean,
    /** `SETTINGS_H3_DATAGRAM` value; the setting is always sent (RFC 9297; threat-model 3.17: no fingerprint by omission). */
    public val h3Datagram: Boolean,
    /** Send a reserved setting, frame and unidirectional stream (RFC 9114 sections 6.2.3, 7.2.4.1, 7.2.8) to keep peers tolerant. */
    public val grease: Boolean,
    /** Interim (1xx) responses a client accepts before the final one; 5 by default, at least 0. */
    public val maxInformationalResponses: Int,
    /** PRIORITY_UPDATE frames remembered for streams not yet open; 32 by default, at least 0. */
    public val maxEarlyPriorityUpdates: Int,
    /** Close a connection whose peer floods useless frames (glitch limiter: 1000 tokens, 33/s). */
    public val glitchProtection: Boolean,
    /** Server: what happens to requests received in 0-RTT before the handshake completed (only with `QuicServerConfig.earlyData`). */
    @property:ExperimentalKuicksilverApi
    public val earlyData: Http3EarlyDataPolicy,
    /**
     * Speak WebTransport over HTTP/3 (draft-ietf-webtrans-http3-16): advertise its SETTINGS and route WebTransport streams to
     * sessions. Needs [enableConnectProtocol] and [h3Datagram].
     */
    @property:ExperimentalKuicksilverApi
    public val webTransport: Boolean,
) {
    /** Mutable form of [Http3Settings], used through [http3Settings] or [toBuilder]; ranges are checked by [build]. */
    @KuicksilverDsl
    public class Builder {
        /** Dynamic table capacity in bytes the peer's encoder may use toward our decoder, 0..2^30; 0 (static table only) by default. */
        public var qpackMaxTableCapacity: Long = 0

        /** Streams that may wait for dynamic table inserts at once (RFC 9204 section 2.1.2), 0..65535; 0 by default. */
        public var qpackBlockedStreams: Long = 0

        /** Ceiling in bytes of our encoder's dynamic table, applied below the peer's capacity, 0..2^30; 4096 by default. */
        public var encoderMaxTableCapacity: Long = 4096

        /** Largest decoded field section in bytes we accept and advertise (RFC 9114 section 4.2.2), 1..2^30; 65536 by default. */
        public var maxFieldSectionSize: Long = 65_536

        /** Advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL=1` so peers may send Extended CONNECT (RFC 9220); false by default. */
        public var enableConnectProtocol: Boolean = false

        /** Advertise `SETTINGS_H3_DATAGRAM=1` (RFC 9297); true by default; [Http3Endpoint] sends 0 when QUIC datagrams are off. */
        public var h3Datagram: Boolean = true

        /** Send a reserved setting, frame and unidirectional stream (RFC 9114 section 7.2.8); true by default. */
        public var grease: Boolean = true

        /** Interim (1xx) responses a client accepts per request; one more fails it with H3_EXCESSIVE_LOAD; 5 by default. */
        public var maxInformationalResponses: Int = 5

        /** PRIORITY_UPDATE frames kept for streams not yet open (RFC 9218 section 7); extra ones are dropped; 32 by default. */
        public var maxEarlyPriorityUpdates: Int = 32

        /** Close with H3_EXCESSIVE_LOAD a connection whose peer floods useless frames (1000 tokens, 33/s); true by default. */
        public var glitchProtection: Boolean = true

        /** Server: early requests that are not replayable wait for the handshake; [Http3EarlyDataPolicy.WaitForHandshake] by default. */
        @ExperimentalKuicksilverApi
        public var earlyData: Http3EarlyDataPolicy = Http3EarlyDataPolicy.WaitForHandshake()

        /**
         * WebTransport over HTTP/3 (draft-ietf-webtrans-http3-16); false by default. A server advertises
         * `SETTINGS_WT_ENABLED`, `SETTINGS_WT_MAX_SESSIONS=1` (draft-14) and `SETTINGS_ENABLE_WEBTRANSPORT` (draft-02), so
         * browsers that still speak the older drafts find theirs; a client advertises the first and the last. [build]
         * refuses it without [enableConnectProtocol] and [h3Datagram]: sessions are Extended CONNECT requests and carry
         * HTTP datagrams.
         */
        @ExperimentalKuicksilverApi
        public var webTransport: Boolean = false

        /** Advertises a 4096-byte dynamic table and 16 blocked streams (the dynamic table is off by default). */
        public fun enableQpackDynamicTable() {
            qpackMaxTableCapacity = 4096
            qpackBlockedStreams = 16
        }

        /** The immutable settings; throws [IllegalArgumentException] when a value is outside the range given on its property. */
        public fun build(): Http3Settings {
            require(qpackMaxTableCapacity in 0..(1L shl 30)) { "qpackMaxTableCapacity must be 0..2^30" }
            require(qpackBlockedStreams in 0..65_535) { "qpackBlockedStreams must be 0..65535" }
            require(encoderMaxTableCapacity in 0..(1L shl 30)) { "encoderMaxTableCapacity must be 0..2^30" }
            require(maxFieldSectionSize in 1..(1L shl 30)) { "maxFieldSectionSize must be 1..2^30" }
            require(maxInformationalResponses >= 0) { "maxInformationalResponses must not be negative" }
            require(maxEarlyPriorityUpdates >= 0) { "maxEarlyPriorityUpdates must not be negative" }
            require(!webTransport || (enableConnectProtocol && h3Datagram)) {
                "webTransport needs enableConnectProtocol and h3Datagram"
            }
            return Http3Settings(
                qpackMaxTableCapacity,
                qpackBlockedStreams,
                encoderMaxTableCapacity,
                maxFieldSectionSize,
                enableConnectProtocol,
                h3Datagram,
                grease,
                maxInformationalResponses,
                maxEarlyPriorityUpdates,
                glitchProtection,
                earlyData,
                webTransport,
            )
        }
    }

    /** A builder pre-filled with these values. */
    public fun toBuilder(): Builder =
        Builder().also {
            it.qpackMaxTableCapacity = qpackMaxTableCapacity
            it.qpackBlockedStreams = qpackBlockedStreams
            it.encoderMaxTableCapacity =
                encoderMaxTableCapacity
            it.maxFieldSectionSize = maxFieldSectionSize
            it.enableConnectProtocol = enableConnectProtocol
            it.h3Datagram = h3Datagram
            it.grease =
                grease
            it.maxInformationalResponses = maxInformationalResponses
            it.maxEarlyPriorityUpdates = maxEarlyPriorityUpdates
            it.glitchProtection =
                glitchProtection
            it.earlyData = earlyData
            it.webTransport = webTransport
        }

    /**
     * The settings a 0-RTT client relies on (RFC 9114 section 7.2.4.2), bound into the server's tickets: a ticket issued
     * under other SETTINGS gets no early data. WebTransport is part of it (draft-ietf-webtrans-http3-16 section 3.2: its
     * settings must not be reduced for 0-RTT); the suffix is only added when it is on, so tickets of servers without it
     * stay valid across this release.
     */
    internal fun earlyDataContext(): ByteArray =
        (
            "h3|$qpackMaxTableCapacity|$qpackBlockedStreams|$maxFieldSectionSize|$enableConnectProtocol|$h3Datagram" +
                if (webTransport) "|wt" else ""
        ).encodeToByteArray()

    /** Holds [Default]. */
    public companion object { /** The defaults listed on [Builder]'s properties. */
        public val Default: Http3Settings = Builder().build()
    }
}

/** Builds [Http3Settings] from the defaults. */
public inline fun http3Settings(block: Http3Settings.Builder.() -> Unit): Http3Settings = Http3Settings.Builder().apply(block).build()

/** SETTINGS received from the peer; absent settings take their RFC defaults. */
public class Http3PeerSettings internal constructor(
    /** `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (0 when absent): the upper bound of our encoder's dynamic table toward this peer. */
    public val qpackMaxTableCapacity: Long,
    /** `SETTINGS_QPACK_BLOCKED_STREAMS` (0 when absent): how many of our streams may reference unacknowledged inserts. */
    public val qpackBlockedStreams: Long,
    /** null: the peer set no limit. */
    public val maxFieldSectionSize: Long?,
    /** `SETTINGS_ENABLE_CONNECT_PROTOCOL=1`: the peer accepts Extended CONNECT (RFC 9220 section 3), needed by `connect`. */
    public val enableConnectProtocol: Boolean,
    /** `SETTINGS_H3_DATAGRAM=1`: the peer accepts HTTP datagrams (RFC 9297 section 2.1.1). */
    public val h3Datagram: Boolean,
    /** Settings this library does not interpret (GREASE included); the WebTransport ones are interpreted, see [webTransport]. */
    public val unknown: Map<Long, Long>,
    /**
     * The peer speaks WebTransport over HTTP/3: it sent `SETTINGS_WT_ENABLED=1` (draft-15 and later), a non-zero
     * `SETTINGS_WT_MAX_SESSIONS` (draft-13, -14) or `SETTINGS_ENABLE_WEBTRANSPORT` (draft-02).
     */
    @property:ExperimentalKuicksilverApi
    public val webTransport: Boolean = false,
) {
    override fun toString(): String =
        "Http3PeerSettings(qpack=$qpackMaxTableCapacity/$qpackBlockedStreams, maxFieldSectionSize=$maxFieldSectionSize, connect=$enableConnectProtocol, datagram=$h3Datagram)"
}
