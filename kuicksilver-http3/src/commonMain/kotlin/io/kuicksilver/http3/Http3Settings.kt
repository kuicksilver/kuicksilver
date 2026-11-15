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
    /**
     * No longer a limit: a client accepts any number of interim (1xx) responses (RFC 9110 section 15.2), bounded only by
     * [maxFieldSectionSize][Http3Settings.maxFieldSectionSize] over all of a request's interim field sections. Kept for compatibility; 5 by default, at least 0.
     */
    @Deprecated("Ignored: interim responses are bounded by maxFieldSectionSize over all of them (RFC 9110 section 15.2)")
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
     * sessions. Needs [enableConnectProtocol][Http3Settings.enableConnectProtocol] and [h3Datagram][Http3Settings.h3Datagram].
     */
    @property:ExperimentalKuicksilverApi
    public val webTransport: Boolean,
    /**
     * WebTransport sessions a server accepts at once on one connection when flow control is on (draft-ietf-webtrans-http3-16
     * section 5.2); one more is reset with H3_REQUEST_REJECTED before the application sees it. Without flow control a
     * connection carries one session whatever this says (section 5.1). Advertised to draft-14 clients as
     * `SETTINGS_WT_MAX_SESSIONS`. Ignored by a client, whose limit is the server's.
     */
    @property:ExperimentalKuicksilverApi
    public val webTransportMaxSessions: Int,
    /**
     * `SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI` (section 5.5.2): the bidirectional streams the peer may open in each
     * WebTransport session before we raise the limit with WT_MAX_STREAMS as its streams end.
     */
    @property:ExperimentalKuicksilverApi
    public val webTransportInitialMaxStreamsBidi: Long,
    /** `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI` (section 5.5.1): the same for unidirectional streams. */
    @property:ExperimentalKuicksilverApi
    public val webTransportInitialMaxStreamsUni: Long,
    /**
     * `SETTINGS_WT_INITIAL_MAX_DATA` (section 5.5.3): the stream body bytes the peer may send in each WebTransport
     * session, raised with WT_MAX_DATA as they are consumed: taken by the application, all of a stream that ended cleanly
     * once it was handed to its input, a reset or stopped stream's by its final size. Our sender serves a session's
     * streams in the order they were opened; a peer of another implementation may not: read its streams concurrently, or
     * a strictly sequential reader under a tight limit can stall the session ([Builder.webTransportInitialMaxData]).
     */
    @property:ExperimentalKuicksilverApi
    public val webTransportInitialMaxData: Long,
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

        /**
         * No longer a limit (see [Http3Settings.maxInformationalResponses]): a client accepts any number of interim responses up to
         * [maxFieldSectionSize] bytes of fields over all of them. Still validated (at least 0); 5 by default.
         */
        @Deprecated("Ignored: interim responses are bounded by maxFieldSectionSize over all of them (RFC 9110 section 15.2)")
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
         * `SETTINGS_WT_ENABLED`, `SETTINGS_WT_MAX_SESSIONS` (draft-14: [webTransportMaxSessions] with flow control, else 1)
         * and `SETTINGS_ENABLE_WEBTRANSPORT` (draft-02), so browsers that still speak the older drafts find theirs; a client
         * advertises the first and the last. Both add the non-zero `SETTINGS_WT_INITIAL_*` values that declare WebTransport
         * flow control (section 5), which lets several sessions share a connection. [build]
         * refuses it without [enableConnectProtocol] and [h3Datagram]: sessions are Extended CONNECT requests and carry
         * HTTP datagrams.
         */
        @ExperimentalKuicksilverApi
        public var webTransport: Boolean = false

        /**
         * WebTransport sessions on one connection when flow control is on (both sides sent a non-zero
         * `SETTINGS_WT_INITIAL_*`, draft-ietf-webtrans-http3-16 section 5.1), 1..65535; 4 by default. A server resets a
         * CONNECT beyond it with H3_REQUEST_REJECTED (section 5.2), and a client opens another connection instead of
         * putting more on one. The per-session limits below, times this, must fit the QUIC connection's
         * ([Http3Endpoint] refuses a configuration where they do not, and the connection's receive window is kept at the
         * open sessions' sum): no
         * session can then hold every stream slot or the whole connection window. `Http3Connection.client` and `server`
         * on a QUIC connection made by the caller cannot check this: its configuration must fit them the same way.
         */
        @ExperimentalKuicksilverApi
        public var webTransportMaxSessions: Int = 4

        /**
         * Bidirectional streams the peer may open in each WebTransport session (section 5.5.2), 0..2^60; 24 by default, so
         * 4 sessions and their CONNECT streams fit the default 100 QUIC streams. The limit rises with WT_MAX_STREAMS as the
         * peer's streams end. When this, [webTransportInitialMaxStreamsUni] and [webTransportInitialMaxData] are all 0, we
         * do not declare WebTransport flow control (section 5.1) and a connection carries one session.
         */
        @ExperimentalKuicksilverApi
        public var webTransportInitialMaxStreamsBidi: Long = 24

        /**
         * Unidirectional streams the peer may open in each WebTransport session (section 5.5.1), 0..2^60; 24 by default
         * (4 sessions and the peer's 3 HTTP/3 streams fit the default 100 QUIC streams).
         */
        @ExperimentalKuicksilverApi
        public var webTransportInitialMaxStreamsUni: Long = 24

        /**
         * Stream body bytes the peer may send in each WebTransport session (section 5.5.3), 0..2^62-1; 3 932 160 by
         * default (4 sessions fill the default largest QUIC connection window, 15 MiB). The limit rises with WT_MAX_DATA
         * as the bytes are consumed: taken by the application, all of a stream that ended cleanly once it was handed to its
         * input, a reset or stopped stream's by its final size.
         *
         * Our sender hands a session's credit to its streams in the order they were opened (a stream waiting for credit,
         * or writing what it was given, is served before every stream opened after it), so a reader that takes this
         * library's streams one after another in that order never stalls. Section 5 sets no order, so a peer of another
         * implementation may serve its streams in any order: read its streams concurrently, or keep this above what the
         * peer sends at once, as a reader that takes them strictly one after another can wait on a stream with no credit
         * while the credit sits unread in later ones, and under a tight limit the session stalls.
         */
        @ExperimentalKuicksilverApi
        public var webTransportInitialMaxData: Long = 3_932_160

        /** Advertises a 4096-byte dynamic table and 16 blocked streams (the dynamic table is off by default). */
        public fun enableQpackDynamicTable() {
            qpackMaxTableCapacity = 4096
            qpackBlockedStreams = 16
        }

        /** The immutable settings; throws [IllegalArgumentException] when a value is outside the range given on its property. */
        @Suppress("DEPRECATION") // maxInformationalResponses is still validated and carried
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
            require(webTransportMaxSessions in 1..65_535) { "webTransportMaxSessions must be 1..65535" }
            require(webTransportInitialMaxStreamsBidi in 0..(1L shl 60)) { "webTransportInitialMaxStreamsBidi must be 0..2^60" }
            require(webTransportInitialMaxStreamsUni in 0..(1L shl 60)) { "webTransportInitialMaxStreamsUni must be 0..2^60" }
            require(webTransportInitialMaxData in 0..((1L shl 62) - 1)) { "webTransportInitialMaxData must be 0..2^62-1" }
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
                webTransportMaxSessions,
                webTransportInitialMaxStreamsBidi,
                webTransportInitialMaxStreamsUni,
                webTransportInitialMaxData,
            )
        }
    }

    /** A builder pre-filled with these values. */
    @Suppress("DEPRECATION") // maxInformationalResponses is still carried
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
            it.webTransportMaxSessions = webTransportMaxSessions
            it.webTransportInitialMaxStreamsBidi = webTransportInitialMaxStreamsBidi
            it.webTransportInitialMaxStreamsUni = webTransportInitialMaxStreamsUni
            it.webTransportInitialMaxData = webTransportInitialMaxData
        }

    /**
     * We declare WebTransport flow control (draft-ietf-webtrans-http3-16 section 5.1: a non-zero
     * `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI`, `_BIDI` or `SETTINGS_WT_INITIAL_MAX_DATA`).
     */
    internal val webTransportFlowControl: Boolean
        get() = webTransportInitialMaxStreamsBidi != 0L || webTransportInitialMaxStreamsUni != 0L || webTransportInitialMaxData != 0L

    /**
     * With WebTransport flow control, [webTransportMaxSessions] sessions at their initial limits must fit [quic]'s:
     * their bidirectional streams and CONNECT streams within `maxBidiStreams`, their unidirectional streams and the
     * peer's three HTTP/3 streams within `maxUniStreams`, their data within `maxConnectionWindow`. Otherwise one session,
     * or a few, could hold every stream slot (a new CONNECT among them) or the whole connection window, and starve the
     * others (draft-ietf-webtrans-http3-16 sections 5.1 and 8). IllegalArgumentException when they do not.
     */
    internal fun requireWebTransportFits(quic: io.kuicksilver.quic.QuicConfig) {
        if (!webTransport || !webTransportFlowControl) return
        val n = webTransportMaxSessions.toLong()
        require(webTransportInitialMaxStreamsBidi <= quic.maxBidiStreams / n - 1) {
            "webTransportMaxSessions ($n) x (webTransportInitialMaxStreamsBidi ($webTransportInitialMaxStreamsBidi) + its " +
                "CONNECT stream) exceeds QuicConfig.maxBidiStreams (${quic.maxBidiStreams})"
        }
        require(webTransportInitialMaxStreamsUni <= (quic.maxUniStreams - 3) / n) {
            "webTransportMaxSessions ($n) x webTransportInitialMaxStreamsUni ($webTransportInitialMaxStreamsUni) + 3 HTTP/3 " +
                "streams exceeds QuicConfig.maxUniStreams (${quic.maxUniStreams})"
        }
        require(webTransportInitialMaxData <= quic.maxConnectionWindow / n) {
            "webTransportMaxSessions ($n) x webTransportInitialMaxData ($webTransportInitialMaxData) exceeds " +
                "QuicConfig.maxConnectionWindow (${quic.maxConnectionWindow})"
        }
    }

    /**
     * The settings a 0-RTT client relies on (RFC 9114 section 7.2.4.2), bound into the server's tickets: a ticket issued
     * under other SETTINGS gets no early data. WebTransport is part of it (draft-ietf-webtrans-http3-16 section 3.2: its
     * settings must not be reduced for 0-RTT, and "If the server accepts 0-RTT, the server MUST NOT reduce these initial
     * flow control values from those negotiated during the previous session": its flow-control values and session limit
     * are part of it, so a server that changed them accepts no 0-RTT); the suffix is only added when it is on, so tickets
     * of servers without it stay valid across this release.
     */
    internal fun earlyDataContext(): ByteArray =
        (
            "h3|$qpackMaxTableCapacity|$qpackBlockedStreams|$maxFieldSectionSize|$enableConnectProtocol|$h3Datagram" +
                if (webTransport) {
                    "|wt|$webTransportMaxSessions|$webTransportInitialMaxStreamsBidi|$webTransportInitialMaxStreamsUni|" +
                        "$webTransportInitialMaxData"
                } else {
                    ""
                }
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
    /** Settings this library does not interpret (GREASE included); the WebTransport ones are interpreted, see [webTransport][Http3PeerSettings.webTransport]. */
    public val unknown: Map<Long, Long>,
    /**
     * The peer speaks WebTransport over HTTP/3: it sent `SETTINGS_WT_ENABLED=1` (draft-15 and later), a non-zero
     * `SETTINGS_WT_MAX_SESSIONS` (draft-13, -14) or `SETTINGS_ENABLE_WEBTRANSPORT` (draft-02).
     */
    @property:ExperimentalKuicksilverApi
    public val webTransport: Boolean = false,
) {
    /** For logs: the settings this library interprets. */
    override fun toString(): String =
        "Http3PeerSettings(qpack=$qpackMaxTableCapacity/$qpackBlockedStreams, maxFieldSectionSize=$maxFieldSectionSize, connect=$enableConnectProtocol, datagram=$h3Datagram, webTransport=$webTransport)"
}
