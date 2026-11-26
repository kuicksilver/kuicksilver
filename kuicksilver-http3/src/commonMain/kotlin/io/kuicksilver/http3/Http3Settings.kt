// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, InternalKuicksilverApi::class)

package io.kuicksilver.http3

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.annotations.KuicksilverDsl
import io.kuicksilver.annotations.SecuritySensitive
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** Local HTTP/3 settings: what we advertise in SETTINGS (RFC 9114 section 7.2.4) and our own resource limits; build with [http3Settings]. */
public class Http3Settings private constructor(
    /** `SETTINGS_QPACK_MAX_TABLE_CAPACITY` we advertise: how much of our decoder's table the peer may fill (0 by default; [Builder.Qpack.enableDynamicTable] raises it). */
    @property:InternalKuicksilverApi
    public val qpackMaxTableCapacity: Long,
    /** `SETTINGS_QPACK_BLOCKED_STREAMS` we advertise (0 by default). */
    @property:InternalKuicksilverApi
    public val qpackBlockedStreams: Long,
    /** Ceiling of our own encoder's dynamic table, whatever the peer allows; 4096 by default, 0..2^30. */
    @property:InternalKuicksilverApi
    public val encoderMaxTableCapacity: Long,
    /**
     * Largest decoded field section (headers or trailers) we accept, advertised as `SETTINGS_MAX_FIELD_SECTION_SIZE`;
     * 64 KiB by default, 1..2^30.
     */
    @property:InternalKuicksilverApi
    public val maxFieldSectionSize: Long,
    /** Advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 9220): servers that accept Extended CONNECT turn it on. */
    @property:InternalKuicksilverApi
    public val enableConnectProtocol: Boolean,
    /** `SETTINGS_H3_DATAGRAM` value; the setting is always sent (RFC 9297; threat-model 3.17: no fingerprint by omission). */
    @property:InternalKuicksilverApi
    public val h3Datagram: Boolean,
    /** Send a reserved setting, frame and unidirectional stream (RFC 9114 sections 6.2.3, 7.2.4.1, 7.2.8) to keep peers tolerant. */
    @property:InternalKuicksilverApi
    public val grease: Boolean,
    /** PRIORITY_UPDATE frames remembered for streams not yet open; 32 by default, at least 0. */
    @property:InternalKuicksilverApi
    public val maxEarlyPriorityUpdates: Int,
    /** Close a connection whose peer floods useless frames (glitch limiter: 1000 tokens, 33/s). */
    @property:InternalKuicksilverApi
    public val glitchProtection: Boolean,
    /**
     * How long one field section (a HEADERS frame) may take to arrive, as `Http2Settings.maxHeaderBlockTime`; a server
     * also counts a request's head from its stream's first byte. Positive; 10 s by default ([Builder.maxHeaderBlockTime]).
     */
    @property:InternalKuicksilverApi
    public val maxHeaderBlockTime: Duration,
    /** Server: what happens to requests received in 0-RTT before the handshake completed (only with `QuicServerConfig.acceptEarlyData`). */
    @property:InternalKuicksilverApi
    public val earlyData: Http3EarlyDataPolicy,
    /**
     * Speak WebTransport over HTTP/3 (draft-ietf-webtrans-http3-17, and the drafts browsers and other libraries still
     * speak: -16, -14, -02): advertise its SETTINGS and route WebTransport streams to
     * sessions. Needs [enableConnectProtocol][Http3Settings.enableConnectProtocol] and [h3Datagram][Http3Settings.h3Datagram].
     */
    @property:InternalKuicksilverApi
    public val webTransport: Boolean,
    /**
     * WebTransport sessions a server accepts at once on one connection when flow control is on (draft-ietf-webtrans-http3-17
     * section 5.2); one more is reset with H3_REQUEST_REJECTED before the application sees it. Without flow control a
     * connection carries one session whatever this says (section 5.1). Advertised to draft-14 clients as
     * `SETTINGS_WT_MAX_SESSIONS`. Ignored by a client, whose limit is the server's.
     */
    @property:InternalKuicksilverApi
    public val webTransportMaxSessions: Int,
    /**
     * `SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI` (section 5.5.2): the bidirectional streams the peer may open in each
     * WebTransport session before we raise the limit with WT_MAX_STREAMS as its streams end.
     */
    @property:InternalKuicksilverApi
    public val webTransportInitialMaxStreamsBidi: Long,
    /** `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI` (section 5.5.1): the same for unidirectional streams. */
    @property:InternalKuicksilverApi
    public val webTransportInitialMaxStreamsUni: Long,
    /**
     * `SETTINGS_WT_INITIAL_MAX_DATA` (section 5.5.3): the stream body bytes the peer may send in each WebTransport
     * session, raised with WT_MAX_DATA as they are consumed: taken by the application, all of a stream that ended cleanly
     * once it was handed to its input, a reset or stopped stream's by its final size. Our sender serves a
     * non-incremental session's streams in the order they were opened and shares an incremental session's credit
     * between them (RFC 9218); otherwise, or with a peer of another implementation, read the streams concurrently, or a
     * strictly sequential reader under a tight limit can stall the session ([Builder.WebTransport.initialMaxData]).
     */
    @property:InternalKuicksilverApi
    public val webTransportInitialMaxData: Long,
) {
    /**
     * Mutable form of [Http3Settings], used through [http3Settings] or [toBuilder]: the limits at the top, [qpack] for header
     * compression, [webTransport] and [expert] (both experimental) in blocks; ranges are checked by [build].
     */
    @KuicksilverDsl
    public class Builder {
        /** The options a layer above derives that were assigned explicitly (`enableConnectProtocol`, `webTransport`, ...). */
        internal val assigned: MutableSet<String> = mutableSetOf()

        /** Largest decoded field section in bytes we accept and advertise (RFC 9114 section 4.2.2), 1..2^30; 65536 by default. */
        @SecuritySensitive
        public var maxFieldSectionSize: Long = 65_536

        /**
         * How long one field section (a HEADERS frame: request or response head, interim response, trailers) may take to
         * arrive, from its frame header to its last byte; positive, 10 s by default (as `Http2Settings.maxHeaderBlockTime`).
         * A server also counts a request's head from the first byte of its stream (frames before the HEADERS and a stream
         * that sends nothing included) to its decoded HEADERS. A request head that misses it is rejected with
         * H3_REQUEST_REJECTED before the application sees it (RFC 9114 section 4.1.1), so the client may send it again;
         * other field sections cancel their request with H3_REQUEST_CANCELLED. The connection lives on either way.
         */
        @SecuritySensitive
        public var maxHeaderBlockTime: Duration = 10.seconds

        /**
         * Advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL=1` so peers may send Extended CONNECT (RFC 9220); false by default. For
         * applications of the raw HTTP/3 API: a Ktor server engine derives it from its WebSocket, WebTransport and
         * CONNECT-UDP options.
         */
        public var enableConnectProtocol: Boolean = false
            set(value) {
                field = value
                assigned += "enableConnectProtocol"
            }

        /**
         * Advertise `SETTINGS_H3_DATAGRAM=1` (RFC 9297); true by default; [Http3Endpoint] sends 0 when QUIC datagrams are off.
         * For applications of the raw HTTP/3 API: a Ktor engine derives it.
         */
        public var h3Datagram: Boolean = true
            set(value) {
                field = value
                assigned += "h3Datagram"
            }

        /**
         * Server: early requests that are not replayable wait for the handshake; [Http3EarlyDataPolicy.WaitForHandshake] by
         * default. A Ktor server sets it from `http3 { earlyData { policy } }`.
         */
        @ExperimentalKuicksilverApi
        @SecuritySensitive
        public var earlyData: Http3EarlyDataPolicy = Http3EarlyDataPolicy.WaitForHandshake()
            set(value) {
                field = value
                assigned += "earlyData"
            }

        /** QPACK header compression (RFC 9204): the dynamic tables, off by default. */
        public val qpack: Qpack = Qpack()

        /** Sets the [qpack] options. */
        public fun qpack(block: Qpack.() -> Unit) {
            qpack.block()
        }

        /** WebTransport over HTTP/3 (draft-ietf-webtrans-http3-17); experimental. */
        @ExperimentalKuicksilverApi
        public val webTransport: WebTransport = WebTransport(assigned)

        /** Sets the [webTransport] options. */
        @ExperimentalKuicksilverApi
        public fun webTransport(block: WebTransport.() -> Unit) {
            webTransport.block()
        }

        /** GREASE and the abuse limits few applications change; experimental. */
        @ExperimentalKuicksilverApi
        public val expert: Expert = Expert()

        /** Sets the [expert] options. */
        @ExperimentalKuicksilverApi
        public fun expert(block: Expert.() -> Unit) {
            expert.block()
        }

        /** The QPACK options of a [Builder] (RFC 9204). */
        @KuicksilverDsl
        public class Qpack internal constructor() {
            /** Dynamic table capacity in bytes the peer's encoder may use toward our decoder, 0..2^30; 0 (static table only) by default. */
            public var maxTableCapacity: Long = 0

            /** Streams that may wait for dynamic table inserts at once (RFC 9204 section 2.1.2), 0..65535; 0 by default. */
            public var blockedStreams: Long = 0

            /** Ceiling in bytes of our encoder's dynamic table, applied below the peer's capacity, 0..2^30; 4096 by default. */
            public var encoderMaxTableCapacity: Long = 4096

            /** Advertises a 4096-byte dynamic table and 16 blocked streams (the dynamic table is off by default). */
            public fun enableDynamicTable() {
                maxTableCapacity = 4096
                blockedStreams = 16
            }
        }

        /** The WebTransport options of a [Builder] (draft-ietf-webtrans-http3-17); experimental. */
        @ExperimentalKuicksilverApi
        @KuicksilverDsl
        public class WebTransport internal constructor(
            private val assigned: MutableSet<String>,
        ) {
            /**
             * WebTransport over HTTP/3; false by default. A server advertises `SETTINGS_WT_ENABLED` of draft-17 and of
             * draft-16, `SETTINGS_WT_MAX_SESSIONS` (draft-14: [maxSessions] with flow control, else 1) and
             * `SETTINGS_ENABLE_WEBTRANSPORT` (draft-02), so browsers and libraries that still speak the older drafts find
             * theirs; a client advertises all but draft-14's. The highest version both sides speak is used (draft-17 section
             * 7.1). Both add the non-zero `SETTINGS_WT_INITIAL_*` values that declare WebTransport flow control (section 5),
             * which lets several sessions share a connection. [build][Builder.build] refuses it without
             * [enableConnectProtocol][Builder.enableConnectProtocol] and [h3Datagram][Builder.h3Datagram]: sessions are
             * Extended CONNECT requests and carry HTTP datagrams. A Ktor engine derives this block from its own `webTransport { }`.
             */
            public var enabled: Boolean = false
                set(value) {
                    field = value
                    assigned += "webTransport"
                }

            /**
             * WebTransport sessions on one connection when flow control is on (both sides sent a non-zero
             * `SETTINGS_WT_INITIAL_*`, draft-ietf-webtrans-http3-17 section 5.1), 1..65535; 4 by default. A server resets a
             * CONNECT beyond it with H3_REQUEST_REJECTED (section 5.2), and a client opens another connection instead of
             * putting more on one. The per-session limits below, times this, must fit the QUIC connection's ([Http3Endpoint]
             * refuses a configuration where they do not, and the connection's receive window is kept at the open sessions'
             * sum): no session can then hold every stream slot or the whole connection window. `Http3Connection.client` and
             * `server` on a QUIC connection made by the caller cannot check this: its configuration must fit them the same way.
             */
            public var maxSessions: Int = 4
                set(value) {
                    field = value
                    assigned += "webTransport"
                }

            /**
             * Bidirectional streams the peer may open in each WebTransport session (section 5.5.2), 0..2^60; 24 by default, so
             * 4 sessions and their CONNECT streams fit the default 100 QUIC streams. The limit rises with WT_MAX_STREAMS as the
             * peer's streams end. When this, [initialMaxStreamsUni] and [initialMaxData] are all 0, we do not declare
             * WebTransport flow control (section 5.1) and a connection carries one session.
             */
            public var initialMaxStreamsBidi: Long = 24
                set(value) {
                    field = value
                    assigned += "webTransport.limits"
                }

            /**
             * Unidirectional streams the peer may open in each WebTransport session (section 5.5.1), 0..2^60; 24 by default
             * (4 sessions and the peer's 3 HTTP/3 streams fit the default 100 QUIC streams).
             */
            public var initialMaxStreamsUni: Long = 24
                set(value) {
                    field = value
                    assigned += "webTransport.limits"
                }

            /**
             * Stream body bytes the peer may send in each WebTransport session (section 5.5.3), 0..2^62-1; 3 932 160 by
             * default (4 sessions fill the default largest QUIC connection window, 15 MiB). The limit rises with WT_MAX_DATA
             * as the bytes are consumed: taken by the application, all of a stream that ended cleanly once it was handed to its
             * input, a reset or stopped stream's by its final size.
             *
             * How our sender shares a session's credit follows the session's RFC 9218 `incremental` parameter. Non-incremental
             * (`i=?0`, the default): in the order the streams were opened, a stream waiting for credit, or writing what it was
             * given, served before every stream opened after it; streams written one after another then reach a peer that
             * reads them one after another in that order, but a stream that keeps writing holds the later ones. Incremental
             * (`i`, signalled with `priority: i`): the grants led by the streams that ask in turn, none starved, no order. A
             * session without a signal is non-incremental (RFC 9218 section 4.2). Each side chooses for its own sending: the
             * client by its request's priority, the server by the client's signal unless its `acceptWebTransport` answer
             * carries a `priority` field. Section 5 sets no order, so a peer of another implementation may serve its streams in
             * any order: unless the order is ours, read the streams concurrently, or keep this above what the peer sends at
             * once, as a reader that takes them strictly one after another can wait on a stream with no credit while the credit
             * sits unread in later ones, and under a tight limit the session stalls.
             */
            public var initialMaxData: Long = 3_932_160
                set(value) {
                    field = value
                    assigned += "webTransport.limits"
                }
        }

        /** The expert options of a [Builder]; experimental. */
        @ExperimentalKuicksilverApi
        @KuicksilverDsl
        public class Expert internal constructor() {
            /** Send a reserved setting, frame and unidirectional stream (RFC 9114 section 7.2.8); true by default. */
            public var grease: Boolean = true

            /** PRIORITY_UPDATE frames kept for streams not yet open (RFC 9218 section 7); extra ones are dropped; 32 by default. */
            @SecuritySensitive
            public var maxEarlyPriorityUpdates: Int = 32

            /**
             * Close with H3_EXCESSIVE_LOAD a connection whose peer floods useless frames (1000 tokens, 33/s); true by default.
             * False only weakens the default.
             */
            @DelicateKuicksilverApi
            @SecuritySensitive
            public var glitchProtection: Boolean = true
        }

        /** The options of a layer above's derived set that were assigned explicitly here, such as `enableConnectProtocol`. */
        @InternalKuicksilverApi
        public fun assignedOptions(): Set<String> = assigned.toSet()

        /** The immutable settings; throws [IllegalArgumentException] when a value is outside the range given on its property. */
        @OptIn(DelicateKuicksilverApi::class)
        public fun build(): Http3Settings {
            require(qpack.maxTableCapacity in 0..(1L shl 30)) { "qpack { maxTableCapacity } must be 0..2^30" }
            require(qpack.blockedStreams in 0..65_535) { "qpack { blockedStreams } must be 0..65535" }
            require(qpack.encoderMaxTableCapacity in 0..(1L shl 30)) { "qpack { encoderMaxTableCapacity } must be 0..2^30" }
            require(maxFieldSectionSize in 1..(1L shl 30)) { "maxFieldSectionSize must be 1..2^30" }
            require(expert.maxEarlyPriorityUpdates >= 0) { "expert { maxEarlyPriorityUpdates } must not be negative" }
            require(maxHeaderBlockTime.isPositive()) { "maxHeaderBlockTime must be positive" }
            val wt = webTransport
            require(!wt.enabled || (enableConnectProtocol && h3Datagram)) {
                "webTransport { enabled } needs enableConnectProtocol and h3Datagram"
            }
            require(wt.maxSessions in 1..65_535) { "webTransport { maxSessions } must be 1..65535" }
            require(wt.initialMaxStreamsBidi in 0..(1L shl 60)) { "webTransport { initialMaxStreamsBidi } must be 0..2^60" }
            require(wt.initialMaxStreamsUni in 0..(1L shl 60)) { "webTransport { initialMaxStreamsUni } must be 0..2^60" }
            require(wt.initialMaxData in 0..((1L shl 62) - 1)) { "webTransport { initialMaxData } must be 0..2^62-1" }
            return Http3Settings(
                qpack.maxTableCapacity,
                qpack.blockedStreams,
                qpack.encoderMaxTableCapacity,
                maxFieldSectionSize,
                enableConnectProtocol,
                h3Datagram,
                expert.grease,
                expert.maxEarlyPriorityUpdates,
                expert.glitchProtection,
                maxHeaderBlockTime,
                earlyData,
                wt.enabled,
                wt.maxSessions,
                wt.initialMaxStreamsBidi,
                wt.initialMaxStreamsUni,
                wt.initialMaxData,
            )
        }
    }

    /** A builder pre-filled with these values, to change some of them; nothing counts as assigned explicitly in it. */
    @OptIn(DelicateKuicksilverApi::class)
    public fun toBuilder(): Builder =
        Builder().also {
            it.qpack.maxTableCapacity = qpackMaxTableCapacity
            it.qpack.blockedStreams = qpackBlockedStreams
            it.qpack.encoderMaxTableCapacity = encoderMaxTableCapacity
            it.maxFieldSectionSize = maxFieldSectionSize
            it.enableConnectProtocol = enableConnectProtocol
            it.h3Datagram = h3Datagram
            it.expert.grease = grease
            it.expert.maxEarlyPriorityUpdates = maxEarlyPriorityUpdates
            it.expert.glitchProtection = glitchProtection
            it.maxHeaderBlockTime = maxHeaderBlockTime
            it.earlyData = earlyData
            it.webTransport.enabled = webTransport
            it.webTransport.maxSessions = webTransportMaxSessions
            it.webTransport.initialMaxStreamsBidi = webTransportInitialMaxStreamsBidi
            it.webTransport.initialMaxStreamsUni = webTransportInitialMaxStreamsUni
            it.webTransport.initialMaxData = webTransportInitialMaxData
            it.assigned.clear()
        }

    /**
     * We declare WebTransport flow control (draft-ietf-webtrans-http3-17 section 5.1: a non-zero
     * `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI`, `_BIDI` or `SETTINGS_WT_INITIAL_MAX_DATA`).
     */
    internal val webTransportFlowControl: Boolean
        get() = webTransportInitialMaxStreamsBidi != 0L || webTransportInitialMaxStreamsUni != 0L || webTransportInitialMaxData != 0L

    /**
     * With WebTransport flow control, [webTransportMaxSessions] sessions at their initial limits must fit [quic]'s:
     * their bidirectional streams and CONNECT streams within `maxBidiStreams`, their unidirectional streams and the
     * peer's three HTTP/3 streams within `maxUniStreams`, their data within `maxConnectionWindow`. Otherwise one session,
     * or a few, could hold every stream slot (a new CONNECT among them) or the whole connection window, and starve the
     * others (draft-ietf-webtrans-http3-17 sections 5.1 and 8). IllegalArgumentException when they do not.
     */
    internal fun requireWebTransportFits(quic: io.kuicksilver.quic.QuicConfig) {
        if (!webTransport || !webTransportFlowControl) return
        val n = webTransportMaxSessions.toLong()
        require(webTransportInitialMaxStreamsBidi <= quic.maxBidiStreams / n - 1) {
            "webTransport { maxSessions ($n) } x (initialMaxStreamsBidi ($webTransportInitialMaxStreamsBidi) + its " +
                "CONNECT stream) exceeds the QuicConfig maxBidiStreams (${quic.maxBidiStreams})"
        }
        require(webTransportInitialMaxStreamsUni <= (quic.maxUniStreams - 3) / n) {
            "webTransport { maxSessions ($n) } x initialMaxStreamsUni ($webTransportInitialMaxStreamsUni) + 3 HTTP/3 " +
                "streams exceeds the QuicConfig expert { maxUniStreams } (${quic.maxUniStreams})"
        }
        require(webTransportInitialMaxData <= quic.maxConnectionWindow / n) {
            "webTransport { maxSessions ($n) } x initialMaxData ($webTransportInitialMaxData) exceeds " +
                "the QuicConfig flowControl { maxConnectionWindow } (${quic.maxConnectionWindow})"
        }
    }

    /**
     * The settings a 0-RTT client relies on (RFC 9114 section 7.2.4.2), bound into the server's tickets: a ticket issued
     * under other SETTINGS gets no early data. WebTransport is part of it (draft-ietf-webtrans-http3-16 and -14 section 3.2:
     * "If the server accepts 0-RTT, the server MUST NOT reduce these initial flow control values from those negotiated
     * during the previous session": its flow-control values and session limit are part of it, so a server that changed
     * them accepts no 0-RTT; draft-17 section 3.2 lets a server accept it "regardless of the values it previously sent",
     * but a draft-16 client resuming here would still hold it to them); the suffix is only added when it is on, so tickets
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
     * The peer speaks WebTransport over HTTP/3: it sent `SETTINGS_WT_ENABLED=1` (draft-17's 0x20b8933b or draft-15 and
     * -16's 0x2c7cf000), a non-zero
     * `SETTINGS_WT_MAX_SESSIONS` (draft-13, -14) or `SETTINGS_ENABLE_WEBTRANSPORT` (draft-02).
     */
    @property:ExperimentalKuicksilverApi
    public val webTransport: Boolean = false,
) {
    /** For logs: the settings this library interprets. */
    override fun toString(): String =
        "Http3PeerSettings(qpack=$qpackMaxTableCapacity/$qpackBlockedStreams, maxFieldSectionSize=$maxFieldSectionSize, connect=$enableConnectProtocol, datagram=$h3Datagram, webTransport=$webTransport)"
}
