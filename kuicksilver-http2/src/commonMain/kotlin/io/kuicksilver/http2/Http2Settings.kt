// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.http2

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.annotations.KuicksilverDsl
import io.kuicksilver.annotations.SecuritySensitive
import io.kuicksilver.config.RateLimit
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * The local side of an HTTP/2 connection: the SETTINGS we send (RFC 9113 section 6.5.2), our flow-control windows and
 * the limits we hold the peer to (threat model 3.23). Every limit is per connection; the defaults follow the QUIC
 * defaults of this project for the windows and the published fixes of other HTTP/2 stacks for the flood limits.
 * Build one with [http2Settings] (in the Ktor engines: `http2 { settings { } }`), change one with [toBuilder].
 */
@ExperimentalKuicksilverApi
public class Http2Settings private constructor(
    @property:InternalKuicksilverApi public val headerTableSize: Int,
    @property:InternalKuicksilverApi public val maxConcurrentStreams: Int,
    @property:InternalKuicksilverApi public val initialStreamWindow: Int,
    @property:InternalKuicksilverApi public val maxStreamWindow: Int,
    @property:InternalKuicksilverApi public val initialConnectionWindow: Int,
    @property:InternalKuicksilverApi public val maxConnectionWindow: Int,
    @property:InternalKuicksilverApi public val maxFrameSize: Int,
    /** SETTINGS_MAX_HEADER_LIST_SIZE: the builder's [Builder.maxFieldSectionSize]. */
    @property:InternalKuicksilverApi public val maxHeaderListSize: Int,
    @property:InternalKuicksilverApi public val settingsAckTimeout: Duration,
    @property:InternalKuicksilverApi public val maxContinuationFrames: Int,
    @property:InternalKuicksilverApi public val maxControlFramesQueued: Int,
    @property:InternalKuicksilverApi public val maxEmptyFrames: Int,
    @property:InternalKuicksilverApi public val resetBurst: Int,
    @property:InternalKuicksilverApi public val resetsPerSecond: Int,
    @property:InternalKuicksilverApi public val maxHeaderBlockTime: Duration,
    @property:InternalKuicksilverApi public val glitchBurst: Int,
    @property:InternalKuicksilverApi public val glitchesPerSecond: Int,
) {
    /** For logs: every setting. */
    override fun toString(): String =
        "Http2Settings(headerTableSize=$headerTableSize, maxConcurrentStreams=$maxConcurrentStreams, " +
            "initialStreamWindow=$initialStreamWindow, maxStreamWindow=$maxStreamWindow, " +
            "initialConnectionWindow=$initialConnectionWindow, " +
            "maxConnectionWindow=$maxConnectionWindow, maxFrameSize=$maxFrameSize, maxFieldSectionSize=$maxHeaderListSize, " +
            "settingsAckTimeout=$settingsAckTimeout, maxContinuationFrames=$maxContinuationFrames, " +
            "maxControlFramesQueued=$maxControlFramesQueued, maxEmptyFrames=$maxEmptyFrames, " +
            "resets=$resetsPerSecond/s burst $resetBurst, maxHeaderBlockTime=$maxHeaderBlockTime, " +
            "glitches=$glitchesPerSecond/s burst $glitchBurst)"

    /** A builder pre-filled with these values, to change some of them. */
    public fun toBuilder(): Builder =
        Builder().also {
            it.headerTableSize = headerTableSize.toLong()
            it.maxConcurrentStreams = maxConcurrentStreams.toLong()
            it.initialStreamWindow = initialStreamWindow.toLong()
            it.maxStreamWindow = maxStreamWindow.toLong()
            it.initialConnectionWindow = initialConnectionWindow.toLong()
            it.maxConnectionWindow = maxConnectionWindow.toLong()
            it.maxFrameSize = maxFrameSize.toLong()
            it.maxFieldSectionSize = maxHeaderListSize.toLong()
            it.settingsAckTimeout = settingsAckTimeout
            it.maxHeaderBlockTime = maxHeaderBlockTime
            it.floodLimits.maxContinuationFrames = maxContinuationFrames
            it.floodLimits.maxControlFramesQueued = maxControlFramesQueued
            it.floodLimits.maxEmptyFrames = maxEmptyFrames
            it.floodLimits.resets = RateLimit(resetsPerSecond, resetBurst)
            it.floodLimits.glitches = RateLimit(glitchesPerSecond, glitchBurst)
        }

    /**
     * The mutable side of [Http2Settings]: SETTINGS, windows and deadlines at the top, the limits against floods in
     * [floodLimits]. Byte and stream counts are `Long`, as everywhere in the configuration; [build] checks every range and
     * throws IllegalArgumentException naming the option out of range.
     */
    @KuicksilverDsl
    public class Builder {
        /** SETTINGS_HEADER_TABLE_SIZE: the HPACK dynamic table the peer may use towards us, 0..65 536 bytes; default 4096. */
        public var headerTableSize: Long = 4_096

        /**
         * SETTINGS_MAX_CONCURRENT_STREAMS: streams the peer may have open towards us, 0..2^31 - 1; default 100. A stream the
         * peer reset still counts until its handler has finished.
         */
        @SecuritySensitive
        public var maxConcurrentStreams: Long = 100

        /** SETTINGS_INITIAL_WINDOW_SIZE: the receive window each stream starts with, 0..2^31 - 1; default 512 KiB. */
        public var initialStreamWindow: Long = 524_288

        /** The largest a stream's receive window grows to while the application reads faster than the window; default 6 MiB. */
        public var maxStreamWindow: Long = 6_291_456

        /** The connection's receive window, at least the protocol's 65 535; default 768 KiB. */
        public var initialConnectionWindow: Long = 786_432

        /** The largest the connection's receive window grows to, at most 2^31 - 1; default 15 MiB. */
        public var maxConnectionWindow: Long = 15_728_640

        /** SETTINGS_MAX_FRAME_SIZE: the largest frame payload we accept, 16 384..16 777 215; default 16 384. */
        public var maxFrameSize: Long = 16_384

        /**
         * SETTINGS_MAX_HEADER_LIST_SIZE: the largest field section we decode (name + value + 32 per field, as HTTP/3 counts
         * its `maxFieldSectionSize`), 1..2^30 - 1; default 64 KiB. A field block above it fails only its stream; its compressed
         * form (HEADERS plus CONTINUATION) is buffered up to twice this before decoding, and beyond that the connection ends.
         */
        @SecuritySensitive
        public var maxFieldSectionSize: Long = 65_536

        /** How long our SETTINGS may go unacknowledged before the connection ends with SETTINGS_TIMEOUT; default 10 s. */
        public var settingsAckTimeout: Duration = 10.seconds

        /**
         * How long one field block (HEADERS and its CONTINUATION frames) may take to arrive; default 10 s. A Ktor server bounds
         * it by its `requestHeaderTimeout`.
         */
        @SecuritySensitive
        public var maxHeaderBlockTime: Duration = 10.seconds

        /** The limits against floods of frames that cost the receiver more than the sender (threat model 3.23). */
        public val floodLimits: FloodLimits = FloodLimits()

        /** Sets the [floodLimits]. */
        public fun floodLimits(block: FloodLimits.() -> Unit) {
            floodLimits.block()
        }

        /** The flood limits of a [Builder]; every one ends the connection with ENHANCE_YOUR_CALM when the peer passes it. */
        @KuicksilverDsl
        public class FloodLimits internal constructor() {
            /** CONTINUATION frames allowed in one field block; default 8 (nghttp2's), at most [MAX_CONTINUATION_FRAMES]. */
            @SecuritySensitive
            public var maxContinuationFrames: Int = 8

            /**
             * Control frames (SETTINGS and PING acknowledgements, RST_STREAM, WINDOW_UPDATE) queued for the peer; default 10 000
             * (Go's), at most [MAX_CONTROL_FRAMES_QUEUED].
             */
            @SecuritySensitive
            public var maxControlFramesQueued: Int = 10_000

            /** DATA frames in a row with no content and no END_STREAM; default 100, at most [MAX_EMPTY_FRAMES]. */
            @SecuritySensitive
            public var maxEmptyFrames: Int = 100

            /**
             * A server's budget for the client's RST_STREAM frames (Rapid Reset, CVE-2023-44487): 33 a second, 1000 at once, as
             * nghttp2. At most [MAX_RESETS] (100 times that): a larger budget no longer bounds a connection's stream churn.
             */
            @SecuritySensitive
            public var resets: RateLimit = RateLimit(33, 1_000)

            /**
             * The glitch budget: 330 a second, 10 000 at once (nghttp2's numbers). Counted events: PRIORITY, unknown frame
             * types, SETTINGS, empty DATA without END_STREAM, a PING with no DATA or HEADERS of ours since the previous PING (a
             * bandwidth probe that follows our data is free, as grpc-go's ping strikes), and every stream error the peer causes.
             * At most [MAX_GLITCHES] (100 times the default), for the same reason as [resets].
             */
            @SecuritySensitive
            public var glitches: RateLimit = RateLimit(330, 10_000)

            /** Holds the ceilings of the budgets. */
            public companion object {
                /**
                 * The largest [resets] budget: 3300 a second, 100 000 at once, 100 times nghttp2's. Rapid Reset floods run at
                 * hundreds of thousands of resets a second on one connection; a budget near that would let them through.
                 */
                public val MAX_RESETS: RateLimit = RateLimit(3_300, 100_000)

                /** The largest [glitches] budget: 33 000 a second, 1 000 000 at once, 100 times the default. */
                public val MAX_GLITCHES: RateLimit = RateLimit(33_000, 1_000_000)

                /**
                 * The largest [maxContinuationFrames]: 800, 100 times the default. At the smallest frame size (16 KiB) that is
                 * 12.5 MiB of field block, beyond any header list a peer sends; a CONTINUATION flood (CVE-2024-27316) spends
                 * its CPU on the frame count, empty frames included, so the count must stay bounded.
                 */
                public const val MAX_CONTINUATION_FRAMES: Int = 800

                /**
                 * The largest [maxControlFramesQueued]: 100 000, 10 times the default. A peer that never reads (PING and
                 * SETTINGS floods, CVE-2019-9512 and CVE-2019-9515) holds that many frames of tens of bytes each, a few MiB
                 * per connection; 100 times the default would be tens of MiB per connection.
                 */
                public const val MAX_CONTROL_FRAMES_QUEUED: Int = 100_000

                /**
                 * The largest [maxEmptyFrames]: 10 000, 100 times the default. An empty-frame flood (CVE-2019-9518) costs
                 * the peer 9 bytes a frame and us a frame's processing each; no sender has a reason to send more than a few
                 * empty DATA frames in a row, and a run this long is a flood whatever its rate.
                 */
                public const val MAX_EMPTY_FRAMES: Int = 10_000
            }
        }

        private fun int(
            name: String,
            v: Long,
            range: LongRange,
        ): Int {
            require(v in range) { "$name must be ${range.first}..${range.last}, got $v" }
            return v.toInt()
        }

        /** An immutable [Http2Settings]; IllegalArgumentException names the first option out of range. */
        public fun build(): Http2Settings {
            val initialStream = int("initialStreamWindow", initialStreamWindow, 0..Int.MAX_VALUE.toLong())
            val initialConnection = int("initialConnectionWindow", initialConnectionWindow, 65_535..Int.MAX_VALUE.toLong())
            require(maxStreamWindow >= initialStreamWindow) { "maxStreamWindow must be at least initialStreamWindow" }
            require(maxConnectionWindow >= initialConnectionWindow) { "maxConnectionWindow must be at least initialConnectionWindow" }
            require(settingsAckTimeout.isPositive()) { "settingsAckTimeout must be positive" }
            require(maxHeaderBlockTime.isPositive()) { "maxHeaderBlockTime must be positive" }
            val f = floodLimits
            require(f.maxContinuationFrames in 0..FloodLimits.MAX_CONTINUATION_FRAMES) {
                "floodLimits { maxContinuationFrames } must be 0..${FloodLimits.MAX_CONTINUATION_FRAMES}: more no longer bounds a " +
                    "CONTINUATION flood (CVE-2024-27316), got ${f.maxContinuationFrames}"
            }
            require(f.maxControlFramesQueued in 1..FloodLimits.MAX_CONTROL_FRAMES_QUEUED) {
                "floodLimits { maxControlFramesQueued } must be 1..${FloodLimits.MAX_CONTROL_FRAMES_QUEUED}: more lets a peer " +
                    "that never reads hold that much memory, got ${f.maxControlFramesQueued}"
            }
            require(f.maxEmptyFrames in 0..FloodLimits.MAX_EMPTY_FRAMES) {
                "floodLimits { maxEmptyFrames } must be 0..${FloodLimits.MAX_EMPTY_FRAMES}: more no longer bounds an empty-frame " +
                    "flood (CVE-2019-9518), got ${f.maxEmptyFrames}"
            }
            require(f.resets.perSecond <= FloodLimits.MAX_RESETS.perSecond && f.resets.burst <= FloodLimits.MAX_RESETS.burst) {
                "floodLimits { resets } must be at most ${FloodLimits.MAX_RESETS}: a larger budget no longer bounds Rapid Reset " +
                    "(CVE-2023-44487), got ${f.resets}"
            }
            require(f.glitches.perSecond <= FloodLimits.MAX_GLITCHES.perSecond && f.glitches.burst <= FloodLimits.MAX_GLITCHES.burst) {
                "floodLimits { glitches } must be at most ${FloodLimits.MAX_GLITCHES}, got ${f.glitches}"
            }
            return Http2Settings(
                int("headerTableSize", headerTableSize, 0..65_536L),
                int("maxConcurrentStreams", maxConcurrentStreams, 0..Int.MAX_VALUE.toLong()),
                initialStream,
                int("maxStreamWindow", maxStreamWindow, 0..Int.MAX_VALUE.toLong()),
                initialConnection,
                int("maxConnectionWindow", maxConnectionWindow, 0..Int.MAX_VALUE.toLong()),
                int("maxFrameSize", maxFrameSize, 16_384..16_777_215L),
                // twice this is buffered for one field block: it must fit an Int
                int("maxFieldSectionSize", maxFieldSectionSize, 1..(Int.MAX_VALUE / 2).toLong()),
                settingsAckTimeout,
                f.maxContinuationFrames,
                f.maxControlFramesQueued,
                f.maxEmptyFrames,
                f.resets.burst,
                f.resets.perSecond,
                maxHeaderBlockTime,
                f.glitches.burst,
                f.glitches.perSecond,
            )
        }
    }

    /** Holds [Default]. */
    public companion object {
        /** Every default of [Builder]. */
        public val Default: Http2Settings = Builder().build()
    }
}

/** Builds [Http2Settings] from the defaults. */
@ExperimentalKuicksilverApi
public inline fun http2Settings(block: Http2Settings.Builder.() -> Unit): Http2Settings = Http2Settings.Builder().apply(block).build()
