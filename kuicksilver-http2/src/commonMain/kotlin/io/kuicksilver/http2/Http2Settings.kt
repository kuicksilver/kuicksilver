// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * The local side of an HTTP/2 connection: the SETTINGS we send (RFC 9113 section 6.5.2), our flow-control windows and
 * the limits we hold the peer to (threat model 3.23). Every limit is per connection; the defaults follow the QUIC
 * defaults of this project for the windows and the published fixes of other HTTP/2 stacks for the flood limits.
 * The constructor throws IllegalArgumentException for a value out of range.
 */
@ExperimentalKuicksilverApi
public class Http2Settings(
    /** SETTINGS_HEADER_TABLE_SIZE: the HPACK dynamic table the peer may use towards us, 0..65 536 bytes; default 4096. */
    public val headerTableSize: Int = 4_096,
    /**
     * SETTINGS_MAX_CONCURRENT_STREAMS: streams the peer may have open towards us, 0..2^31 - 1; default 100. A stream the
     * peer reset still counts until its handler has finished.
     */
    public val maxConcurrentStreams: Int = 100,
    /** SETTINGS_INITIAL_WINDOW_SIZE: the receive window each stream starts with; default 512 KiB. */
    public val initialStreamWindow: Int = 524_288,
    /** The largest a stream's receive window grows to while the application reads faster than the window; default 6 MiB. */
    public val maxStreamWindow: Int = 6_291_456,
    /** The connection's receive window, at least the protocol's 65 535; default 768 KiB. */
    public val initialConnectionWindow: Int = 786_432,
    /** The largest the connection's receive window grows to; default 15 MiB. */
    public val maxConnectionWindow: Int = 15_728_640,
    /** SETTINGS_MAX_FRAME_SIZE: the largest frame payload we accept, 16 384..16 777 215; default 16 384. */
    public val maxFrameSize: Int = 16_384,
    /**
     * SETTINGS_MAX_HEADER_LIST_SIZE: the largest field section we decode (name + value + 32 per field), 1..2^30 - 1;
     * default 64 KiB. A
     * field block above it fails only its stream; its compressed form (HEADERS plus CONTINUATION) is buffered up to twice
     * this before decoding, and beyond that the connection ends.
     */
    public val maxHeaderListSize: Int = 65_536,
    /** How long our SETTINGS may go unacknowledged before the connection ends with SETTINGS_TIMEOUT; default 10 s. */
    public val settingsAckTimeout: Duration = 10.seconds,
    /** CONTINUATION frames allowed in one field block; more ends the connection (ENHANCE_YOUR_CALM); default 8. */
    public val maxContinuationFrames: Int = 8,
    /** Control frames (SETTINGS and PING acknowledgements, RST_STREAM, WINDOW_UPDATE) queued for the peer; default 10 000. */
    public val maxControlFramesQueued: Int = 10_000,
    /** DATA frames in a row with no content and no END_STREAM; more ends the connection; default 100. */
    public val maxEmptyFrames: Int = 100,
    /** A server's budget for the client's RST_STREAM frames (Rapid Reset), burst; default 1000, as nghttp2. */
    public val resetBurst: Int = 1_000,
    /** The refill rate of that budget per second; default 33, as nghttp2. */
    public val resetsPerSecond: Int = 33,
    /** How long one field block (HEADERS and its CONTINUATION frames) may take to arrive; default 10 s. */
    public val maxHeaderBlockTime: Duration = 10.seconds,
    /**
     * The burst of the glitch budget; default 10 000 (the numbers are nghttp2's). Counted events: PRIORITY, unknown frame
     * types, SETTINGS, empty DATA without END_STREAM, a PING with no DATA or HEADERS of ours since the previous PING (a
     * bandwidth probe that follows our data is free, as grpc-go's ping strikes), and every stream error the peer causes.
     */
    public val glitchBurst: Int = 10_000,
    /** The refill rate of the glitch budget per second; default 330, as nghttp2. */
    public val glitchesPerSecond: Int = 330,
) {
    init {
        require(headerTableSize in 0..65_536) { "headerTableSize must be 0..65536, got $headerTableSize" }
        require(maxConcurrentStreams >= 0) { "maxConcurrentStreams must not be negative" }
        require(initialStreamWindow >= 0) { "initialStreamWindow must not be negative" }
        require(maxStreamWindow >= initialStreamWindow) { "maxStreamWindow must be at least initialStreamWindow" }
        require(initialConnectionWindow >= 65_535) { "initialConnectionWindow must be at least 65535" }
        require(maxConnectionWindow >= initialConnectionWindow) { "maxConnectionWindow must be at least initialConnectionWindow" }
        require(maxFrameSize in 16_384..16_777_215) { "maxFrameSize must be 16384..16777215, got $maxFrameSize" }
        // twice this is buffered for one field block: it must fit an Int
        require(maxHeaderListSize in 1..Int.MAX_VALUE / 2) { "maxHeaderListSize must be 1..${Int.MAX_VALUE / 2}, got $maxHeaderListSize" }
        require(settingsAckTimeout.isPositive()) { "settingsAckTimeout must be positive" }
        require(maxContinuationFrames >= 0) { "maxContinuationFrames must not be negative" }
        require(maxControlFramesQueued >= 1) { "maxControlFramesQueued must be positive" }
        require(maxEmptyFrames >= 0) { "maxEmptyFrames must not be negative" }
        require(resetBurst >= 1 && resetsPerSecond >= 0) { "resetBurst must be positive and resetsPerSecond not negative" }
        require(maxHeaderBlockTime.isPositive()) { "maxHeaderBlockTime must be positive" }
        require(glitchBurst >= 1 && glitchesPerSecond >= 0) { "glitchBurst must be positive and glitchesPerSecond not negative" }
    }

    override fun toString(): String =
        "Http2Settings(headerTableSize=$headerTableSize, maxConcurrentStreams=$maxConcurrentStreams, " +
            "initialStreamWindow=$initialStreamWindow, maxStreamWindow=$maxStreamWindow, " +
            "initialConnectionWindow=$initialConnectionWindow, " +
            "maxConnectionWindow=$maxConnectionWindow, maxFrameSize=$maxFrameSize, maxHeaderListSize=$maxHeaderListSize, " +
            "settingsAckTimeout=$settingsAckTimeout, maxContinuationFrames=$maxContinuationFrames, " +
            "maxControlFramesQueued=$maxControlFramesQueued, maxEmptyFrames=$maxEmptyFrames, resetBurst=$resetBurst, " +
            "resetsPerSecond=$resetsPerSecond, maxHeaderBlockTime=$maxHeaderBlockTime, glitchBurst=$glitchBurst, " +
            "glitchesPerSecond=$glitchesPerSecond)"
}
