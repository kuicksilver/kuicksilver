// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.config

import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/**
 * A token bucket: [perSecond] events sustained, [burst] at once. The HTTP/2 flood limits (RST_STREAM and glitches) and the
 * CONNECT-UDP packet limits are set with one; both values are at least 1.
 *
 * @property perSecond Tokens added per second: the rate the limit allows for good.
 * @property burst The bucket's size: events allowed at once before the rate applies.
 */
@ExperimentalKuicksilverApi
public class RateLimit(
    public val perSecond: Int,
    public val burst: Int,
) {
    init {
        require(perSecond >= 1) { "RateLimit perSecond must be at least 1, got $perSecond" }
        require(burst >= 1) { "RateLimit burst must be at least 1, got $burst" }
    }

    /** Equal to another [RateLimit] of the same [perSecond] and [burst]. */
    override fun equals(other: Any?): Boolean = other is RateLimit && other.perSecond == perSecond && other.burst == burst

    /** A hash of [perSecond] and [burst]. */
    override fun hashCode(): Int = 31 * perSecond + burst

    /** `RateLimit(perSecond=..., burst=...)`. */
    override fun toString(): String = "RateLimit(perSecond=$perSecond, burst=$burst)"
}
