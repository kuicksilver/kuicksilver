// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.TimeMark
import kotlin.random.Random
import kotlin.time.Duration.Companion.seconds

/** Comparisons whose running time does not depend on where the bytes differ (reset tokens are secrets). */
internal object ConstantTime {
    fun equals(
        a: PacketBuffer,
        aOff: Int,
        b: ByteArray,
        bOff: Int,
        len: Int,
    ): Boolean {
        var diff = 0
        for (i in 0 until len) diff = diff or ((a[aOff + i].toInt() xor b[bOff + i].toInt()) and 0xff)
        return diff == 0
    }
}

/** Stateless Reset packets (RFC 9000 section 10.3): random bytes that look like a short header, the 16-byte token last. */
internal object StatelessReset {
    /** 1 header byte + 4 random bytes + 16-byte token: the smallest reset that cannot be mistaken for anything else (section 10.3). */
    const val MIN_SIZE: Int = 21

    /**
     * Writes a reset for [token] into [out]: strictly shorter than the [incomingLength] that triggered it (so two endpoints
     * cannot reset each other forever, section 10.3.3), at least [MIN_SIZE], and no longer than [out] holds (a trigger can be
     * a jumbo datagram). Returns 0 when the trigger is too small.
     */
    fun write(
        out: PacketBuffer,
        token: ByteArray,
        incomingLength: Int,
        random: Random,
    ): Int {
        if (incomingLength <= MIN_SIZE) return 0
        val limit = minOf(incomingLength, out.capacity + 1)
        if (limit <= MIN_SIZE) return 0
        val length = MIN_SIZE + random.nextInt(limit - MIN_SIZE) // [MIN_SIZE, min(incomingLength - 1, capacity)]
        val head = ByteArray(length - 16)
        random.nextBytes(head)
        head[0] = ((head[0].toInt() and 0x3f) or 0x40).toByte() // fixed bit set, long-header bit clear
        out.copyFrom(head, 0, 0, head.size)
        out.copyFrom(token, 0, head.size, 16)
        return length
    }

    /** True when the datagram `[0, end)` ends with [token]; an all-zero token never matches (section 10.3.1). */
    fun matches(
        buf: PacketBuffer,
        end: Int,
        token: ByteArray,
    ): Boolean {
        if (end < MIN_SIZE || token.size != 16) return false
        var nonZero = 0
        for (b in token) nonZero = nonZero or b.toInt()
        if (nonZero == 0) return false
        return ConstantTime.equals(buf, end - 16, token, 0, 16)
    }
}

/** Budget for stateless answers (Version Negotiation, Retry, Stateless Reset) per peer address and in total, per second. */
internal class StatelessRateLimiter(
    private val perAddressPerSecond: Int,
    private val totalPerSecond: Int,
) {
    private var windowStart = TimeMark.NEVER
    private var total = 0
    private val perAddress = HashMap<InetSocketAddress, Int>()

    fun allow(
        to: InetSocketAddress,
        now: TimeMark,
    ): Boolean {
        if (windowStart == TimeMark.NEVER || now - windowStart >= 1.seconds) {
            windowStart = now
            total = 0
            perAddress.clear()
        }
        if (total >= totalPerSecond) return false
        val n = perAddress[to] ?: 0
        if (n >= perAddressPerSecond) return false
        if (n == 0 && perAddress.size >= MAX_ADDRESSES) return false // the table itself is bounded
        perAddress[to] = n + 1
        total++
        return true
    }

    private companion object {
        const val MAX_ADDRESSES = 4096
    }
}
