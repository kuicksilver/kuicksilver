// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.kuicksilver.tls.KslCrypto
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.random.Random

/**
 * One CSPRNG stream: OpenSSL's `RAND_bytes` through `ksl`, refilled in 4 KiB blocks. Not thread-safe: each
 * endpoint loop owns one ([KslRandom.newSource]) and hands it to its `EndpointCore`, which shares it with its connections.
 */
internal class KslRandomSource : Random() {
    private val buffer = ByteArray(4096)
    private var pos = buffer.size

    private fun refill() {
        KslCrypto.randomBytes(buffer.size).copyInto(buffer)
        pos = 0
    }

    private fun nextByte(): Int {
        if (pos >= buffer.size) refill()
        return buffer[pos++].toInt() and 0xff
    }

    override fun nextBits(bitCount: Int): Int {
        if (bitCount == 0) return 0
        var v = 0
        var bits = 0
        while (bits < bitCount) {
            v = (v shl 8) or nextByte()
            bits += 8
        }
        return v ushr (bits - bitCount)
    }

    override fun nextBytes(
        array: ByteArray,
        fromIndex: Int,
        toIndex: Int,
    ): ByteArray {
        require(
            fromIndex in 0..array.size && toIndex in fromIndex..array.size,
        ) { "fromIndex ($fromIndex) or toIndex ($toIndex) out of range" }
        var i = fromIndex
        while (i <
            toIndex
        ) {
            if (pos >=
                buffer.size
            ) {
                refill()
            }
            val n = minOf(toIndex - i, buffer.size - pos)
            buffer.copyInto(array, i, pos, pos + n)
            pos += n
            i +=
                n
        }
        return array
    }
}

/**
 * The process-wide fallback: thread-safe (a short spin lock around one [KslRandomSource]) for code without a loop of
 * its own. Endpoint loops take a private [newSource] instead (several loops drew from one unsynchronised
 * buffer and could read the same bytes or overrun it).
 */
@OptIn(ExperimentalAtomicApi::class)
internal object KslRandom : Random() {
    private val lock = AtomicInt(0)
    private val source = KslRandomSource()

    /** A private CSPRNG stream for one endpoint loop (single-threaded use only). */
    fun newSource(): Random = KslRandomSource()

    private inline fun <T> locked(block: () -> T): T {
        while (!lock.compareAndSet(0, 1)) { /* spin: the critical section is a few array reads, a refill at most */ }
        try {
            return block()
        } finally {
            lock.store(0)
        }
    }

    override fun nextBits(bitCount: Int): Int = locked { source.nextBits(bitCount) }

    override fun nextBytes(
        array: ByteArray,
        fromIndex: Int,
        toIndex: Int,
    ): ByteArray = locked { source.nextBytes(array, fromIndex, toIndex) }
}
