// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class)

package io.kuicksilver.quic.endpoint

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.QuicLbConfig
import io.kuicksilver.tls.LoadBalancerKey
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.fetchAndIncrement

/**
 * The QUIC-LB block encryption of draft-ietf-quic-load-balancers-21 section 5.4 over `len` bytes in place: one AES-128-ECB
 * block when `len` is 16 (5.4.1), else the four-pass Feistel network of 5.4.2 whose round function is AES over
 * `expand(len, pass, half)`. For an odd `len` the middle byte is split between the halves, the left one keeping its high
 * nibble and the right one its low nibble, and each pass clears the other nibble of the half it wrote (steps 2, 5, 7, 9, 11).
 *
 * Stateless (every call allocates its scratch), so one key may serve the loops of a group at once.
 */
internal object QuicLbCipher {
    /** `expand(length, pass, input)` (section 5.4.2.2): the first [half] bytes of [input], zeros, then [length] and [pass]. */
    fun expand(
        length: Int,
        pass: Int,
        input: ByteArray,
        half: Int,
        out: ByteArray,
    ) {
        out.fill(0)
        input.copyInto(out, 0, 0, half)
        out[14] = length.toByte()
        out[15] = pass.toByte()
    }

    /** dst ^= truncate(AES(expand(len, pass, src)), half). */
    private fun pass(
        key: LoadBalancerKey,
        len: Int,
        pass: Int,
        src: ByteArray,
        dst: ByteArray,
        half: Int,
        block: ByteArray,
    ) {
        expand(len, pass, src, half, block)
        key.encrypt(block, 0, block, 0)
        for (i in 0 until half) dst[i] = (dst[i].toInt() xor block[i].toInt()).toByte()
    }

    private fun clearLast(
        left: ByteArray,
        half: Int,
        odd: Boolean,
    ) {
        if (odd) left[half - 1] = (left[half - 1].toInt() and 0xf0).toByte()
    }

    private fun clearFirst(
        right: ByteArray,
        odd: Boolean,
    ) {
        if (odd) right[0] = (right[0].toInt() and 0x0f).toByte()
    }

    private fun split(
        b: ByteArray,
        off: Int,
        len: Int,
        half: Int,
        left: ByteArray,
        right: ByteArray,
    ) {
        b.copyInto(left, 0, off, off + half)
        b.copyInto(right, 0, off + len - half, off + len)
        clearLast(left, half, len and 1 == 1)
        clearFirst(right, len and 1 == 1)
    }

    private fun join(
        left: ByteArray,
        right: ByteArray,
        half: Int,
        b: ByteArray,
        off: Int,
        len: Int,
    ) {
        right.copyInto(b, off + len - half, 0, half)
        left.copyInto(b, off, 0, half - 1)
        // an odd length shares the middle byte: the left half's high nibble, the right half's low nibble (both others are zero)
        b[off + half - 1] = if (len and 1 == 1) (left[half - 1].toInt() or right[0].toInt()).toByte() else left[half - 1]
    }

    fun encrypt(
        key: LoadBalancerKey,
        b: ByteArray,
        off: Int,
        len: Int,
    ) {
        if (len == 16) return key.encrypt(b, off, b, off)
        val half = (len + 1) / 2
        val odd = len and 1 == 1
        val left = ByteArray(half)
        val right = ByteArray(half)
        val block = ByteArray(16)
        split(b, off, len, half, left, right)
        pass(key, len, 1, left, right, half, block)
        clearFirst(right, odd)
        pass(key, len, 2, right, left, half, block)
        clearLast(left, half, odd)
        pass(key, len, 3, left, right, half, block)
        clearFirst(right, odd)
        pass(key, len, 4, right, left, half, block)
        clearLast(left, half, odd)
        join(left, right, half, b, off, len)
        block.fill(0)
    }

    fun decrypt(
        key: LoadBalancerKey,
        b: ByteArray,
        off: Int,
        len: Int,
    ) {
        if (len == 16) return key.decrypt(b, off, b, off)
        val half = (len + 1) / 2
        val odd = len and 1 == 1
        val left = ByteArray(half)
        val right = ByteArray(half)
        val block = ByteArray(16)
        split(b, off, len, half, left, right)
        pass(key, len, 4, right, left, half, block)
        clearLast(left, half, odd)
        pass(key, len, 3, left, right, half, block)
        clearFirst(right, odd)
        pass(key, len, 2, right, left, half, block)
        clearLast(left, half, odd)
        pass(key, len, 1, left, right, half, block)
        clearFirst(right, odd)
        join(left, right, half, b, off, len)
        left.fill(0)
        right.fill(0)
        block.fill(0)
    }
}

/**
 * Connection IDs of one [QuicLbConfig] (draft-ietf-quic-load-balancers-21 sections 3 and 5): `first octet || server ID ||
 * nonce`, the first octet `configId << 5 | (cidLength - 1)` (config rotation and self-encoded length), the rest in clear
 * without a key, else encrypted ([QuicLbCipher]). [key] belongs to the caller. Stateless, so the loops of a group share one.
 */
internal class QuicLbCodec(
    val config: QuicLbConfig,
    private val key: LoadBalancerKey?,
) {
    init {
        require((key != null) == config.encrypted) { "a key exactly when the configuration has one" }
    }

    val sidLength: Int = config.serverIdLength
    val plainLength: Int = sidLength + config.nonceLength
    val cidLength: Int = 1 + plainLength
    val firstOctet: Int = (config.configId shl 5) or (cidLength - 1)

    /** Writes the connection ID for [nonce] ([QuicLbConfig.nonceLength] bytes) into `out[0, cidLength)`. */
    fun encode(
        nonce: ByteArray,
        out: ByteArray,
    ) {
        out[0] = firstOctet.toByte()
        for (i in 0 until sidLength) out[1 + i] = config.serverIdAt(i)
        nonce.copyInto(out, 1 + sidLength, 0, config.nonceLength)
        if (key != null) QuicLbCipher.encrypt(key, out, 1, plainLength)
    }

    /** The server ID of the connection ID at `cid[off]`, or null when its first octet is not this configuration's. */
    fun decodeServerId(
        cid: ByteArray,
        off: Int,
    ): ByteArray? {
        if (off + cidLength > cid.size || (cid[off].toInt() and 0xff) != firstOctet) return null
        val plain = cid.copyOfRange(off + 1, off + cidLength)
        if (key != null) QuicLbCipher.decrypt(key, plain, 0, plainLength)
        return plain.copyOf(sidLength).also { plain.fill(0) }
    }

    /** True when the connection ID at `buf[off]` (cidLength bytes) has this configuration's first octet and our server ID. */
    fun matchesServerId(
        buf: PacketBuffer,
        off: Int,
    ): Boolean {
        if ((buf[off].toInt() and 0xff) != firstOctet) return false
        val plain = ByteArray(plainLength)
        buf.copyTo(plain, off + 1, 0, plainLength)
        if (key != null) QuicLbCipher.decrypt(key, plain, 0, plainLength)
        var same = true
        for (i in 0 until sidLength) if (plain[i] != config.serverIdAt(i)) same = false
        plain.fill(0)
        return same
    }
}

/**
 * The nonces of one QUIC-LB nonce space (one server ID, nonce length and key): a counter that starts at a random [seed] and
 * is permuted with a local random [permute] key ([QuicLbCipher] over [length] bytes), so no nonce repeats and none shows a
 * relation to the one before (draft-ietf-quic-load-balancers-21 section 5.4: plaintext nonces "MUST" have "no observable
 * relationship to the field in previously issued connection IDs"; section 9.6: "the server MUST NOT reuse a nonce until it
 * switches to a configuration with new keys", and servers "SHOULD start with a random nonce value"). After 2^(8 x length)
 * draws (never for 8 bytes or more: 2^63) the space is spent and [next] returns null for good: the caller issues
 * unroutable connection IDs (section 9.6: "A server that has exhausted its nonces MUST either switch to a different
 * configuration, or if none exists, use the 4-tuple routing config rotation codepoint"). Thread-safe: the loops of a group
 * draw from one counter. [start] is a test hook (draws already made).
 */
internal class QuicLbNonces(
    val length: Int,
    seed: ByteArray,
    private val permute: LoadBalancerKey?,
    start: Long = 0,
) {
    private val seed = seed.copyOf()
    private val drawn = AtomicLong(start)
    private val limit: Long = if (length >= 8) Long.MAX_VALUE else 1L shl (8 * length)

    /** True once every nonce of the space was drawn. */
    val exhausted: Boolean get() = drawn.load().let { it < 0 || it >= limit }

    /** The next nonce, or null when the space is spent. */
    fun next(): ByteArray? {
        val n = drawn.fetchAndIncrement()
        if (n < 0 || n >= limit) {
            drawn.store(limit) // stays spent; no wrap of the counter itself
            return null
        }
        // seed + n, big-endian, modulo 2^(8 x length)
        val out = ByteArray(length)
        var carry = 0
        var v = n
        for (i in length - 1 downTo 0) {
            val s = (seed[i].toInt() and 0xff) + (v and 0xff).toInt() + carry
            out[i] = s.toByte()
            carry = s ushr 8
            v = v ushr 8
        }
        permute?.let { QuicLbCipher.encrypt(it, out, 0, length) }
        return out
    }
}
