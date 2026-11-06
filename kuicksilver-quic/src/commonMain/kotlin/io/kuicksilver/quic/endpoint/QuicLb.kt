// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class)

package io.kuicksilver.quic.endpoint

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.QuicLbConfig
import io.kuicksilver.tls.LoadBalancerKey
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.fetchAndIncrement
import kotlin.random.Random

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
        left.fill(0)
        right.fill(0)
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
 * without a key, else encrypted ([QuicLbCipher]) with the configuration's key. Stateless, so the loops of a group share one.
 */
internal class QuicLbCodec(
    val config: QuicLbConfig,
    private val key: LoadBalancerKey? = config.key,
) {
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
 * The blocks a configuration key encrypts for the endpoint's own use: a fingerprint, the nonce permutation key and the seed.
 * Each is `"kuicksilver-lb" (14 bytes) || nonce length || 0x80 + use`: its last byte is never a Feistel pass number (1..4),
 * so none equals an `expand` block (draft section 5.4.2.2) under the same key. A single-pass connection ID encrypts
 * arbitrary 16 bytes, so one could in principle carry the encryption of such a block; that shows only a value derived
 * from the key (the fingerprint, the permutation key of nonces that are encrypted anyway), never the key.
 */
internal object QuicLbDerivation {
    const val FINGERPRINT = 0x80
    const val PERMUTE = 0x81
    const val SEED = 0x82
    private val PREFIX = "kuicksilver-lb".encodeToByteArray()

    fun label(
        use: Int,
        nonceLength: Int,
        index: Int = 0,
    ): ByteArray =
        ByteArray(16).also {
            PREFIX.copyInto(it)
            it[14] = (nonceLength or (index shl 6)).toByte()
            it[15] = use.toByte()
        }
}

/** A spin lock for the few places loops meet: held for a few field or collection writes, never across I/O or a key setup. */
internal class SpinLock {
    private val held = AtomicInt(0)

    inline fun <T> locked(block: () -> T): T {
        while (!held.compareAndSet(0, 1)) { /* spin */ }
        try {
            return block()
        } finally {
            held.store(0)
        }
    }
}

/**
 * The nonces of one QUIC-LB nonce space: one key and nonce length (or, in clear, one nonce length), shared by every
 * endpoint of the process ([QuicLbNonceSpaces]) whatever their server IDs. A counter that starts at [seed] is permuted
 * ([QuicLbCipher] over [length] bytes, with a key derived from the configuration key, or [plainPermute] in clear), so no
 * nonce repeats and none shows a relation to the one before (draft-ietf-quic-load-balancers-21 section 5.4: plaintext nonces
 * "MUST" have "no observable relationship to the field in previously issued connection IDs"; section 9.6: "the server MUST
 * NOT reuse a nonce until it switches to a configuration with new keys", and servers "SHOULD start with a random nonce
 * value"). After 2^(8 x length) draws (never for 8 bytes or more: 2^63) the space is spent ([exhausted]) and [next] returns
 * null for good: the caller issues unroutable connection IDs (section 9.6: "A server that has exhausted its nonces MUST
 * either switch to a different configuration, or if none exists, use the 4-tuple routing config rotation codepoint").
 *
 * With a [reservation] the counter resumes past the mark the last process stored. Nonces are used only below the mark
 * stored last; the next block is stored ahead of need, once half of the current one is drawn, by the thread that crosses
 * it, outside any lock (the other loops go on drawing what is reserved). A failed store is retried after a back-off
 * counted in draws (sans IO: no clock here), 64 draws doubling to 65,536; a draw past the reserved mark meanwhile returns
 * null without the space being spent (the caller gives that one request an unroutable ID). Thread-safe. [start] is a test
 * hook.
 */
internal class QuicLbNonceSpace(
    val length: Int,
    seed: ByteArray,
    val plainPermute: LoadBalancerKey?,
    val reservation: io.kuicksilver.quic.QuicLbNonceReservation? = null,
    start: Long = 0,
) {
    private val seed = seed.copyOf()
    private val limit: Long = if (length >= 8) Long.MAX_VALUE else 1L shl (8 * length)
    private val drawn = AtomicLong(maxOf(start, reservation?.load() ?: 0L))
    private val reservedUpTo = AtomicLong(drawn.load())
    private val refilling = AtomicInt(0)
    private val retryAt = AtomicLong(Long.MIN_VALUE)
    private var backoffDraws = FIRST_BACKOFF_DRAWS // the refilling thread only

    /** Test hook: every nonce drawn. */
    internal fun spendForTest() = drawn.store(limit)

    /** True once every nonce of the space was drawn. */
    val exhausted: Boolean get() = drawn.load().let { it < 0 || it >= limit }

    /** Stores the next block when the draws are past half of the reserved one; [onStoreFailed] hears a failed store. */
    private fun refill(
        n: Long,
        onStoreFailed: (Throwable) -> Unit,
    ) {
        val r = reservation ?: return
        val reserved = reservedUpTo.load()
        if (reserved >= limit || n < reserved - BLOCK / 2) return
        if (n < retryAt.load() || !refilling.compareAndSet(0, 1)) return
        try {
            val mark = minOf(limit, reservedUpTo.load() + BLOCK)
            if (mark <= reservedUpTo.load()) return
            r.store(mark)
            reservedUpTo.store(mark)
            backoffDraws = FIRST_BACKOFF_DRAWS
        } catch (e: Exception) {
            retryAt.store(n + backoffDraws)
            backoffDraws = minOf(backoffDraws * 2, MAX_BACKOFF_DRAWS)
            onStoreFailed(e)
        } finally {
            refilling.store(0)
        }
    }

    /**
     * The next nonce permuted with [permute] (or [plainPermute]), or null: the space is spent ([exhausted]), or (with a
     * reservation) the draw is past the stored mark (that nonce is skipped, never used).
     */
    fun next(
        permute: LoadBalancerKey?,
        onStoreFailed: (Throwable) -> Unit = {},
    ): ByteArray? {
        val n = drawn.fetchAndIncrement()
        if (n < 0 || n >= limit) {
            drawn.store(limit) // stays spent; no wrap of the counter itself
            return null
        }
        if (reservation != null) {
            refill(n, onStoreFailed)
            if (n >= reservedUpTo.load()) return null
        }
        // seed + n, big-endian, modulo 2^(8 x length)
        val out = ByteArray(length)
        var carry = 0
        var v = n
        for (i in length - 1 downTo 0) {
            val sum = (seed[i].toInt() and 0xff) + (v and 0xff).toInt() + carry
            out[i] = sum.toByte()
            carry = sum ushr 8
            v = v ushr 8
        }
        (permute ?: plainPermute)?.let { QuicLbCipher.encrypt(it, out, 0, length) }
        return out
    }

    companion object {
        val BLOCK: Long = io.kuicksilver.quic.QuicLbNonceReservation.BLOCK
        const val FIRST_BACKOFF_DRAWS = 64L
        const val MAX_BACKOFF_DRAWS = 65_536L
    }
}

/**
 * Every QUIC-LB nonce space of the process, by key fingerprint and nonce length (and by nonce length alone in clear). It
 * lives as long as the process (a few dozen bytes per space): two endpoints, or two server IDs, that use one key draw from
 * one counter, and a configuration that comes back goes on where it stopped (draft section 9.6). An encrypted space keeps
 * only its counter and seed: its permutation key is derived from the configuration key by each user. A plaintext space
 * keeps its permutation key (one per nonce length, at most 15, never freed): random, or with a reservation made from the
 * reservation's stored secret. All configurations of one space must bring the same [QuicLbConfig.nonceReservation]
 * instance (or none): the first one decides how the counter survives a restart.
 */
internal object QuicLbNonceSpaces {
    private val lock = SpinLock()
    private val spaces = HashMap<String, QuicLbNonceSpace>()

    private fun idOf(config: QuicLbConfig): String =
        config.keyFingerprint?.let { "k:$it:${config.nonceLength}" } ?: "p:${config.nonceLength}"

    private fun checkSame(
        space: QuicLbNonceSpace,
        config: QuicLbConfig,
    ): QuicLbNonceSpace {
        require(space.reservation === config.nonceReservation) {
            "every configuration with this key (or, in clear, this nonce length) must bring the same nonceReservation, or none: " +
                "the first one decides where the nonce counter survives a restart"
        }
        return space
    }

    /** IllegalArgumentException when [config] brings another reservation than the space's ([QuicLbConfig.nonceReservation]). */
    fun check(config: QuicLbConfig) {
        lock.locked { spaces[idOf(config)] }?.let { checkSame(it, config) }
    }

    fun of(
        config: QuicLbConfig,
        crypto: io.kuicksilver.tls.QuicCrypto,
        random: Random,
    ): QuicLbNonceSpace {
        val id = idOf(config)
        lock.locked { spaces[id] }?.let { return checkSame(it, config) }
        // made outside the lock (a key, a reservation's load and secret); the first one in wins
        val key = config.key
        val r = config.nonceReservation
        val made =
            if (key != null) {
                // with a reservation, a fixed sequence, so the stored counter means the same nonces in the next process
                val seed =
                    if (r ==
                        null
                    ) {
                        ByteArray(config.nonceLength).also { random.nextBytes(it) }
                    } else {
                        derivedSeed(key, config.nonceLength)
                    }
                QuicLbNonceSpace(config.nonceLength, seed, null, r)
            } else {
                val permute =
                    if (r == null) {
                        crypto.newLoadBalancerKey(null)
                    } else {
                        val secret = r.secret()
                        require(secret.size == 16) { "QuicLbNonceReservation.secret() must give 16 bytes" }
                        crypto.newLoadBalancerKey(secret.copyOf()) // the copy is wiped
                    }
                val seed =
                    if (r == null) ByteArray(config.nonceLength).also { random.nextBytes(it) } else derivedSeed(permute, config.nonceLength)
                QuicLbNonceSpace(config.nonceLength, seed, permute, r)
            }
        val space = lock.locked { spaces[id] ?: made.also { spaces[id] = it } }
        if (space !== made) made.plainPermute?.close()
        return checkSame(space, config)
    }

    private fun derivedSeed(
        key: LoadBalancerKey,
        nonceLength: Int,
    ): ByteArray {
        val b = ByteArray(32)
        for (i in 0..1) key.encrypt(QuicLbDerivation.label(QuicLbDerivation.SEED, nonceLength, i), 0, b, 16 * i)
        return b.copyOf(nonceLength).also { b.fill(0) }
    }

    /** Test hook: a new process, as far as nonce spaces go (the plaintext permutation keys are dropped, not freed). */
    internal fun forgetForTest() = lock.locked { spaces.clear() }
}
