// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.core.AddressClass
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.tls.QuicCrypto
import io.kuicksilver.tls.TokenKey
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

/** What a token in a client Initial turned out to be. */
internal sealed interface TokenCheck {
    object Absent : TokenCheck

    /** Neither a Retry nor a NEW_TOKEN token of ours (another type byte): ignored, the address stays unvalidated (RFC 9000 section 8.1.3). */
    object NotRetry : TokenCheck

    /** A Retry-type token that does not open: refused with INVALID_TOKEN. */
    object Invalid : TokenCheck

    /** A Retry token older than its lifetime: refused with INVALID_TOKEN. */
    object Expired : TokenCheck

    /** Our token: the client's original Destination Connection ID and the Source Connection ID of the Retry that carried it. */
    class Valid(
        val odcid: ConnectionId,
        val retryScid: ConnectionId,
    ) : TokenCheck

    /**
     * A NEW_TOKEN token of ours, for this client's IP and within its lifetime; its [nonce] still has to pass the replay register
     * ([AddressTokens.admitNewToken]) before the address counts as validated.
     */
    class NewTokenValid(
        val nonce: Long,
    ) : TokenCheck

    /**
     * A NEW_TOKEN-type token that does not validate (forged, truncated, expired, minted for another IP, or replayed): treated as no
     * token at all, never answered with INVALID_TOKEN (RFC 9000 section 8.1.3: the client may hold a stale one).
     */
    object NewTokenRejected : TokenCheck
}

/**
 * The server's address-validation tokens (RFC 9000 section 8.1), both kinds under one set of [TokenKey]s that live inside ksl:
 *
 * - Retry tokens (section 8.1.2): `0x01 | nonce(8) | AEAD(issuedAt(8) | odcidLen(1) | odcid | scidLen(1) | scid)` with the
 *   client's address, port and the QUIC version as associated data. The Retry SCID binds the token to the one Initial that may
 *   carry it (section 8.1.3: the server checks it against the Destination Connection ID). They live [retryLifetime] and open
 *   under the current or the previous key.
 * - NEW_TOKEN tokens (section 8.1.3): `0x02 | nonce(8) | AEAD(issuedAt(8))` with `0x02 | client IP` as associated data, as
 *   quic-go and ngtcp2 bind them: no port (a NAT picks a new one per flow) and no connection ID, so the token says nothing that
 *   links the connection it was issued on to the one that presents it. The random nonce makes every token unique. Its top byte
 *   names the key generation that sealed it, so a token costs one AEAD open, forged or not. They live [newTokenLifetime] and pass
 *   the replay register once ([admitNewToken]; section 8.1.4).
 *
 * Keys rotate every [rotateEvery]; the keys of the last `newTokenLifetime / rotateEvery + 1` generations are kept so a NEW_TOKEN
 * token opens for its whole lifetime, while a Retry token only opens under the two newest. A token is checked by the process that
 * minted it (process time, keys only in memory).
 *
 * One instance serves every loop of a [io.kuicksilver.quic.runtime.LoopGroup] ([owners] of them): a client the kernel hashes onto
 * another loop next time still holds a token that loop can check. Every call takes a short lock (`ksl_seal` mutates the key's EVP
 * context, and [random] is not thread-safe); the keys are freed when the last owner calls [close].
 */
@OptIn(ExperimentalAtomicApi::class)
internal class AddressTokens(
    private val crypto: QuicCrypto,
    private val random: Random,
    private val retryLifetime: Duration = 10.seconds,
    /** Null: this server issues no NEW_TOKEN tokens, and any it is shown are rejected. */
    val newTokenLifetime: Duration? = DEFAULT_NEW_TOKEN_LIFETIME,
    private val rotateEvery: Duration = 1.hours,
    owners: Int = 1,
    /** The NEW_TOKEN replay register (keyed from [random]); tests shrink it. */
    register: ZeroRttReplayRegister? = null,
) : AutoCloseable {
    init {
        require(owners >= 1)
        require(rotateEvery.isPositive())
        newTokenLifetime?.let { require(it.isPositive() && it <= MAX_NEW_TOKEN_LIFETIME) { "newTokenLifetime must be in (0, 7 days]" } }
    }

    private val lock = AtomicInt(0)
    private val owners = AtomicInt(owners)

    /** Generations kept: enough for a NEW_TOKEN token sealed just before a rotation to open until it expires; never more than the generation byte tells apart. */
    private val ring: Int =
        newTokenLifetime
            ?.let { ((it.inWholeNanoseconds + rotateEvery.inWholeNanoseconds - 1) / rotateEvery.inWholeNanoseconds).toInt() + 1 }
            ?.coerceAtLeast(2) ?: 2

    init {
        require(ring <= 256) { "newTokenLifetime / rotateEvery must stay below 256 key generations" }
    }

    private val keys = arrayOfNulls<TokenKey>(ring)
    private val generations = LongArray(ring) { -1L }
    private var current = 0L
    private var epoch: TimeMark = TimeMark.NEVER
    private var closed = false

    /**
     * One fingerprint per accepted NEW_TOKEN nonce for as long as the token lives (entries last between one and two lifetimes); made
     * on the first token shown, outside the lock (1 MiB), so a server nobody returns to holds no memory for it.
     */
    private val replay = AtomicReference(register)

    init {
        keys[0] = crypto.newTokenKey()
        generations[0] = 0
    }

    private inline fun <T> locked(block: () -> T): T {
        // held for one AEAD seal or open (a microsecond) and a few array writes, never across a suspension or a key setup: a
        // blocking lock would cost more than the wait
        while (!lock.compareAndSet(0, 1)) { /* spin */ }
        try {
            check(!closed) { "address tokens closed" }
            return block()
        } finally {
            lock.store(0)
        }
    }

    /** The key generation of [now], or -1 when the current one covers it (the loops' clocks may differ by microseconds: never backwards). */
    private fun generationToMake(now: TimeMark): Long {
        if (epoch == TimeMark.NEVER) {
            epoch = now
            return -1
        }
        val elapsed = now - epoch
        if (!elapsed.isPositive()) return -1
        val g = elapsed.inWholeNanoseconds / rotateEvery.inWholeNanoseconds
        return if (g <= current) -1 else g
    }

    /**
     * Moves to the key generation of [now]. The new key is made, and the one it replaces freed, outside the lock: the lock only
     * ever covers an AEAD seal or open and a few array writes, never an OpenSSL key setup.
     */
    private fun rotate(now: TimeMark) {
        val g = locked { generationToMake(now) }
        if (g < 0) return
        val made = crypto.newTokenKey()
        val unused =
            locked {
                if (g <= current) {
                    made // another loop moved there first
                } else {
                    current = g
                    val slot = (g % ring).toInt()
                    val old = keys[slot]
                    keys[slot] = made
                    generations[slot] = g
                    old // out of reach now: every use of a key happens under the lock
                }
            }
        unused?.close()
    }

    private fun key(generation: Long): TokenKey? {
        if (generation < 0 || generation > current || current - generation >= ring) return null
        val slot = (generation % ring).toInt()
        return if (generations[slot] == generation) keys[slot] else null
    }

    private fun retryAad(
        client: InetSocketAddress,
        version: Int,
    ): ByteArray {
        val ip = AddressClass.ipBytes(client)
        val out = ByteArray(1 + ip.size + 2 + 4)
        out[0] = RETRY
        ip.copyInto(out, 1)
        out[1 + ip.size] = (client.port ushr 8).toByte()
        out[2 + ip.size] = client.port.toByte()
        for (i in 0 until 4) out[3 + ip.size + i] = (version ushr (8 * (3 - i))).toByte()
        return out
    }

    private fun newTokenAad(client: InetSocketAddress): ByteArray {
        val ip = AddressClass.ipBytes(client)
        val out = ByteArray(1 + ip.size)
        out[0] = NEW_TOKEN
        ip.copyInto(out, 1)
        return out
    }

    private fun token(
        type: Byte,
        nonce: Long,
        sealed: ByteArray,
    ): ByteArray {
        val token = ByteArray(1 + 8 + sealed.size)
        token[0] = type
        for (i in 0 until 8) token[1 + i] = (nonce ushr (8 * (7 - i))).toByte()
        sealed.copyInto(token, 9)
        return token
    }

    private fun issuedAt(now: TimeMark): ByteArray =
        ByteArray(8).also {
            for (i in 0 until 8) {
                it[i] =
                    (now.nanos ushr (8 * (7 - i))).toByte()
            }
        }

    /** A Retry token for the Initial from [client] whose DCID was [odcid], answered by a Retry with SCID [retryScid]. */
    fun mint(
        odcid: ConnectionId,
        retryScid: ConnectionId,
        client: InetSocketAddress,
        version: Int,
        now: TimeMark,
    ): ByteArray {
        rotate(now)
        return locked {
            val nonce = random.nextLong()
            val plain = ByteArray(8 + 1 + odcid.length + 1 + retryScid.length)
            issuedAt(now).copyInto(plain, 0)
            plain[8] = odcid.length.toByte()
            odcid.copyToArray(plain, 9)
            plain[9 + odcid.length] = retryScid.length.toByte()
            retryScid.copyToArray(plain, 10 + odcid.length)
            token(RETRY, nonce, key(current)!!.seal(nonce, retryAad(client, version), plain))
        }
    }

    /** A NEW_TOKEN token for [client]'s IP (RFC 9000 section 19.7); only when [newTokenLifetime] is set. */
    fun mintNewToken(
        client: InetSocketAddress,
        now: TimeMark,
    ): ByteArray {
        checkNotNull(newTokenLifetime) { "this server issues no NEW_TOKEN tokens" }
        rotate(now)
        return locked {
            val nonce = ((current and 0xff) shl 56) or (random.nextLong() ushr 8)
            token(NEW_TOKEN, nonce, key(current)!!.seal(nonce, newTokenAad(client), issuedAt(now)))
        }
    }

    fun check(
        token: PacketBuffer,
        off: Int,
        len: Int,
        client: InetSocketAddress,
        version: Int,
        now: TimeMark,
    ): TokenCheck {
        if (len == 0) return TokenCheck.Absent
        return when (token[off]) {
            RETRY -> checkRetry(token, off, len, client, version, now)
            NEW_TOKEN -> checkNewToken(token, off, len, client, now)
            else -> TokenCheck.NotRetry
        }
    }

    private fun nonceOf(
        token: PacketBuffer,
        off: Int,
    ): Long {
        var nonce = 0L
        for (i in 0 until 8) nonce = (nonce shl 8) or (token[off + 1 + i].toLong() and 0xff)
        return nonce
    }

    private fun checkRetry(
        token: PacketBuffer,
        off: Int,
        len: Int,
        client: InetSocketAddress,
        version: Int,
        now: TimeMark,
    ): TokenCheck {
        if (len < 1 + 8 + 16 + 10) return TokenCheck.Invalid
        val nonce = nonceOf(token, off)
        val sealed = ByteArray(len - 9)
        token.copyTo(sealed, off + 9, 0, sealed.size)
        val a = retryAad(client, version)
        rotate(now)
        val plain =
            locked {
                key(current)?.open(nonce, a, sealed) ?: key(current - 1)?.open(nonce, a, sealed)
            } ?: return TokenCheck.Invalid
        if (plain.size < 10) return TokenCheck.Invalid
        val issued = readLong(plain)
        val odcidLen = plain[8].toInt() and 0xff
        if (odcidLen > 20 || plain.size < 10 + odcidLen) return TokenCheck.Invalid
        val scidLen = plain[9 + odcidLen].toInt() and 0xff
        if (scidLen > 20 || plain.size != 10 + odcidLen + scidLen) return TokenCheck.Invalid
        if (now.nanos - issued > retryLifetime.inWholeNanoseconds || now.nanos < issued - CLOCK_SLACK_NANOS) return TokenCheck.Expired
        val scidOff = 10 + odcidLen
        return TokenCheck.Valid(
            ConnectionId(plain.copyOfRange(9, 9 + odcidLen)),
            ConnectionId(plain.copyOfRange(scidOff, scidOff + scidLen)),
        )
    }

    private fun checkNewToken(
        token: PacketBuffer,
        off: Int,
        len: Int,
        client: InetSocketAddress,
        now: TimeMark,
    ): TokenCheck {
        val lifetime = newTokenLifetime ?: return TokenCheck.NewTokenRejected
        if (len != NEW_TOKEN_SIZE) return TokenCheck.NewTokenRejected
        val nonce = nonceOf(token, off)
        val sealed = ByteArray(len - 9)
        token.copyTo(sealed, off + 9, 0, sealed.size)
        rotate(now)
        val plain =
            locked {
                // the newest generation whose low byte the nonce names
                val generation = current - ((current - (nonce ushr 56)) and 0xff)
                key(generation)?.open(nonce, newTokenAad(client), sealed)
            } ?: return TokenCheck.NewTokenRejected
        if (plain.size != 8) return TokenCheck.NewTokenRejected
        val issued = readLong(plain)
        if (now.nanos - issued > lifetime.inWholeNanoseconds || now.nanos < issued - CLOCK_SLACK_NANOS) return TokenCheck.NewTokenRejected
        return TokenCheck.NewTokenValid(nonce)
    }

    private fun readLong(b: ByteArray): Long {
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (b[i].toLong() and 0xff)
        return v
    }

    private fun nonceBytes(nonce: Long) = ByteArray(8).also { for (i in 0 until 8) it[i] = (nonce ushr (8 * (7 - i))).toByte() }

    /**
     * True the first time a valid NEW_TOKEN token's [nonce] is shown within its lifetime: the address counts as validated. False for a
     * replay, or when the register is full (fails closed: the client is treated as one without a token, at worst a Retry).
     */
    fun admitNewToken(
        nonce: Long,
        now: TimeMark,
    ): Boolean {
        val lifetime = newTokenLifetime ?: return false
        val r =
            replay.load() ?: run {
                val k0 = locked { random.nextLong() } // the SipHash keys: [random] is shared, the rest happens unlocked
                val k1 = locked { random.nextLong() }
                val made = ZeroRttReplayRegister(k0, k1, halfSpan = lifetime)
                if (replay.compareAndSet(null, made)) made else replay.load()!!
            }
        return r.admit(nonceBytes(nonce), now)
    }

    /** Forgets [nonce]: the Initial that carried it created no connection, so the client may show it again. */
    fun releaseNewToken(nonce: Long) {
        replay.load()?.release(nonceBytes(nonce))
    }

    /** Called once by every owner (each loop's endpoint core); the last one frees the keys. */
    override fun close() {
        if (owners.decrementAndFetch() != 0) return
        locked {
            for (i in keys.indices) {
                keys[i]?.close()
                keys[i] = null
            }
            closed = true
        }
    }

    companion object {
        private const val RETRY: Byte = 0x01
        private const val NEW_TOKEN: Byte = 0x02

        /** `0x02 | nonce(8) | issuedAt(8) | tag(16)`. */
        const val NEW_TOKEN_SIZE = 1 + 8 + 8 + 16

        /** How far another loop's clock may run ahead of this one's (each loop counts from its own start). */
        private const val CLOCK_SLACK_NANOS = 1_000_000_000L

        val DEFAULT_NEW_TOKEN_LIFETIME: Duration = 24.hours
        val MAX_NEW_TOKEN_LIFETIME: Duration = 7.days
    }
}
