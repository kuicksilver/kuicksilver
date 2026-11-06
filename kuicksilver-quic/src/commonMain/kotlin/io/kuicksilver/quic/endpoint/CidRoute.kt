// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class)

package io.kuicksilver.quic.endpoint

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.QuicLbConfig
import io.kuicksilver.quic.Releaser
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.tls.LoadBalancerKey
import io.kuicksilver.tls.QuicCrypto
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.random.Random

/** How many connection IDs a server connection may hand out, by the kind of the ones it gets (draft-ietf-quic-load-balancers-21). */
internal enum class CidIssuance {
    /** Up to the peer's `active_connection_id_limit` (RFC 9000 section 5.1.1). */
    Full,

    /**
     * Only the handshake ID: plaintext QUIC-LB IDs, which show every observer the server (section 9: "SHOULD NOT send CIDs in
     * QUIC NEW_CONNECTION_ID frames, except that it sends one new Connection ID in the event of config rotation").
     */
    Single,

    /**
     * Only the handshake ID and `disable_active_migration`: unroutable IDs, codepoint 0b111 (section 3.2: "SHOULD provide the
     * client exactly one CID over the life of the connection", "SHOULD send the disable_active_migration transport parameter").
     */
    SingleNoMigration,
}

/** A connection ID and what the configuration that made it allows ([CidIssuance]). */
internal class IssuedCid(
    val cid: ConnectionId,
    val issuance: CidIssuance,
)

/**
 * The one place that knows the layout of this endpoint's connection IDs: it makes them, tells which loop of a group owns one,
 * and whether an unknown one may be answered with a Stateless Reset. Everything that routes by connection ID asks it, so an
 * in-process dispatcher that hands datagrams of one socket to several loops can call [ownerLoop] as it is.
 *
 * - [ByteRoute]: `[0x01][loop index][random]`, the format without a load balancer.
 * - [QuicLbRoute]: QUIC-LB IDs (draft-ietf-quic-load-balancers-21, experimental) when `QuicEndpointConfig.loadBalancer` is set.
 *
 * One instance per loop. [issue], [ownerLoop] and [mayReset] keep no state of their own (a QUIC-LB route reads the shared
 * [QuicLbState]), so [ownerLoop] may also be asked from a thread that is not the loop's.
 */
internal sealed interface CidRoute {
    /** A new connection ID of ours: for a server connection, or with [client] for a client connection of a loop group. */
    fun issue(
        random: Random,
        client: Boolean,
    ): IssuedCid

    fun newCid(
        random: Random,
        client: Boolean,
    ): ConnectionId = issue(random, client).cid

    /**
     * The loop that owns the connection ID at `buf[off, +len)`, or -1 when it is not in our format. A value past the group's
     * loops (the routing byte of a stranger's ID) is left to the caller.
     */
    fun ownerLoop(
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): Int

    /** True when a short header whose unknown DCID is at `buf[off, +len)` may be answered with a Stateless Reset by this loop. */
    fun mayReset(
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): Boolean

    /** What [cid], one of ours made earlier ([issue]; a Retry's SCID), allows, read from its codepoint. */
    fun issuanceOf(cid: ConnectionId): CidIssuance
}

/**
 * Server connection IDs `[format version 0x01][routing byte = loop index][random]`. In a loop group the client connections'
 * IDs take this format too, so the answers of their peers reach the loop that connected.
 */
internal class ByteRoute(
    private val loopIndex: Int,
    private val length: Int,
) : CidRoute {
    override fun issue(
        random: Random,
        client: Boolean,
    ): IssuedCid {
        val b = ByteArray(length)
        random.nextBytes(b)
        b[0] = FORMAT_VERSION.toByte()
        b[1] = loopIndex.toByte()
        return IssuedCid(ConnectionId(b), CidIssuance.Full)
    }

    override fun ownerLoop(
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): Int = if (len == length && buf[off].toInt() == FORMAT_VERSION) buf[off + 1].toInt() and 0xff else -1

    override fun mayReset(
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): Boolean = ownerLoop(buf, off, len) == loopIndex

    override fun issuanceOf(cid: ConnectionId): CidIssuance = CidIssuance.Full

    companion object {
        const val FORMAT_VERSION: Int = 0x01
    }
}

/**
 * The QUIC-LB state of an endpoint, shared by the loops of a group: the configuration new IDs use ([routes]`.current`, null
 * for unroutable IDs), the one before it, still recognised for Stateless Resets, and the SipHash key that spreads IDs over
 * the loops. The loop that owns an ID is `SipHash(key, id) mod loops`: an encrypted ID cannot name its loop in clear, and
 * decrypting it for every datagram would cost up to four AES blocks. A loop that draws a nonce whose ID hashes to another
 * loop keeps it for that loop ([Entry.issue]) instead of spending it.
 *
 * The nonce counters live in the process-wide [QuicLbNonceSpaces] (draft section 9.6: no nonce reuse under one key). The
 * configuration keys belong to the caller; the permutation keys derived from them belong to this state and are freed when
 * their configuration is neither current nor previous any more and no loop uses it. [update] and [close] take [lock].
 */
internal class QuicLbState(
    private val crypto: QuicCrypto,
    private val random: Random,
    initial: QuicLbConfig?,
    val loops: Int,
    val cidLength: Int,
) : AutoCloseable {
    /** One configuration in use: its codec, its nonce space and (encrypted) the permutation key derived for its nonces. */
    inner class Entry(
        val config: QuicLbConfig,
    ) {
        val codec = QuicLbCodec(config)
        val space: QuicLbNonceSpace = QuicLbNonceSpaces.of(config, crypto, random)
        private val permute: LoadBalancerKey? =
            config.key?.derive(QuicLbDerivation.label(QuicLbDerivation.PERMUTE, config.nonceLength))
        private val pools = Array(loops) { ArrayDeque<ByteArray>() }
        private val poolLock = SpinLock()
        private val users = AtomicInt(0)
        private val exhaustNoticed = AtomicInt(0)

        /** IDs drawn for a loop whose pool was full: their nonces are spent unused (a loop that issues far fewer IDs than the others). */
        val wasted = AtomicLong(0)

        /** True the first time any loop finds this configuration's nonces spent. */
        fun firstExhaustion(): Boolean = exhaustNoticed.compareAndSet(0, 1)

        fun enter(): Boolean {
            while (true) {
                val n = users.load()
                if (n < 0) return false
                if (users.compareAndSet(n, n + 1)) return true
            }
        }

        fun exit() {
            if (users.decrementAndFetch() == RETIRED) free()
        }

        /** Out of current and previous: freed once the last loop using it is done. */
        fun retire() {
            while (true) {
                val n = users.load()
                if (n < 0) return
                if (users.compareAndSet(n, n + RETIRED)) {
                    if (n == 0) free()
                    return
                }
            }
        }

        private fun free() {
            permute?.close()
            poolLock.locked { for (p in pools) p.clear() }
        }

        /**
         * An ID that hashes to [loop], from its pool or from new nonces (the ones that hash elsewhere wait in their loop's pool,
         * at most [POOL] each); null when the nonces are spent. Between [enter] and [exit].
         */
        fun issue(
            loop: Int,
            owner: (ByteArray) -> Int,
        ): ByteArray? {
            poolLock.locked { pools[loop].removeFirstOrNull() }?.let { return it }
            while (true) {
                val nonce = space.next(permute) ?: return null
                val b = ByteArray(cidLength)
                codec.encode(nonce, b)
                nonce.fill(0)
                val o = owner(b)
                if (o == loop) return b
                poolLock.locked {
                    if (pools[o].size < POOL) pools[o].addLast(b) else wasted.incrementAndFetch()
                }
            }
        }
    }

    /** The configuration new IDs use (null: unroutable, codepoint 0b111) and the one before it (also null when none). */
    class Routes(
        val current: Entry?,
        val previous: Entry?,
    )

    val k0: Long = random.nextLong()
    val k1: Long = random.nextLong()

    @Volatile var routes: Routes = Routes(null, null)
        private set

    private val owners = AtomicInt(1)
    private val lock = SpinLock()
    private var closed = false

    /** Every server ID this endpoint used, and whether in clear (section 9.7). */
    private val history = ArrayList<kotlin.Pair<String, Boolean>>()

    init {
        if (initial != null) {
            check(initial)
            routes = Routes(Entry(initial), null)
            history += sidHex(initial) to initial.encrypted
        }
    }

    private fun sidHex(c: QuicLbConfig) = c.serverId.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    private fun check(config: QuicLbConfig) {
        require(config.connectionIdLength == cidLength) {
            "QuicLbConfig.connectionIdLength (${config.connectionIdLength}) must equal the endpoint's connectionIdLength ($cidLength)"
        }
    }

    /**
     * New IDs use [config] from now on (null: unroutable IDs); the current configuration becomes the previous one. False when
     * [config] is the current one already (nothing changes). Throws IllegalArgumentException for a configuration of another
     * connection ID length; for one that would use a server ID in clear that an encrypted configuration of this endpoint used,
     * or the other way round (draft section 9.7: "Such deployments MUST use different server ID allocations for the clear text
     * and the encrypted versions"); and for a codepoint the current or previous configuration holds with another key, server
     * ID or nonce length (section 3.1: a codepoint names one configuration while its IDs are in use).
     */
    fun update(config: QuicLbConfig?): Boolean =
        lock.locked {
            check(!closed) { "the endpoint is closed" }
            val r = routes
            if (config != null) {
                check(config)
                val sid = sidHex(config)
                for ((s, enc) in history) {
                    require(enc == config.encrypted || s != sid) {
                        "a server ID used in clear must not be used encrypted, or the other way round (draft-ietf-quic-load-balancers-21 section 9.7)"
                    }
                }
                for (e in listOfNotNull(r.current, r.previous)) {
                    require(e.config.configId != config.configId || e.config.sameAs(config)) {
                        "configId ${config.configId} still names the configuration before it: use another codepoint (draft-ietf-quic-load-balancers-21 section 3.1)"
                    }
                }
            }
            val next =
                when {
                    config == null -> null
                    r.current?.config?.sameAs(config) == true -> r.current
                    r.previous?.config?.sameAs(config) == true -> r.previous
                    else -> Entry(config)
                }
            if (next === r.current) return@locked false
            val previous = r.current ?: r.previous // after a spell of unroutable IDs, the last configuration, whose IDs live on
            routes = Routes(next, previous)
            if (config != null) history += sidHex(config) to config.encrypted
            for (old in listOfNotNull(r.current, r.previous)) if (old !== next && old !== previous) old.retire()
            true
        }

    /** One more owner (an endpoint core of the group); false once closed. */
    fun retain(): Boolean {
        while (true) {
            val n = owners.load()
            if (n == 0) return false
            if (owners.compareAndSet(n, n + 1)) return true
        }
    }

    /** Called once by every owner; the last one frees the permutation keys. */
    override fun close() {
        if (owners.decrementAndFetch() != 0) return
        val r =
            lock.locked {
                closed = true
                routes
            }
        val rel = Releaser()
        for (e in listOfNotNull(r.current, r.previous)) rel.release { e.retire() }
        rel.finish()
    }

    private companion object {
        const val RETIRED = Int.MIN_VALUE / 2

        /** IDs kept per loop for when it needs one: about 30 KiB per loop. */
        const val POOL = 1024
    }
}

/**
 * QUIC-LB connection IDs (draft-ietf-quic-load-balancers-21 sections 3 to 5, experimental) for loop [loopIndex] of
 * [state]'s endpoint: the current configuration's encoding while it has nonces, else unroutable IDs (first octet
 * `0b111 << 5 | (length - 1)`, the rest random: section 3.2), which client connections of a group use as well.
 * [onExhausted] runs once per configuration, on the loop that first finds its nonces spent.
 */
internal class QuicLbRoute(
    private val state: QuicLbState,
    private val loopIndex: Int,
    private val onExhausted: () -> Unit = {},
) : CidRoute {
    private val length = state.cidLength
    private val loops = state.loops

    private fun owner(b: ByteArray): Int = if (loops == 1) 0 else ((SipHash.hash24(state.k0, state.k1, b) ushr 1) % loops).toInt()

    override fun issue(
        random: Random,
        client: Boolean,
    ): IssuedCid {
        if (!client) {
            while (true) {
                val e = state.routes.current ?: break
                if (!e.enter()) {
                    if (state.routes.current === e) break // closed
                    continue // replaced meanwhile: the new one
                }
                try {
                    val b = e.issue(loopIndex, ::owner)
                    if (b != null) return IssuedCid(ConnectionId(b), if (e.config.encrypted) CidIssuance.Full else CidIssuance.Single)
                    if (e.firstExhaustion()) onExhausted()
                } finally {
                    e.exit()
                }
                break // spent: unroutable from now on (section 9.6)
            }
        }
        val b = ByteArray(length)
        while (true) {
            random.nextBytes(b)
            b[0] = (UNROUTABLE shl 5 or (length - 1)).toByte() // section 3.2: unroutable IDs "MUST self-encode their length"
            if (owner(b) == loopIndex) return IssuedCid(ConnectionId(b), CidIssuance.SingleNoMigration)
        }
    }

    /**
     * Any ID of our length whose first octet encodes that length, whatever its codepoint: an ID of a configuration two
     * changes back can still be in use (RFC 9000 section 5.1.2: retired IDs are accepted until the peer retires them), and
     * the owner never depends on it.
     */
    override fun ownerLoop(
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): Int {
        if (len != length || (buf[off].toInt() and 0x1f) != length - 1) return -1
        return if (loops == 1) 0 else ((SipHash.hash24(state.k0, state.k1, buf, off, len) ushr 1) % loops).toInt()
    }

    /**
     * Only for an ID this loop could have issued under the current or previous configuration: its codepoint, our server ID
     * once decrypted (checked last), and a hash that names this loop. Never for an unroutable ID, which carries no server ID.
     */
    override fun mayReset(
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): Boolean {
        if (ownerLoop(buf, off, len) != loopIndex) return false
        val cr = (buf[off].toInt() and 0xff) ushr 5
        if (cr == UNROUTABLE) return false
        val r = state.routes
        for (e in arrayOf(r.current, r.previous)) {
            if (e != null && e.config.configId == cr && e.codec.matchesServerId(buf, off)) return true
        }
        return false
    }

    override fun issuanceOf(cid: ConnectionId): CidIssuance {
        val cr = (cid[0].toInt() and 0xff) ushr 5
        if (cr == UNROUTABLE) return CidIssuance.SingleNoMigration
        val r = state.routes
        val e = if (r.current?.config?.configId == cr) r.current else r.previous?.takeIf { it.config.configId == cr }
        return if (e?.config?.encrypted == false) CidIssuance.Single else CidIssuance.Full
    }

    companion object {
        /** The config rotation codepoint of unroutable IDs (section 3.1: "MUST NOT use the reserved identifier 0b111"). */
        const val UNROUTABLE: Int = 7
    }
}
