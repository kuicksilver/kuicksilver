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
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.decrementAndFetch
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

/**
 * A connection ID and what the configuration that made it allows ([CidIssuance]). [temporary]: an unroutable ID only because
 * no nonce was reserved just now (a failed `QuicLbNonceReservation.store`), not because the nonces are spent: a connection
 * that has IDs skips this one and goes on issuing later.
 */
internal class IssuedCid(
    val cid: ConnectionId,
    val issuance: CidIssuance,
    val temporary: Boolean = false,
)

/** The Stateless Reset gate's answer for an unknown short-header DCID. */
internal enum class ResetGate {
    /** Not one this loop could have issued: no reset. */
    No,

    /** One of ours: a reset may go out (under the stateless rate limit). */
    Yes,

    /** It could be ours, but the decryption budget of the second is spent: no reset, counted as rate limited. */
    RateLimited,
}

/**
 * The one place that knows the layout of this endpoint's connection IDs: it makes them, tells which loop of a group owns one,
 * and whether an unknown one may be answered with a Stateless Reset. Everything that routes by connection ID asks it, so an
 * in-process dispatcher that hands datagrams of one socket to several loops can call [ownerLoop] as it is.
 *
 * - [ByteRoute]: `[0x01][loop index][random]`, the format without a load balancer.
 * - [QuicLbRoute]: QUIC-LB IDs (draft-ietf-quic-load-balancers-21, experimental) when `QuicEndpointConfig.loadBalancer` is set.
 *
 * One instance per loop, called on that loop's thread; [ownerLoop] reads only shared, thread-safe state, so it may also be
 * asked from another thread.
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

    /** Cheap, no decryption: the DCID at `buf[off, +len)` could be one this loop issued and answers with a Stateless Reset. */
    fun resetCandidate(
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): Boolean

    /**
     * Whether a [resetCandidate] may be answered with a Stateless Reset; a check that decrypts asks [decryptBudget] first and
     * answers [ResetGate.RateLimited] when it says no.
     */
    fun mayReset(
        buf: PacketBuffer,
        off: Int,
        len: Int,
        decryptBudget: () -> Boolean,
    ): ResetGate

    /** An ID of ours left the endpoint (retired, or its connection removed). */
    fun release(cid: ConnectionId) {}

    /** A server ID for a stateless answer (a Retry's SCID), which nothing may ever release. */
    fun issueStateless(random: Random): ConnectionId = issue(random, client = false).cid

    /** What [cid], one of ours made earlier (a Retry's SCID), allows, when its first octet still tells; null otherwise. */
    fun knownIssuance(cid: ConnectionId): CidIssuance? = CidIssuance.Full

    /** One receive batch went by (a failed nonce reservation store may be tried again). */
    fun tick() {}

    /** A routable ID can be issued now without a store (nonces reserved, or none needed). */
    fun canIssueRoutable(): Boolean = true

    /** [cid] is of the configuration new IDs use (the codepoint new IDs carry). */
    fun isCurrent(cid: ConnectionId): Boolean = true
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

    override fun resetCandidate(
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): Boolean = ownerLoop(buf, off, len) == loopIndex

    override fun mayReset(
        buf: PacketBuffer,
        off: Int,
        len: Int,
        decryptBudget: () -> Boolean,
    ): ResetGate = if (resetCandidate(buf, off, len)) ResetGate.Yes else ResetGate.No

    companion object {
        const val FORMAT_VERSION: Int = 0x01
    }
}

/**
 * The QUIC-LB state of an endpoint, shared by the loops of a group: the configuration new IDs use ([routes]`.current`, null
 * for unroutable IDs), the one before it, still recognised for Stateless Resets, and the SipHash key that spreads IDs over
 * the loops. The loop that owns an ID is `SipHash(key, id) mod loops`: an encrypted ID cannot name its loop in clear, and
 * decrypting it for every datagram would cost up to four AES blocks. The price: a nonce whose ID hashes to another loop
 * cannot serve the loop that drew it. It waits in that loop's pool ([POOL] IDs); past that, the drawing loop issues it
 * itself and records the exception in [exceptions] (at most [MAX_EXCEPTIONS] live IDs, released when the ID leaves; past
 * that, and for a Retry's SCID, which takes none, the nonce is spent unused and counted) ([Entry.issue]).
 *
 * The nonce counters live in the process-wide [QuicLbNonceSpaces] (draft section 9.6: no nonce reuse under one key). Each
 * configuration in use holds its own copy of the configuration key (the caller may close theirs) and the permutation key
 * derived from it; both are freed once the configuration is neither current nor previous and no loop uses it. Keys are made
 * and nonce spaces looked up outside [lock], which guards only the switch of [routes].
 */
internal class QuicLbState(
    private val crypto: QuicCrypto,
    private val random: Random,
    initial: QuicLbConfig?,
    val loops: Int,
    val cidLength: Int,
    /** Test hooks: the pool size per loop and the owner-exception capacity. */
    private val poolSize: Int = POOL,
    maxExceptions: Int = MAX_EXCEPTIONS,
) : AutoCloseable {
    /** One configuration in use: its own key copy, codec, nonce space and (encrypted) the permutation key of its nonces. */
    inner class Entry(
        val config: QuicLbConfig,
    ) {
        private val key: LoadBalancerKey? = config.key?.duplicate()
        val codec = QuicLbCodec(config, key)
        val space: QuicLbNonceSpace
        private val permute: LoadBalancerKey?

        init {
            try {
                space = QuicLbNonceSpaces.of(config, key, crypto, random)
                permute = key?.derive(QuicLbDerivation.label(QuicLbDerivation.PERMUTE, config.nonceLength))
            } catch (e: Throwable) {
                Releaser(e).release { key?.close() }
                throw e
            }
        }

        private val pools = Array(loops) { ArrayDeque<ByteArray>() }
        private val poolLock = SpinLock()
        private val users = AtomicInt(0)
        private val exhaustNoticed = AtomicInt(0)

        /** True the first time any loop finds this configuration's nonces spent. */
        fun firstExhaustion(): Boolean = exhaustNoticed.compareAndSet(0, 1)

        /** Out of current and previous for good: never committed again ([commit] checks it). */
        val retired: Boolean get() = users.load() < 0

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
            val r = Releaser()
            r.release { permute?.close() }
            r.release { key?.close() }
            poolLock.locked { for (p in pools) p.clear() }
            r.finish()
        }

        /**
         * An ID for [loop], from its pool or from new nonces; null when no nonce is to be had ([space] spent, or a reservation
         * not stored). A nonce whose ID hashes to another loop goes to that loop's pool, or, when the pool is full, is issued
         * here with an owner exception ([exceptions]). A [stateless] ID (a Retry's SCID: the client may never come back, so nothing
         * would release an exception) takes no exception: past a full pool its nonce is spent unused ([onWasted]). Between
         * [enter] and [exit].
         */
        fun issue(
            loop: Int,
            stateless: Boolean,
            hashOf: (ByteArray) -> Long,
            onStoreFailed: (Throwable) -> Unit,
            onWasted: () -> Unit,
        ): ByteArray? {
            poolLock.locked { pools[loop].removeFirstOrNull() }?.let { return it }
            while (true) {
                val nonce = space.next(permute, onStoreFailed, loops) ?: return null
                val b = ByteArray(cidLength)
                codec.encode(nonce, b)
                nonce.fill(0)
                val h = hashOf(b)
                val o = ownerOfHash(h)
                if (o == loop) return b
                val pooled =
                    poolLock.locked {
                        if (pools[o].size < poolSize) {
                            pools[o].addLast(b)
                            true
                        } else {
                            false
                        }
                    }
                if (pooled) continue
                if (!stateless && exceptions.add(h, b, loop)) return b
                onWasted() // a Retry's SCID, or the exceptions are full: a live one is never dropped
            }
        }

        /** True when the codec matches our server ID in the ID at `buf[off]`; false once this configuration was freed. */
        fun matches(
            buf: PacketBuffer,
            off: Int,
        ): Boolean {
            if (!enter()) return false
            try {
                return codec.matchesServerId(buf, off)
            } finally {
                exit()
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

    /** IDs issued by another loop than the one they hash to (its pool was full): their real owner. */
    val exceptions = OwnerExceptions(maxExceptions)

    fun hashOf(b: ByteArray): Long = SipHash.hash24(k0, k1, b)

    fun ownerOfHash(h: Long): Int = if (loops == 1) 0 else ((h ushr 1) % loops).toInt()

    fun release(cid: ConnectionId) {
        if (exceptions.size == 0) return
        exceptions.release(hashOf(cid.toByteArray()), cid)
    }

    init {
        if (initial != null) {
            validate(initial)
            routes = Routes(Entry(initial), null)
            history += sidHex(initial) to initial.encrypted
        }
    }

    private fun sidHex(c: QuicLbConfig) = c.serverId.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    /**
     * Throws what [update] would throw for [config], changing nothing: IllegalArgumentException for another connection ID
     * length; for a server ID this endpoint used in clear that is now encrypted, or the other way round (draft section 9.7:
     * "Such deployments MUST use different server ID allocations for the clear text and the encrypted versions"); for a
     * codepoint the current or previous configuration holds with another key, server ID or nonce length (section 3.1: a
     * codepoint names one configuration while its IDs are in use); and for another nonce reservation than its nonce space's.
     */
    fun validate(config: QuicLbConfig?) {
        if (config == null) return
        require(config.connectionIdLength == cidLength) {
            "QuicLbConfig.connectionIdLength (${config.connectionIdLength}) must equal the endpoint's connectionIdLength ($cidLength)"
        }
        val sid = sidHex(config)
        val r = routes
        val seen = lock.locked { history.toList() }
        for ((s, enc) in seen) {
            require(enc == config.encrypted || s != sid) {
                "a server ID used in clear must not be used encrypted, or the other way round (draft-ietf-quic-load-balancers-21 section 9.7)"
            }
        }
        for (e in listOfNotNull(r.current, r.previous)) {
            require(e.config.configId != config.configId || e.config.sameAs(config)) {
                "configId ${config.configId} still names the configuration before it: use another codepoint (draft-ietf-quic-load-balancers-21 section 3.1)"
            }
        }
        QuicLbNonceSpaces.check(config)
    }

    /**
     * New IDs use [config] from now on (null: unroutable IDs); the current configuration becomes the previous one. False when
     * [config] is the current one already (nothing changes). Throws as [validate]. One caller at a time. [prepare] and
     * [commit] split it so the slow part runs off the loops.
     */
    fun update(config: QuicLbConfig?): Boolean {
        repeat(STALE_RETRIES - 1) {
            try {
                return commit(prepare(config))
            } catch (_: StaleConfiguration) {
                // the entry it reused was retired meanwhile: prepare again
            }
        }
        return commit(prepare(config))
    }

    /** [commit] of a [Prepared] whose reused entry was retired after [prepare]: prepare again. */
    class StaleConfiguration : IllegalStateException("the configuration changed meanwhile: prepare again")

    /** A configuration [prepare]d for [commit]: its entry built (a new one, or the current or previous one again). */
    inner class Prepared internal constructor(
        val config: QuicLbConfig?,
        val entry: Entry?,
        val fresh: Boolean,
    )

    /**
     * Validates [config] and builds its entry (key copy, derived key, nonce space and its first stored block), all of which
     * may take time (a reservation's fsync): call it off the loops, then [commit] on the loop. Throws as [validate].
     */
    fun prepare(config: QuicLbConfig?): Prepared {
        check(!lock.locked { closed }) { "the endpoint is closed" }
        validate(config)
        val r = routes
        val reuse =
            when {
                config == null -> null
                r.current?.config?.sameAs(config) == true -> r.current
                r.previous?.config?.sameAs(config) == true -> r.previous
                else -> null
            }
        return if (config == null || reuse != null) Prepared(config, reuse, false) else Prepared(config, Entry(config), true)
    }

    /** Drops a [prepare]d configuration that will not be committed; nothing when it is in use (it was committed after all). */
    fun discard(p: Prepared) {
        if (!p.fresh) return
        val inUse = lock.locked { routes.let { p.entry === it.current || p.entry === it.previous } }
        if (!inUse) p.entry?.retire()
    }

    /**
     * Switches to [p]: false when it is the current configuration already. Throws when the endpoint closed meanwhile, and
     * [StaleConfiguration] when the entry [p] reuses was retired since [prepare] (another change came between).
     */
    fun commit(p: Prepared): Boolean {
        val r = routes
        val next = p.entry
        if ((p.config == null && r.current == null) || (next != null && next === r.current)) {
            discard(p)
            return false
        }
        val previous = r.current ?: r.previous // after a spell of unroutable IDs, the last configuration, whose IDs live on
        val committed =
            lock.locked {
                if (closed) return@locked false
                if (next != null && next.retired) throw StaleConfiguration()
                routes = Routes(next, previous)
                p.config?.let { history += sidHex(it) to it.encrypted }
                true
            }
        if (!committed) {
            discard(p)
            throw IllegalStateException("the endpoint is closed")
        }
        for (old in listOfNotNull(r.current, r.previous)) if (old !== next && old !== previous) old.retire()
        return true
    }

    /** One more owner (an endpoint core of the group); false once closed. */
    fun retain(): Boolean {
        while (true) {
            val n = owners.load()
            if (n == 0) return false
            if (owners.compareAndSet(n, n + 1)) return true
        }
    }

    /** Called once by every owner; the last one frees the keys. */
    override fun close() {
        if (owners.decrementAndFetch() != 0) return
        val r =
            lock.locked {
                closed = true
                routes
            }
        val rel = Releaser()
        for (e in listOfNotNull(r.current, r.previous)) rel.release { e.retire() }
        exceptions.clear()
        rel.finish()
    }

    private companion object {
        const val RETIRED = Int.MIN_VALUE / 2

        /** IDs kept per loop for when it needs one: about 30 KiB per loop. */
        const val POOL = 1024

        /** [update]'s tries when another change retires the entry it prepared. */
        const val STALE_RETRIES = 3

        /** Live IDs issued off their hash: about 4 MiB at most; past that a nonce whose pool is full is spent unused. */
        const val MAX_EXCEPTIONS = 65_536
    }
}

/**
 * QUIC-LB connection IDs (draft-ietf-quic-load-balancers-21 sections 3 to 5, experimental) for loop [loopIndex] of
 * [state]'s endpoint: the current configuration's encoding while it has nonces, else unroutable IDs (first octet
 * `0b111 << 5 | (length - 1)`, the rest random: section 3.2), which client connections of a group use as well.
 * [onExhausted] runs once per configuration, on the loop that first finds its nonces spent; [onStoreFailed] on every failed
 * reservation store. The counters belong to this loop.
 */
internal class QuicLbRoute(
    private val state: QuicLbState,
    private val loopIndex: Int,
    private val onExhausted: () -> Unit = {},
    private val onStoreFailed: (Throwable) -> Unit = {},
) : CidRoute {
    private val length = state.cidLength
    private val loops = state.loops

    /** Nonces this loop drew and spent unused (another loop's pool and the owner exceptions were full). */
    var wasted = 0L
        private set

    private fun owner(b: ByteArray): Int = state.ownerOfHash(state.hashOf(b))

    override fun issue(
        random: Random,
        client: Boolean,
    ): IssuedCid = issue(random, client, stateless = false)

    override fun issueStateless(random: Random): ConnectionId = issue(random, client = false, stateless = true).cid

    private fun issue(
        random: Random,
        client: Boolean,
        stateless: Boolean,
    ): IssuedCid {
        var temporary = false
        if (!client) {
            while (true) {
                val e = state.routes.current ?: break
                if (!e.enter()) {
                    if (state.routes.current === e) break // closed
                    continue // replaced meanwhile: the new one
                }
                try {
                    val b = e.issue(loopIndex, stateless, state::hashOf, onStoreFailed) { wasted++ }
                    if (b != null) return IssuedCid(ConnectionId(b), if (e.config.encrypted) CidIssuance.Full else CidIssuance.Single)
                    if (e.space.exhausted) {
                        if (e.firstExhaustion()) onExhausted()
                    } else {
                        temporary = true // a reservation not stored: this one request only
                    }
                } finally {
                    e.exit()
                }
                break
            }
        }
        val b = ByteArray(length)
        while (true) {
            random.nextBytes(b)
            b[0] = (UNROUTABLE shl 5 or (length - 1)).toByte() // section 3.2: unroutable IDs "MUST self-encode their length"
            if (owner(b) == loopIndex) return IssuedCid(ConnectionId(b), CidIssuance.SingleNoMigration, temporary)
        }
    }

    /**
     * Any ID of our length whose first octet encodes that length, whatever its codepoint: an ID of a configuration two
     * changes back can still be in use (RFC 9000 section 5.1.2: retired IDs are accepted until the peer retires them), and
     * the owner never depends on it. A random 8-byte DCID (a client's first Initial) passes this check one time in 32 and is
     * then forwarded to the loop it hashes to (with every retransmission and 0-RTT packet of that client, consistently):
     * one copy between loops for 1 in 32 new connections times (loops - 1) / loops.
     */
    override fun ownerLoop(
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): Int {
        if (len != length || (buf[off].toInt() and 0x1f) != length - 1) return -1
        if (loops == 1) return 0
        val h = SipHash.hash24(state.k0, state.k1, buf, off, len)
        state.exceptions.ownerOf(h, buf, off, len).let { if (it >= 0) return it }
        return state.ownerOfHash(h)
    }

    override fun resetCandidate(
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): Boolean {
        if (ownerLoop(buf, off, len) != loopIndex) return false
        val cr = (buf[off].toInt() and 0xff) ushr 5
        if (cr == UNROUTABLE) return false // no server ID to check: never answered
        val r = state.routes
        return r.current?.config?.configId == cr || r.previous?.config?.configId == cr
    }

    /** Our server ID once decrypted (up to four AES blocks), within [decryptBudget], under the current or previous configuration. */
    override fun mayReset(
        buf: PacketBuffer,
        off: Int,
        len: Int,
        decryptBudget: () -> Boolean,
    ): ResetGate {
        if (!resetCandidate(buf, off, len)) return ResetGate.No
        val cr = (buf[off].toInt() and 0xff) ushr 5
        val r = state.routes
        val candidates = listOfNotNull(r.current, r.previous).filter { it.config.configId == cr }
        if (candidates.any { it.config.encrypted } && !decryptBudget()) return ResetGate.RateLimited
        for (e in candidates) if (e.matches(buf, off)) return ResetGate.Yes
        return ResetGate.No
    }

    override fun release(cid: ConnectionId) = state.release(cid)

    override fun tick() {
        state.routes.current
            ?.space
            ?.tick(onStoreFailed, state.loops)
    }

    override fun canIssueRoutable(): Boolean =
        state.routes.current
            ?.space
            ?.hasReserved() == true

    override fun isCurrent(cid: ConnectionId): Boolean {
        val cr = (cid[0].toInt() and 0xff) ushr 5
        return cr == (
            state.routes.current
                ?.config
                ?.configId ?: UNROUTABLE
        )
    }

    /** The current or previous configuration's codepoint: Full or Single by its key; 0b111: SingleNoMigration; else null. */
    override fun knownIssuance(cid: ConnectionId): CidIssuance? {
        if (cid.length != length || (cid[0].toInt() and 0x1f) != length - 1) return null
        val cr = (cid[0].toInt() and 0xff) ushr 5
        if (cr == UNROUTABLE) return CidIssuance.SingleNoMigration
        val r = state.routes
        val e = if (r.current?.config?.configId == cr) r.current else r.previous?.takeIf { it.config.configId == cr }
        return e?.let { if (it.config.encrypted) CidIssuance.Full else CidIssuance.Single }
    }

    companion object {
        /** The config rotation codepoint of unroutable IDs (section 3.1: "MUST NOT use the reserved identifier 0b111"). */
        const val UNROUTABLE: Int = 7
    }
}
