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

/** How many connection IDs a server connection may hand out, by the kind of its first one (draft-ietf-quic-load-balancers-21). */
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
 * The one place that knows the layout of this endpoint's connection IDs: it makes them, tells which loop of a group owns one,
 * and whether an unknown one may be answered with a Stateless Reset. Everything that routes by connection ID asks it, so an
 * in-process dispatcher that hands datagrams of one socket to several loops can call [ownerLoop] as it is.
 *
 * - [ByteRoute]: `[0x01][loop index][random]`, the format without a load balancer.
 * - [QuicLbRoute]: QUIC-LB IDs (draft-ietf-quic-load-balancers-21, experimental) when `QuicEndpointConfig.loadBalancer` is set.
 *
 * One instance per loop. [newCid], [ownerLoop] and [mayReset] keep no state of their own (a QUIC-LB route reads the shared
 * [QuicLbState]), so [ownerLoop] may also be asked from a thread that is not the loop's.
 */
internal sealed interface CidRoute {
    /** A new connection ID of ours: for a server connection, or with [client] for a client connection of a loop group. */
    fun newCid(
        random: Random,
        client: Boolean,
    ): ConnectionId

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

    /** How many IDs a server connection whose handshake ID is [cid] hands out. */
    fun issuance(cid: ConnectionId): CidIssuance
}

/**
 * Server connection IDs `[format version 0x01][routing byte = loop index][random]`. In a loop group the client connections'
 * IDs take this format too, so the answers of their peers reach the loop that connected.
 */
internal class ByteRoute(
    private val loopIndex: Int,
    private val length: Int,
) : CidRoute {
    override fun newCid(
        random: Random,
        client: Boolean,
    ): ConnectionId {
        val b = ByteArray(length)
        random.nextBytes(b)
        b[0] = FORMAT_VERSION.toByte()
        b[1] = loopIndex.toByte()
        return ConnectionId(b)
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

    override fun issuance(cid: ConnectionId): CidIssuance = CidIssuance.Full

    companion object {
        const val FORMAT_VERSION: Int = 0x01
    }
}

/**
 * The QUIC-LB state of an endpoint, shared by the loops of a group: the configuration new IDs use ([routes]`.current`, null
 * for unroutable IDs), the one before it, still recognised for owner and reset, and the SipHash key that spreads IDs over the
 * loops. The loop that owns an ID is `SipHash(key, id) mod loops`: an encrypted ID cannot name its loop in clear, and
 * decrypting it for every datagram would cost up to four AES blocks, so each loop keeps only the IDs that hash to it
 * ([QuicLbRoute.newCid] draws until one does).
 *
 * Every configuration's keys stay until the last owner closes ([retain]/[close]): another loop may be encrypting with one
 * when it is replaced. So do the nonce counters, by nonce space: a configuration that comes back with the same server ID,
 * nonce length and key goes on with its counter instead of starting over (draft section 9.6: no nonce reuse under one key).
 * [update] is called by one caller at a time; [routes] is read from any loop.
 */
internal class QuicLbState(
    private val crypto: QuicCrypto,
    private val random: Random,
    initial: QuicLbConfig?,
    val loops: Int,
    val cidLength: Int,
) : AutoCloseable {
    class Entry(
        val config: QuicLbConfig,
        val codec: QuicLbCodec,
        val nonces: QuicLbNonces,
    )

    /** The configuration new IDs use (null: unroutable, codepoint 0b111) and the one replaced last (also null when none). */
    class Routes(
        val current: Entry?,
        val previous: Entry?,
    )

    val k0: Long = random.nextLong()
    val k1: Long = random.nextLong()

    @Volatile var routes: Routes = Routes(null, null)
        private set

    private val owners = AtomicInt(1)
    private val spaces = ArrayList<Entry>()
    private val keys = ArrayList<LoadBalancerKey>()
    private var closed = false

    init {
        try {
            if (initial != null) routes = Routes(entryFor(initial), null)
        } catch (e: Throwable) {
            freeKeys(Releaser(e))
            throw e
        }
    }

    /**
     * New IDs use [config] from now on (null: unroutable IDs); the current configuration becomes the previous one. Throws
     * IllegalArgumentException for a configuration of another connection ID length, or one that would use a server ID in
     * clear that an encrypted configuration of this endpoint used, or the other way round (draft section 9.7: "Such deployments MUST use
     * different server ID allocations for the clear text and the encrypted versions").
     */
    fun update(config: QuicLbConfig?) {
        check(!closed) { "the endpoint is closed" }
        val now = routes
        if (config != null) {
            require(config.connectionIdLength == cidLength) {
                "QuicLbConfig.connectionIdLength (${config.connectionIdLength}) must equal the endpoint's connectionIdLength ($cidLength)"
            }
            for (e in spaces) { // every configuration this endpoint used, not only the last two
                require(e.config.encrypted == config.encrypted || !e.config.serverId.contentEquals(config.serverId)) {
                    "a server ID used in clear must not be used encrypted, or the other way round (draft-ietf-quic-load-balancers-21 section 9.7)"
                }
            }
        }
        val entry = config?.let { entryFor(it) }
        // the one replaced; after a spell of unroutable IDs, the last configuration, whose IDs the connections still use
        routes = Routes(entry, now.current ?: now.previous)
    }

    private fun entryFor(config: QuicLbConfig): Entry {
        for (e in spaces) {
            if (e.config.sameNonceSpace(config)) {
                return if (e.config.configId == config.configId) e else Entry(config, QuicLbCodec(config, e.codec.key), e.nonces)
            }
        }
        val key = config.keyBytes?.let { crypto.newLoadBalancerKey(it.copyOf()).also { k -> keys += k } }
        val permute = crypto.newLoadBalancerKey(null).also { keys += it }
        val seed = ByteArray(config.nonceLength).also { random.nextBytes(it) }
        return Entry(config, QuicLbCodec(config, key), QuicLbNonces(config.nonceLength, seed, permute)).also { spaces += it }
    }

    /** One more owner (an endpoint core of the group); false once the keys are freed. */
    fun retain(): Boolean {
        while (true) {
            val n = owners.load()
            if (n == 0) return false
            if (owners.compareAndSet(n, n + 1)) return true
        }
    }

    /** Called once by every owner; the last one frees every key. */
    override fun close() {
        if (owners.decrementAndFetch() != 0) return
        val r = Releaser()
        freeKeys(r)
        r.finish()
    }

    private fun freeKeys(r: Releaser) {
        closed = true
        for (k in keys) r.release { k.close() }
        keys.clear()
        spaces.clear()
    }
}

/**
 * QUIC-LB connection IDs (draft-ietf-quic-load-balancers-21 sections 3 to 5, experimental) for loop [loopIndex] of
 * [state]'s endpoint: the current configuration's encoding while it has nonces, else unroutable IDs (first octet
 * `0b111 << 5 | (length - 1)`, the rest random: section 3.2), which client connections of a group use as well.
 */
internal class QuicLbRoute(
    private val state: QuicLbState,
    private val loopIndex: Int,
) : CidRoute {
    private val length = state.cidLength
    private val loops = state.loops

    private fun owner(b: ByteArray): Int = if (loops == 1) 0 else ((SipHash.hash24(state.k0, state.k1, b) ushr 1) % loops).toInt()

    override fun newCid(
        random: Random,
        client: Boolean,
    ): ConnectionId {
        val entry = if (client) null else state.routes.current
        val b = ByteArray(length)
        if (entry != null) {
            while (true) {
                // a nonce whose ID hashes to another loop is dropped: no loop ever issues it, so none repeats across the group
                val nonce = entry.nonces.next() ?: break // spent: unroutable from now on (section 9.6)
                entry.codec.encode(nonce, b)
                nonce.fill(0)
                if (owner(b) == loopIndex) return ConnectionId(b)
            }
        }
        while (true) {
            random.nextBytes(b)
            b[0] = (UNROUTABLE shl 5 or (length - 1)).toByte() // section 3.2: unroutable IDs "MUST self-encode their length"
            if (owner(b) == loopIndex) return ConnectionId(b)
        }
    }

    /** Our length, a self-encoded length that matches it, and a codepoint of ours: the current or previous one, or 0b111. */
    private fun ours(
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): Boolean {
        if (len != length) return false
        val first = buf[off].toInt() and 0xff
        if (first and 0x1f != length - 1) return false
        val cr = first ushr 5
        if (cr == UNROUTABLE) return true
        val r = state.routes
        return r.current?.config?.configId == cr || r.previous?.config?.configId == cr
    }

    override fun ownerLoop(
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): Int {
        if (!ours(buf, off, len)) return -1
        return if (loops == 1) 0 else ((SipHash.hash24(state.k0, state.k1, buf, off, len) ushr 1) % loops).toInt()
    }

    /**
     * Only for an ID this loop could have issued under the current or previous configuration: its codepoint, our server ID
     * once decrypted, and a hash that names this loop. Never for an unroutable ID, which carries no server ID to check.
     */
    override fun mayReset(
        buf: PacketBuffer,
        off: Int,
        len: Int,
    ): Boolean {
        if (len != length) return false
        val cr = (buf[off].toInt() and 0xff) ushr 5
        if (cr == UNROUTABLE || ownerLoop(buf, off, len) != loopIndex) return false
        val r = state.routes
        for (e in arrayOf(r.current, r.previous)) {
            if (e != null && e.config.configId == cr && e.codec.matchesServerId(buf, off)) return true
        }
        return false
    }

    override fun issuance(cid: ConnectionId): CidIssuance {
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
