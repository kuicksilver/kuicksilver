// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.tls.LoadBalancerKey

/**
 * A QUIC-LB configuration (draft-ietf-quic-load-balancers-21, experimental: the draft is not an RFC yet and may change): the
 * server connection IDs this endpoint issues carry [serverId], so a QUIC-LB load balancer in front of a pool of servers routes
 * every packet of a connection to the server that holds it, also after the client's address changed (docs/guide/quic.md,
 * "Behind a load balancer").
 *
 * A connection ID is `first octet || server ID || nonce`, [connectionIdLength] = 1 + server ID + [nonceLength] bytes, which
 * must equal `QuicEndpointConfig.connectionIdLength`. The first octet holds [configId] in its three high bits and the length
 * of the rest in its five low bits (draft section 3: config rotation, length self-description). With a [key] the server ID
 * and nonce are encrypted with AES-128 (one pass when they are 16 bytes together, else a four-pass Feistel network, draft
 * section 5.4), so only the load balancer can read the server ID; without one they travel in clear and anyone can tell which
 * server a connection is on.
 *
 * The configuration agent of the pool assigns [configId], [serverId], [nonceLength] and the key; the load balancers must have
 * the same values before the servers issue connection IDs with them (draft section 3.1).
 *
 * @param configId The config rotation codepoint, 0..6 (7 marks unroutable connection IDs and is never a configuration).
 * @param serverId This server's ID, 1..15 bytes; copied.
 * @param nonceLength Nonce bytes, at least 4; [serverId] and the nonce are at most 19 bytes together.
 * @param key The AES-128 key, made with `QuicCrypto.newLoadBalancerKey(bytes)` (which wipes `bytes`; the key material then
 * lives in the native layer only), or null for plaintext connection IDs. The caller owns it: keep it open while any endpoint
 * that was given this configuration runs. Draft section 9.6: "the server MUST NOT reuse a nonce until it switches to a
 * configuration with new keys". Within a process no nonce of a key and nonce length is ever used twice, whatever the
 * endpoints and server IDs that share them. Across processes that holds only with [nonceReservation]; without one, each
 * process that uses this key must get a key no earlier process used (a fresh key per process start, per instance).
 * @param nonceReservation Where the nonce counter of this key and nonce length survives a restart (needs a [key]); see
 * [QuicLbNonceReservation]. Null: nonces start at a random point in each process.
 */
@ExperimentalKuicksilverApi
public class QuicLbConfig(
    public val configId: Int,
    serverId: ByteArray,
    public val nonceLength: Int,
    public val key: LoadBalancerKey?,
    public val nonceReservation: QuicLbNonceReservation? = null,
) {
    private val sid: ByteArray = serverId.copyOf()

    init {
        require(configId in 0..6) { "configId must be 0..6 (0b111 marks unroutable connection IDs), was $configId" }
        require(sid.size >= 1) { "serverId must be at least 1 byte" }
        require(nonceLength >= 4) { "nonceLength must be at least 4, was $nonceLength" }
        require(sid.size + nonceLength <= 19) {
            "serverId (${sid.size}) and nonceLength ($nonceLength) must sum to 19 bytes or less (QUIC v1 connection IDs are at most 20)"
        }
        require(
            nonceReservation == null || key != null,
        ) { "a nonceReservation needs a key: plaintext nonces are permuted with a per-process key" }
    }

    /**
     * A keyed fingerprint of [key] (its encryption of a block no connection ID or Feistel pass ever encrypts), never the key:
     * configurations with the same key share one nonce space. Null without a key.
     */
    internal val keyFingerprint: String? =
        key?.let { k ->
            val b =
                io.kuicksilver.quic.endpoint.QuicLbDerivation
                    .label(io.kuicksilver.quic.endpoint.QuicLbDerivation.FINGERPRINT, 0)
            k.encrypt(b, 0, b, 0)
            b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
        }

    /** This server's ID (a copy). */
    public val serverId: ByteArray get() = sid.copyOf()

    /** True when the server ID and nonce are encrypted. */
    public val encrypted: Boolean get() = key != null

    /** The length of every connection ID under this configuration: 1 + server ID + [nonceLength]. */
    public val connectionIdLength: Int get() = 1 + sid.size + nonceLength

    internal val serverIdLength: Int get() = sid.size

    internal fun serverIdAt(i: Int): Byte = sid[i]

    /** The same codepoint, server ID, nonce length and key: one configuration given twice. */
    internal fun sameAs(other: QuicLbConfig): Boolean =
        configId == other.configId && sid.contentEquals(other.sid) && nonceLength == other.nonceLength &&
            keyFingerprint == other.keyFingerprint

    /** Never the key. */
    override fun toString(): String =
        "QuicLbConfig(configId=$configId, serverIdLength=${sid.size}, nonceLength=$nonceLength, encrypted=$encrypted)"
}

/**
 * Keeps the nonce counter of one QUIC-LB key and nonce length across process restarts, so no restart reuses a nonce under
 * that key (draft-ietf-quic-load-balancers-21 section 9.6). With it, the nonce sequence of a key is fixed (derived from the
 * key), and the endpoint reserves nonces in blocks of [BLOCK]: before it uses a nonce at or past the stored mark it calls
 * [store] with the end of the next block, and a new process starts at [load]. A crash skips the rest of a block, never
 * reuses one. Every process that uses the key must share the store (one file per key, say), and only one process may use
 * it at a time.
 */
@ExperimentalKuicksilverApi
public interface QuicLbNonceReservation {
    /** The mark stored last, or 0 when none: nonces below it may be in use already. Called once per process and nonce space. */
    public fun load(): Long

    /**
     * Stores [mark] durably before returning (an fsync'd file, say): nonces below it are about to be used. Called on an
     * endpoint loop's thread, once per [BLOCK] nonces. A throw leaves the endpoint issuing unroutable IDs until a later call
     * succeeds.
     */
    public fun store(mark: Long)

    public companion object {
        /** Nonces reserved per [store]. */
        public const val BLOCK: Long = 65_536
    }
}
