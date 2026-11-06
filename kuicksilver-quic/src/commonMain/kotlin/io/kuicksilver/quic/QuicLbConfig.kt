// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi

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
 * The configuration agent of the pool assigns [configId], [serverId], [nonceLength] and [key]; the load balancers must have the
 * same values before the servers issue connection IDs with them (draft section 3.1).
 *
 * @param configId The config rotation codepoint, 0..6 (7 marks unroutable connection IDs and is never a configuration).
 * @param serverId This server's ID, 1..15 bytes; copied.
 * @param nonceLength Nonce bytes, at least 4; [serverId] and the nonce are at most 19 bytes together.
 * @param key The 16-byte AES-128 key, copied (wipe your array afterwards if you like), or null for plaintext connection IDs.
 */
@ExperimentalKuicksilverApi
public class QuicLbConfig(
    public val configId: Int,
    serverId: ByteArray,
    public val nonceLength: Int,
    key: ByteArray?,
) {
    private val sid: ByteArray = serverId.copyOf()

    /** The key bytes; the endpoint copies them into the crypto provider ([io.kuicksilver.tls.QuicCrypto.newLoadBalancerKey]). */
    internal val keyBytes: ByteArray? = key?.copyOf()

    init {
        require(configId in 0..6) { "configId must be 0..6 (0b111 marks unroutable connection IDs), was $configId" }
        require(sid.size >= 1) { "serverId must be at least 1 byte" }
        require(nonceLength >= 4) { "nonceLength must be at least 4, was $nonceLength" }
        require(sid.size + nonceLength <= 19) {
            "serverId (${sid.size}) and nonceLength ($nonceLength) must sum to 19 bytes or less (QUIC v1 connection IDs are at most 20)"
        }
        require(key == null || key.size == 16) { "key must be 16 bytes (AES-128) or null, was ${key?.size}" }
    }

    /** This server's ID (a copy). */
    public val serverId: ByteArray get() = sid.copyOf()

    /** True when the server ID and nonce are encrypted. */
    public val encrypted: Boolean get() = keyBytes != null

    /** The length of every connection ID under this configuration: 1 + server ID + [nonceLength]. */
    public val connectionIdLength: Int get() = 1 + sid.size + nonceLength

    internal val serverIdLength: Int get() = sid.size

    internal fun serverIdAt(i: Int): Byte = sid[i]

    /** The same server ID, nonce length and key: the same nonce space, whose counter must go on rather than start over. */
    internal fun sameNonceSpace(other: QuicLbConfig): Boolean =
        sid.contentEquals(other.sid) && nonceLength == other.nonceLength &&
            (keyBytes?.contentEquals(other.keyBytes ?: return false) ?: (other.keyBytes == null))

    /** Never the key. */
    override fun toString(): String =
        "QuicLbConfig(configId=$configId, serverIdLength=${sid.size}, nonceLength=$nonceLength, encrypted=$encrypted)"
}
