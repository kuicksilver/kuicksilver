// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Where a client keeps the address-validation tokens servers send in NEW_TOKEN frames (RFC 9000 section 8.1.3), so that
 * its next connection to the same server skips the Retry round trip and the server's anti-amplification limit
 * (`QuicClientConfig.Builder.tokenStore`; off by default).
 *
 * **Privacy.** A token is an identifier the server issued to this client: presenting it on a later connection tells the
 * server that both connections come from the same client, even from another network (RFC 9000 section 8.1.3 lets a
 * client trade that linkability for the saved round trip). Keep a store only where the server may link connections
 * anyway (a logged-in app talking to its own backend); a store that outlives a network change or a user switch links
 * them too.
 *
 * The endpoint calls [take] before each connection to the server named by the key, in the coroutine that calls `connect`,
 * and uses what it gets once; it calls [put] on the endpoint loop for each token the server sends (at most eight per
 * connection, each at most 1024 bytes). Neither should block: a call that has not finished after 250 ms is cancelled
 * and the connection goes on without the token (logged once per endpoint loop), so `connect` never waits longer for the
 * store. An exception from either is logged and the connection goes on without a token. Keys are
 * `"<server name>:<port>"`, or `"<IP literal>:<port>"` without a server name (an IPv6 literal in brackets), so a token is
 * never sent to another server name on the same address (RFC 9000 section 8.1.3: "MUST NOT include a token that is not
 * applicable to the server").
 */
@ExperimentalKuicksilverApi
public interface QuicTokenStore {
    /** Keeps [token] for the server named by [key]; a store may drop older ones (it should keep the newest). */
    public suspend fun put(
        key: String,
        token: ByteArray,
    )

    /** Removes and returns a token for [key] (the newest first), or null: a token is used once (RFC 9000 section 8.1.3). */
    public suspend fun take(key: String): ByteArray?
}

/**
 * A [QuicTokenStore] in memory, bounded to [maxServers] keys of [tokensPerServer] tokens each: the newest token is taken
 * first, the oldest one beyond [tokensPerServer] is dropped, and the server not used for longest is evicted beyond
 * [maxServers] (as quic-go's `NewLRUTokenStore`). Safe to share between endpoints; its contents end with the process.
 */
@ExperimentalKuicksilverApi
public class MemoryTokenStore(
    /** Servers (keys) kept at most, at least 1. */
    public val maxServers: Int = 256,
    /** Tokens kept per server at most, at least 1. */
    public val tokensPerServer: Int = 4,
) : QuicTokenStore {
    init {
        require(maxServers >= 1) { "maxServers must be positive" }
        require(tokensPerServer >= 1) { "tokensPerServer must be positive" }
    }

    private val lock = Mutex()

    // insertion order is recency: a key used again is removed and put back at the end
    private val servers = LinkedHashMap<String, ArrayDeque<ByteArray>>()

    override suspend fun put(
        key: String,
        token: ByteArray,
    ) {
        if (token.isEmpty() || token.size > MAX_TOKEN) return
        val copy = token.copyOf()
        lock.withLock {
            val tokens = servers.remove(key) ?: ArrayDeque()
            tokens.addFirst(copy)
            while (tokens.size > tokensPerServer) tokens.removeLast()
            servers[key] = tokens
            while (servers.size > maxServers) servers.remove(servers.keys.first())
        }
    }

    override suspend fun take(key: String): ByteArray? =
        lock.withLock {
            val tokens = servers.remove(key) ?: return@withLock null
            val token = tokens.removeFirst()
            if (tokens.isNotEmpty()) servers[key] = tokens
            token
        }

    override fun toString(): String = "MemoryTokenStore(maxServers=$maxServers, tokensPerServer=$tokensPerServer)"

    private companion object {
        const val MAX_TOKEN = 1024
    }
}

/** The [QuicTokenStore] key of a connection to [remote] (an IP literal) with SNI [serverName]. */
@OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
internal fun tokenStoreKey(
    serverName: String?,
    remote: InetSocketAddress,
): String {
    if (serverName != null) return "$serverName:${remote.port}"
    val ip = remote.ipLiteral()
    return if (':' in ip) "[$ip]:${remote.port}" else "$ip:${remote.port}"
}
