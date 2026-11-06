// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.ktor.network.resolveTcp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The name resolution of one request: each host is looked up once and its answer, or its failure, reused for the rest of
 * the request, so the two sides of the h3/h1 race (and a fallback after it) connect to what one lookup returned and a
 * name that does not resolve is not asked again. A lookup runs under the caller's deadline; a caller cancelled while it
 * runs leaves no answer behind, and the next caller looks the name up itself.
 */
internal class RequestDns private constructor(
    private val resolve: suspend (String, Int) -> List<TcpAddress>,
    private val lock: Mutex,
    private val answers: HashMap<String, Result<List<TcpAddress>>>,
    /** Every lookup goes to this host and port instead (an HTTPS record's endpoint, [connectTo]). */
    private val endpoint: Pair<String, Int>?,
) {
    constructor(resolve: suspend (String, Int) -> List<TcpAddress>) : this(resolve, Mutex(), HashMap(), null)

    /**
     * A view of this resolution whose every lookup resolves [host] and answers with [port]: the TCP side of a connection to
     * an endpoint of the origin's HTTPS records (RFC 9460 section 3: the client resolves the TargetName and uses the
     * endpoint's port; TLS and the request still name the origin). It shares the answers, so a name is still asked once.
     */
    fun connectTo(
        host: String,
        port: Int,
    ): RequestDns = RequestDns(resolve, lock, answers, host to port)

    /**
     * Takes [addresses] (4 or 16 bytes each) as the answer for [host] unless it was looked up already: the A/AAAA records
     * an HTTPS answer carried, used instead of a follow-up query (RFC 9460 section 5).
     */
    suspend fun seed(
        host: String,
        addresses: List<ByteArray>,
    ) {
        if (addresses.isEmpty()) return
        lock.withLock { answers.getOrPut(socketHost(host)) { Result.success(addresses.map { TcpAddress(it, 0) }) } }
    }

    /** The addresses of [host] with [port]; [host] is a URL host, an IPv6 literal with or without its brackets. */
    suspend fun lookup(
        host: String,
        port: Int,
    ): List<TcpAddress> {
        if (endpoint != null) return RequestDns(resolve, lock, answers, null).lookup(endpoint.first, endpoint.second)
        val name = socketHost(host)
        val found =
            lock.withLock {
                answers[name] ?: try {
                    Result.success(resolve(name, port))
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    Result.failure(e)
                }.also { answers[name] = it }
            }
        return found.getOrThrow().map { it.withPort(port) }
    }
}

/** A fresh [RequestDns] with this configuration's resolver. */
internal fun KuicksilverEngineConfig.newRequestDns(): RequestDns = RequestDns(resolverForTest ?: ::resolveTcp)
