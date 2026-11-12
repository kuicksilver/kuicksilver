// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.kuicksilver.ktor.network.AddressResolution
import io.kuicksilver.ktor.network.DestinationSort
import io.kuicksilver.ktor.network.SourceInfo
import io.kuicksilver.ktor.network.SystemResolution
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.ktor.network.defaultOrder
import io.kuicksilver.ktor.network.parseIpv4Literal
import io.kuicksilver.ktor.network.resolveBoth
import io.kuicksilver.ktor.network.resolveFamily
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * The name resolution of one request: each family of each host is looked up once ([AddressResolution.addresses], RFC 8305
 * section 3: AAAA and A separately) and its answer, or its failure, reused for the rest of the request, so the two sides of
 * the h3/h1 race (and a fallback after it) race what one lookup of each family returned, and a name that does not resolve
 * is not asked again. Different names, and the two families of a name, are looked up in parallel. A lookup runs in the
 * coroutine that asked first; a caller cancelled while it runs leaves no answer behind, and a caller waiting for the same
 * answer then looks it up itself.
 *
 * On an IPv6-only network with NAT64 ([Nat64], RFC 8305 section 7) the IPv4 answers, and an IPv4 literal, are handed out as
 * IPv6 addresses synthesized with the network's prefixes, and the race asks for IPv4 only when it needs to.
 */
internal class RequestDns private constructor(
    /** One family (true: IPv6) of a host name, port 0: empty for none, an exception for a failed lookup. */
    private val resolveFamily: suspend (String, Boolean) -> List<TcpAddress>,
    private val nat64: Nat64,
    private val newSort: () -> DestinationSort,
    private val lock: Mutex,
    private val answers: HashMap<Pair<String, Boolean>, CompletableDeferred<Result<List<TcpAddress>>>>,
    /** Every lookup goes to this host and port instead (an HTTPS record's endpoint, [connectTo]). */
    private val endpoint: Pair<String, Int>?,
) {
    constructor(
        nat64: Nat64 = Nat64.system,
        newSort: () -> DestinationSort = { DestinationSort() },
        resolveFamily: suspend (String, Boolean) -> List<TcpAddress> = ::resolveFamily,
    ) : this(resolveFamily, nat64, newSort, Mutex(), HashMap(), null)

    /** The lock over the answers (tests). */
    internal val lockForTest: Mutex get() = lock

    /**
     * A view of this resolution whose every lookup resolves [host] and answers with [port]: the TCP side of a connection to
     * an endpoint of the origin's HTTPS records (RFC 9460 section 3: the client resolves the TargetName and uses the
     * endpoint's port; TLS and the request still name the origin). It shares the answers, so a name is still asked once.
     */
    fun connectTo(
        host: String,
        port: Int,
    ): RequestDns = RequestDns(resolveFamily, nat64, newSort, lock, answers, host to port)

    /**
     * Takes [addresses] (4 or 16 bytes each), the A/AAAA records an HTTPS answer carried, for [host]: RFC 9460 section 5,
     * they "SHOULD be placed in cache before performing any follow-up queries". Each family they hold is that family's
     * answer, unless it was looked up already; a family they do not hold is still looked up (the answer may have left it
     * out, section 5.2, and section 3 has the client resolve "AAAA and/or A records"), and the race takes its addresses as
     * they come, as any other answer (RFC 8305 section 3).
     */
    suspend fun seed(
        host: String,
        addresses: List<ByteArray>,
    ) {
        if (addresses.isEmpty()) return
        val list = addresses.map { TcpAddress(it, 0) }
        val name = socketHost(host)
        lock.withLock {
            for (v6 in listOf(true, false)) {
                val family = list.filter { it.isIpv6 == v6 }
                if (family.isNotEmpty()) answers.getOrPut(name to v6) { CompletableDeferred(Result.success(family)) }
            }
        }
    }

    /**
     * The resolution of [host] for [port] for a race ([io.kuicksilver.ktor.network.raceAddresses]): a literal answers its
     * own family at once; a name one family at a time through this request's answers. On an IPv6-only network with NAT64
     * the IPv4 addresses come back synthesized (RFC 8305 section 7.1 for a literal: "The synthesized addresses are then
     * inserted into the list of addresses as if they were results from DNS queries").
     */
    suspend fun resolution(
        host: String,
        port: Int,
    ): AddressResolution {
        if (endpoint != null) return root().resolution(endpoint.first, endpoint.second)
        val name = socketHost(host)
        val prefixes = nat64.prefixes()
        // an address literal is never looked up
        val literal = if (':' in name || parseIpv4Literal(name) != null) SystemResolution(name, port) else null
        return object : AddressResolution {
            override val ipv6Only: Boolean = prefixes.isNotEmpty()

            override suspend fun addresses(ipv6: Boolean): List<TcpAddress> {
                if (literal != null) {
                    if (prefixes.isEmpty()) return literal.addresses(ipv6)
                    // section 7.1: an IPv4 literal on an IPv6-only network, synthesized as the IPv6 answer
                    if (!ipv6) return emptyList()
                    return literal.addresses(true) + literal.addresses(false).flatMap { nat64.synthesize(it.bytes, prefixes, port) }
                }
                val found = family(name, ipv6)
                if (!ipv6 && prefixes.isNotEmpty()) return found.flatMap { nat64.synthesize(it.bytes, prefixes, port) }
                return found.map { it.withPort(port) }
            }
        }
    }

    /** A sort and interleave of RFC 8305 section 4 for one race: an RFC 6724 sort of its own ([DestinationSort]). */
    fun order(): (List<TcpAddress>) -> List<TcpAddress> = defaultOrder(newSort())

    /**
     * Every address of [host] with [port], both families as this request resolves them (no NAT64 synthesis: these name the
     * host, as a WebSocket key or a SOCKS5 target), sorted by RFC 6724 section 6 unless [sorted] is false: a SOCKS5 proxy
     * connects to them over its own routes, so this host's say nothing about their order there, and the resolver's order
     * is kept. [host] is a URL host, an IPv6 literal with or without its brackets.
     */
    suspend fun lookup(
        host: String,
        port: Int,
        sorted: Boolean = true,
    ): List<TcpAddress> {
        if (endpoint != null) return root().lookup(endpoint.first, endpoint.second, sorted)
        val name = socketHost(host)
        val plain =
            if (':' in name || parseIpv4Literal(name) != null) {
                SystemResolution(name, port)
            } else {
                object : AddressResolution {
                    override suspend fun addresses(ipv6: Boolean): List<TcpAddress> = family(name, ipv6).map { it.withPort(port) }
                }
            }
        val found = resolveBoth(plain, name)
        return if (sorted) newSort().sort(found) else found
    }

    private fun root(): RequestDns = RequestDns(resolveFamily, nat64, newSort, lock, answers, null)

    /** One family of [name] (port 0) from this request's answers, looked up by the first caller that needs it. */
    private suspend fun family(
        name: String,
        ipv6: Boolean,
    ): List<TcpAddress> {
        val key = name to ipv6
        while (true) {
            var mine = false
            val pending =
                lock.withLock {
                    // a cancelled entry is one whose looker-up went away: replace it, so no waiter spins on it
                    answers[key]?.takeUnless { it.isCancelled } ?: CompletableDeferred<Result<List<TcpAddress>>>().also {
                        mine = true
                        answers[key] = it
                    }
                }
            if (mine) {
                val result =
                    try {
                        Result.success(resolveFamily(name, ipv6))
                    } catch (e: CancellationException) {
                        // this caller goes: no answer is left behind, and a caller waiting for it asks again. Cancel first,
                        // then remove without being cancellable: a busy lock must not leave the entry behind
                        pending.cancel()
                        withContext(NonCancellable) { lock.withLock { if (answers[key] === pending) answers.remove(key) } }
                        throw e
                    } catch (e: Throwable) {
                        Result.failure(e)
                    }
                pending.complete(result)
            }
            val found =
                try {
                    pending.await()
                } catch (e: CancellationException) {
                    currentCoroutineContext().ensureActive() // our own cancellation; else the looker-up was cancelled
                    continue
                }
            return found.getOrThrow()
        }
    }

    companion object {
        /**
         * Tests with a resolver of their own: a dual-stack host whatever the machine has (every destination is its own
         * source, so RFC 6724 orders by precedence: IPv6 first), never an IPv6-only network.
         */
        fun dualStackSortForTest(): DestinationSort = DestinationSort(sourceFor = { it }, sourceInfo = { SourceInfo(it) })
    }
}

/**
 * A fresh [RequestDns] with this configuration's resolver: the system's, or a test's. A test resolver of both families
 * ([KuicksilverEngineConfig.resolverForTest]) is asked once per name, and its answer split by family.
 */
internal fun KuicksilverEngineConfig.newRequestDns(): RequestDns {
    familyResolverForTest?.let { return RequestDns(nat64ForTest ?: Nat64.offForTest(), { RequestDns.dualStackSortForTest() }, it) }
    val both = resolverForTest ?: return RequestDns()
    val lock = Mutex()
    val once = HashMap<String, CompletableDeferred<Result<List<TcpAddress>>>>()
    return RequestDns(nat64ForTest ?: Nat64.offForTest(), { RequestDns.dualStackSortForTest() }) { name, ipv6 ->
        var answer: Result<List<TcpAddress>>? = null
        while (answer == null) {
            var mine = false
            val d =
                lock.withLock {
                    once[name]?.takeUnless { it.isCancelled } ?: CompletableDeferred<Result<List<TcpAddress>>>().also {
                        mine = true
                        once[name] = it
                    }
                }
            if (mine) {
                d.complete(
                    try {
                        Result.success(both(name, 0))
                    } catch (e: CancellationException) {
                        d.cancel()
                        throw e
                    } catch (e: Throwable) {
                        Result.failure(e)
                    },
                )
            }
            answer =
                try {
                    d.await()
                } catch (e: CancellationException) {
                    currentCoroutineContext().ensureActive() // the caller that asked went away: ask again
                    null
                }
        }
        answer.getOrThrow().filter { it.isIpv6 == ipv6 }
    }
}
