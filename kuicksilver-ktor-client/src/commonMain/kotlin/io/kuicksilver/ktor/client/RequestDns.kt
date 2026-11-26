// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.client

import io.kuicksilver.ktor.network.AddressResolution
import io.kuicksilver.ktor.network.DestinationSort
import io.kuicksilver.ktor.network.RESOLUTION_DELAY
import io.kuicksilver.ktor.network.SourceInfo
import io.kuicksilver.ktor.network.SystemResolution
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.ktor.network.defaultOrder
import io.kuicksilver.ktor.network.parseIpv4Literal
import io.kuicksilver.ktor.network.resolveBoth
import io.kuicksilver.ktor.network.resolveFamily
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.onTimeout
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

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
@OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
internal class RequestDns private constructor(
    /** One family (true: IPv6) of a host name, port 0: empty for none, an exception for a failed lookup. */
    private val resolveFamily: suspend (String, Boolean) -> List<TcpAddress>,
    private val nat64: Nat64,
    private val newSort: () -> DestinationSort,
    private val lock: Mutex,
    private val answers: HashMap<Pair<String, Boolean>, CompletableDeferred<Result<List<TcpAddress>>>>,
    /** Every lookup goes to this host and port instead (an HTTPS record's endpoint, [connectTo]). */
    private val endpoint: Pair<String, Int>?,
    /** The request's DNS events of each lookup of one family ([resolveFamily] reports a lookup of both itself); null: none. */
    private val familyEvents: DnsObserver?,
    /** The ECH offer of connections made through this view: an HTTPS record endpoint's ([connectTo]); null: the origin's. */
    private val echOfEndpoint: EchRoute?,
    /** The ECH routes of the request's origins (by host), shared by every view. */
    private val echRoutes: kotlin.concurrent.atomics.AtomicReference<Map<String, EchRoute>>,
) {
    constructor(
        nat64: Nat64 = Nat64.system,
        newSort: () -> DestinationSort = { DestinationSort() },
        familyEvents: DnsObserver? = null,
        resolveFamily: suspend (String, Boolean) -> List<TcpAddress> = ::resolveFamily,
    ) : this(
        resolveFamily,
        nat64,
        newSort,
        Mutex(),
        HashMap(),
        null,
        familyEvents,
        null,
        kotlin.concurrent.atomics.AtomicReference(emptyMap()),
    )

    /** Whether this is the system's resolution ([Dns.System]), made as before the application resolver existed (tests). */
    internal var isSystemForTest: Boolean = false

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
        // the endpoint's ECH (RFC 9848), shared with the QUIC side of the same endpoint; null: the origin's
        ech: EchRoute? = null,
    ): RequestDns = RequestDns(resolveFamily, nat64, newSort, lock, answers, host to port, familyEvents, ech, echRoutes)

    /**
     * The ECH route of a connection through this view for [originHost]: the endpoint's ([connectTo]), else the one of the
     * request for that origin, made once from [initial] (the configured list of the host) and shared by the request's
     * connections, so the request retries after a rejection once (RFC 9849 section 6.1.6, [EchRoute]).
     */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class, io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    fun echRoute(
        originHost: String,
        initial: (String) -> io.kuicksilver.tls.EchConfigList?,
    ): EchRoute {
        echOfEndpoint?.let { return it }
        while (true) {
            val m = echRoutes.load()
            m[originHost]?.let { return it }
            val r = EchRoute(initial(originHost))
            if (echRoutes.compareAndSet(m, m + (originHost to r))) return r
        }
    }

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
        val list = addresses.map { TcpAddress(it, 0) }.filter(::usableAsDestination)
        if (list.isEmpty()) return
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
     * own family at once; a name one family at a time through this request's answers. On an IPv6-only network ([Nat64])
     * an IPv4 address the host has no route to comes back synthesized (RFC 8305 section 7.1 for a literal: "The
     * synthesized addresses are then inserted into the list of addresses as if they were results from DNS queries"), and
     * the race asks for IPv4 only when it needs to; nothing here waits for the NAT64 prefix unless an address needs it.
     */
    suspend fun resolution(
        host: String,
        port: Int,
    ): AddressResolution {
        if (endpoint != null) return root().resolution(endpoint.first, endpoint.second)
        val name = socketHost(host)
        val ipv6Only = nat64.ipv6OnlyNetwork()
        // an address literal is never looked up, and one no connection may go to fails here
        val literal = if (':' in name || parseIpv4Literal(name) != null) checkedLiteral(name, port) else null
        return object : AddressResolution {
            override val ipv6Only: Boolean = ipv6Only
            private var literalSynthesized: List<TcpAddress>? = null

            override suspend fun addresses(ipv6: Boolean): List<TcpAddress> {
                if (literal != null) {
                    if (!ipv6Only) return literal.addresses(ipv6)
                    // section 7.1: an IPv4 literal with no IPv4 route, synthesized as the IPv6 answer; one the host routes
                    // (a loopback or LAN address) stays the IPv4 answer
                    val v4 = literal.addresses(false).singleOrNull()
                    val synthesized =
                        literalSynthesized ?: (v4?.let { a -> nat64.synthesize(a.bytes, port).filter { it.isIpv6 } }.orEmpty())
                            .also { literalSynthesized = it }
                    return if (ipv6) {
                        literal.addresses(true) + synthesized
                    } else if (synthesized.isEmpty()) {
                        literal.addresses(false)
                    } else {
                        emptyList()
                    }
                }
                val found = family(name, ipv6)
                if (!ipv6 && ipv6Only) return found.flatMap { nat64.synthesize(it.bytes, port) }
                return found.map { it.withPort(port) }
            }
        }
    }

    /** A sort and interleave of RFC 8305 section 4 for one race: an RFC 6724 sort of its own ([DestinationSort]). */
    fun order(): (List<TcpAddress>) -> List<TcpAddress> = defaultOrder(newSort())

    /**
     * Every address of [host] with [port], both families as this request resolves them (no NAT64 synthesis: these name the
     * host, as a WebSocket key or a SOCKS5 target), sorted by RFC 6724 section 6 unless [sorted] is false: a SOCKS5 proxy
     * connects to them over its own routes, so this host's say nothing about their order there: the IPv6 addresses come
     * first, then the IPv4 ones, each family in the resolver's order. [host] is a URL host, an IPv6 literal with or without its brackets.
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
                checkedLiteral(name, port)
            } else {
                object : AddressResolution {
                    override suspend fun addresses(ipv6: Boolean): List<TcpAddress> = family(name, ipv6).map { it.withPort(port) }
                }
            }
        val found = resolveBoth(plain, name)
        return if (sorted) newSort().sort(found) else found
    }

    /**
     * The addresses of [host] with [port] that have answered, for keys that name the host (`WebSocketConnecting`): a
     * literal itself; else the first family that answers with addresses, and the other one when it answers within the
     * Resolution Delay (RFC 8305 section 3), never waiting for a family that stalls (a network that drops AAAA queries).
     * A family that answers with none or fails is waited past. Fails only when both failed or neither has an address.
     *
     * [onAnswered] gets the addresses inside the lookups' scope, as soon as they are known: a caller under a deadline keeps
     * them from there even when the deadline cancels this call as its scope completes (the scope then throws instead of
     * returning); [afterForTest] runs right after it, still inside the scope.
     */
    suspend fun answered(
        host: String,
        port: Int,
        onAnswered: ((List<TcpAddress>) -> Unit)? = null,
        afterForTest: (suspend () -> Unit)? = null,
    ): List<TcpAddress> {
        if (endpoint != null) return root().answered(endpoint.first, endpoint.second, onAnswered, afterForTest)
        val name = socketHost(host)
        if (':' in name || parseIpv4Literal(name) != null) {
            return resolveBoth(checkedLiteral(name, port), name).also {
                onAnswered?.invoke(it)
                afterForTest?.invoke()
            }
        }
        val got =
            coroutineScope {
                val answers = Channel<Result<List<TcpAddress>>>(2)
                val lookups =
                    listOf(true, false).map { v6 ->
                        launch(start = CoroutineStart.UNDISPATCHED) {
                            val r =
                                try {
                                    Result.success(family(name, v6))
                                } catch (e: CancellationException) {
                                    throw e
                                } catch (e: Throwable) {
                                    Result.failure(e)
                                }
                            answers.send(r)
                        }
                    }
                val first = answers.receive()
                val positive = first.getOrNull().orEmpty().isNotEmpty()
                // a select, not withTimeoutOrNull around receive: the answer is either taken by the select or left in the
                // channel; a receive cancelled by the timeout after the answer was handed to it would drop it
                val second =
                    if (positive) {
                        select<Result<List<TcpAddress>>?> {
                            answers.onReceive { it }
                            onTimeout(RESOLUTION_DELAY) { null }
                        }
                    } else {
                        answers.receive()
                    }
                val both = listOfNotNull(first, second)
                both
                    .flatMap { it.getOrNull().orEmpty() }
                    .distinct()
                    .map { it.withPort(port) }
                    .takeIf { it.isNotEmpty() }
                    ?.let { onAnswered?.invoke(it) }
                afterForTest?.invoke()
                // the scope waits for the slower lookup's cancellation: a deadline landing then makes it throw
                lookups.forEach { it.cancel() }
                both
            }
        val found = got.flatMap { it.getOrNull().orEmpty() }.distinct().map { it.withPort(port) }
        if (found.isNotEmpty()) return found
        val failure = got.firstNotNullOfOrNull { it.exceptionOrNull() }
        // a fresh exception: the lookups' failures are shared by the request (and kept for their negative TTL)
        throw kotlinx.io.IOException("$name could not be resolved" + (failure?.message?.let { ": $it" } ?: ""), failure)
    }

    /**
     * [answered], plus the addresses a connection to them goes to on an IPv6-only network with NAT64 (the IPv6 addresses
     * synthesized for its IPv4 answers, RFC 8305 section 7): every address a connection to [host] could have now.
     */
    suspend fun answeredDestinations(
        host: String,
        port: Int,
    ): List<TcpAddress> {
        val found = answered(host, port)
        if (!nat64.ipv6OnlyNetwork()) return found
        return found + found.filter { it.bytes.size == 4 }.flatMap { nat64.synthesize(it.bytes, port) }
    }

    /**
     * The resolution of the address literal [name] (no lookup), failing with an IOException when it is an address no
     * connection may go to ([requireDestination]). A literal that does not parse fails later, as before, where it is used.
     */
    private suspend fun checkedLiteral(
        name: String,
        port: Int,
    ): SystemResolution {
        val literal = SystemResolution(name, port)
        val addresses =
            try {
                literal.addresses(true) + literal.addresses(false)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Throwable) {
                emptyList()
            }
        addresses.forEach { requireDestination(name, it) }
        // the JDK makes an IPv4-mapped literal its IPv4 address, which the IPv6 family then leaves out: check the literal itself
        if (':' in name) parseIpLiteral(name)?.let { requireDestination(name, TcpAddress(it, 0)) }
        return literal
    }

    private fun root(): RequestDns = RequestDns(resolveFamily, nat64, newSort, lock, answers, null, familyEvents, null, echRoutes)

    /**
     * One family of [name] (port 0) from this request's answers, looked up by the first caller that needs it. A host with
     * the form of an IPv4 address other than a dotted quad is the engine's to read, whatever the resolver ([numericAnswer]):
     * its address without a lookup (and without DNS events), or a failure.
     */
    private suspend fun family(
        name: String,
        ipv6: Boolean,
    ): List<TcpAddress> {
        numericAnswer(name, ipv6)?.let { return it }
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
                        // no answer, the system's included, is a destination no packet may go to (usableAsDestination)
                        Result.success(familyEvents.observing(name, ipv6) { resolveFamily(name, ipv6).filter(::usableAsDestination) })
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
 * A fresh [RequestDns] with this configuration's resolver: the system's ([Dns.System], the default: the path of 0.2, as it
 * was), the application's ([KuicksilverEngineConfig.dns], through [familyResolver]), or a test's. A test resolver of both
 * families ([KuicksilverEngineConfig.resolverForTest]) is asked once per name, and its answer split by family.
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
internal fun KuicksilverEngineConfig.newRequestDns(events: DnsObserver? = null): RequestDns {
    familyResolverForTest?.let { return RequestDns(nat64ForTest ?: Nat64.offForTest(), { RequestDns.dualStackSortForTest() }, events, it) }
    resolverForTest?.let { both ->
        val once = OncePerName { name -> events.observing(name, null) { both(name, 0) } }
        return RequestDns(nat64ForTest ?: Nat64.offForTest(), { RequestDns.dualStackSortForTest() }) { name, ipv6 ->
            once.get(name).filter { it.isIpv6 == ipv6 }
        }
    }
    if (network.dns === Dns.System) return RequestDns(familyEvents = events).also { it.isSystemForTest = true }
    // the same NAT64 handling and RFC 6724 sort as the system's answers: only the source of the addresses differs
    val app = network.dns
    return RequestDns(
        nat64ForTest ?: Nat64.system,
        familyEvents = events.takeIf { app is FamilyDns },
        resolveFamily = app.familyResolver(events),
    )
}
