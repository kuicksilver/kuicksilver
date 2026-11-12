// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.tls.KslNet
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.IO
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.io.IOException
import kotlin.concurrent.Volatile

/**
 * The addresses of a name as they arrive, one family at a time: RFC 8305 section 3 has the client send "both AAAA and A
 * DNS queries" and "treat DNS resolution as asynchronous", so a race ([raceAddresses]) can start on one family's answer
 * while the other is still out.
 */
@InternalKuicksilverApi
public interface AddressResolution {
    /**
     * The addresses of one family, IPv6 ([ipv6]) or IPv4, with the port of the connection: empty when the name has none
     * of that family ("a negative AAAA response (no error, no data)"), an exception when the lookup failed. The race calls
     * it once per family, the two concurrently. On an IPv6-only network ([ipv6Only]) the IPv4 answer comes back as IPv6
     * addresses synthesized for the network's NAT64 (RFC 8305 section 7).
     */
    public suspend fun addresses(ipv6: Boolean): List<TcpAddress>

    /**
     * Whether this is an IPv6-only network with NAT64 and DNS64 (RFC 8305 section 7): then IPv4 is asked only when the IPv6
     * answer was negative or failed, or as the last resort when no IPv6 attempt connected (section 7.2), and its answer is
     * synthesized; otherwise both families are asked at once.
     */
    public val ipv6Only: Boolean get() = false
}

/**
 * The system's resolution of [host] for [port]: an address literal answers its own family at once without a lookup, a
 * name is resolved one family at a time ([resolveFamily]).
 */
@InternalKuicksilverApi
public class SystemResolution(
    host: String,
    private val port: Int,
) : AddressResolution {
    private val name: String = unbracket(host)
    private val v4Literal: ByteArray? = parseIpv4Literal(name)

    init {
        require(port in 0..0xffff) { "port out of range: $port" }
    }

    override suspend fun addresses(ipv6: Boolean): List<TcpAddress> {
        v4Literal?.let { return if (ipv6) emptyList() else listOf(TcpAddress(it, port)) }
        if (':' in name) {
            // an IPv6 literal: parsed, never looked up
            return if (ipv6) platformResolveTcp(name, port, numericHost = true).filter { it.isIpv6 } else emptyList()
        }
        return resolveFamily(name, ipv6).map { it.withPort(port) }
    }
}

private fun unbracket(host: String): String =
    if (host.length >= 2 && host.first() == '[' && host.last() == ']') host.substring(1, host.length - 1) else host

/**
 * The addresses [host] resolves to for [port], both families, sorted by RFC 6724 section 6 ([DestinationSort]).
 *
 * - An address literal (brackets allowed) never reaches the resolver: a dotted-decimal IPv4 address (four octets
 *   0..255) is parsed here, an IPv6 one (anything with a `:`) by `getaddrinfo` with `AI_NUMERICHOST` or the JVM's literal
 *   parser, which do not look anything up; an invalid one fails with an [IOException].
 * - A name is resolved one family at a time ([resolveFamily]), the two in parallel.
 *
 * Fails with an [IOException] when the name does not resolve or resolves to no address.
 */
@InternalKuicksilverApi
public suspend fun resolveTcp(
    host: String,
    port: Int,
): List<TcpAddress> {
    require(port in 0..0xffff) { "port out of range: $port" }
    val name = unbracket(host)
    parseIpv4Literal(name)?.let { return listOf(TcpAddress(it, port)) }
    if (':' in name) {
        val found = platformResolveTcp(name, port, numericHost = true)
        if (found.isEmpty()) throw IOException("$name resolved to no address")
        return found.distinct()
    }
    val found = resolveBoth(SystemResolution(name, port), name)
    return DestinationSort().sort(found)
}

/**
 * Both families of [resolution], AAAA first: the answers that came, or the failure when neither family has an address
 * (the other failure suppressed), or an [IOException] when both answered with none.
 */
@InternalKuicksilverApi
public suspend fun resolveBoth(
    resolution: AddressResolution,
    name: String,
): List<TcpAddress> =
    coroutineScope {
        val v6 = async(start = CoroutineStart.UNDISPATCHED) { runCatchingLookup { resolution.addresses(true) } }
        val v4 = async(start = CoroutineStart.UNDISPATCHED) { runCatchingLookup { resolution.addresses(false) } }
        val a6 = v6.await()
        val a4 = v4.await()
        val out = (a6.getOrNull().orEmpty() + a4.getOrNull().orEmpty()).distinct()
        if (out.isNotEmpty()) return@coroutineScope out
        val failures = listOfNotNull(a6.exceptionOrNull(), a4.exceptionOrNull())
        if (failures.isEmpty()) throw IOException("$name resolved to no address")
        val first = failures.first()
        for (e in failures.drop(1)) if (e !== first) first.addSuppressed(e)
        throw first
    }

private suspend fun <T> runCatchingLookup(block: suspend () -> T): Result<T> =
    try {
        Result.success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: Throwable) {
        Result.failure(e)
    }

/**
 * The addresses (port 0) of one family of [name], a host name (not a literal), from the system's resolver: `getaddrinfo`
 * with `AF_INET6` ([ipv6]) or `AF_INET`, through `ksl_resolve` on the JVM and Android, whose `InetAddress` asks for both
 * at once (RFC 8305 section 3: "this behavior can be simulated by making two separate synchronous queries on different
 * threads, one per address family"). On the JVM, a resolver the application installed (`InetAddressResolverProvider`,
 * `jdk.net.hosts.file`) is honoured instead: `InetAddress.getAllByName` then answers both families at once.
 *
 * Empty when the name has no address of that family; an [IOException] when the lookup failed. Lookups block a thread and
 * cannot be interrupted: they run on a view of [Dispatchers.IO] limited to [MAX_CONCURRENT_LOOKUPS] threads, so a resolver
 * that stalls holds at most that many and never the threads the socket loops run on (threat model 3.21); one lookup of a
 * name and family is in flight at a time, shared by every caller that asks for it meanwhile. A caller does not wait for a
 * lookup once it is cancelled; the lookup itself finishes on its thread (its answer still reaches the system's cache, as
 * RFC 8305 section 5 has it: "the DNS client resolver SHOULD still process DNS replies from the network for a short period
 * of time") and is then forgotten.
 */
@InternalKuicksilverApi
public suspend fun resolveFamily(
    name: String,
    ipv6: Boolean,
): List<TcpAddress> = sharedLookup(name, ipv6).filter { it.isIpv6 == ipv6 }.distinct()

/**
 * How many name lookups run at once, process-wide. `getaddrinfo` and `getAllByName` block their thread for as long as
 * the system resolver takes (a stalled DNS server: tens of seconds), and [Dispatchers.IO] (64 threads by default) also
 * runs the engines' socket loops; 8 leaves those loops nearly all of it while lookups of different names still proceed
 * in parallel (Chromium runs 6 system lookups at once).
 */
internal const val MAX_CONCURRENT_LOOKUPS: Int = 8

@OptIn(ExperimentalCoroutinesApi::class)
private val lookupDispatcher = Dispatchers.IO.limitedParallelism(MAX_CONCURRENT_LOOKUPS)

/** The lookups in flight, by name and family; each removes itself when it completes. */
private val lookupLock = Mutex()
private val lookupsInFlight = HashMap<Pair<String, Boolean>, Deferred<List<TcpAddress>>>()

/** Replaces the platform's blocking lookup of one family of a name (tests: a resolver that stalls); null in production. */
@Volatile
internal var blockingLookupForTest: ((String, Boolean) -> List<TcpAddress>)? = null

/**
 * The addresses of one family of [name] (port 0) from the lookup in flight for it, or a new one on [lookupDispatcher].
 * The lookup is not a child of the caller: a cancelled caller leaves it to the others waiting for it, or to finish on its
 * own.
 */
@OptIn(DelicateCoroutinesApi::class)
private suspend fun sharedLookup(
    name: String,
    ipv6: Boolean,
): List<TcpAddress> {
    val key = name to ipv6
    val lookup =
        lookupLock.withLock {
            lookupsInFlight[key] ?: GlobalScope
                .async(lookupDispatcher, CoroutineStart.LAZY) {
                    try {
                        blockingLookupForTest?.invoke(name, ipv6) ?: platformResolveFamily(name, ipv6)
                    } finally {
                        val self = coroutineContext[Job]
                        withContext(NonCancellable) {
                            lookupLock.withLock { if (lookupsInFlight[key] === self) lookupsInFlight.remove(key) }
                        }
                    }
                }.also {
                    lookupsInFlight[key] = it
                    it.start()
                }
        }
    return lookup.await()
}

/** The lookups in flight (tests). */
internal suspend fun lookupsInFlightForTest(): Int = lookupLock.withLock { lookupsInFlight.size }

/**
 * The platform's blocking lookup of one family of [name] (port 0): `ksl_resolve` ([KslNet.resolve]); on the JVM the
 * JDK's resolver where the application replaced it. Empty for none of that family; an [IOException] when it failed.
 */
internal expect fun platformResolveFamily(
    name: String,
    ipv6: Boolean,
): List<TcpAddress>

/** [platformResolveFamily] through `ksl_resolve`, or null when the native library cannot be used. */
internal fun kslResolveFamily(
    name: String,
    ipv6: Boolean,
): List<TcpAddress>? {
    if (!KslNet.available()) return null
    val found = KslNet.resolve(name, ipv6) ?: throw IOException("Failed to resolve ${if (ipv6) "AAAA" else "A"} of $name")
    return found.map { TcpAddress(it.bytes, 0, it.scopeId) }
}

/**
 * The platform's blocking resolution of [name] for [port]: `getAllByName` or `getaddrinfo`. With [numericHost], [name]
 * is an address literal that must not be looked up (`AI_NUMERICHOST`; on the JVM a literal parse), and an invalid one
 * fails with an [IOException].
 */
internal expect fun platformResolveTcp(
    name: String,
    port: Int,
    numericHost: Boolean,
): List<TcpAddress>
