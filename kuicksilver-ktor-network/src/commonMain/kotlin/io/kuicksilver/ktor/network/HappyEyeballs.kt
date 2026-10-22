// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.Socket
import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
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
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.onTimeout
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.io.IOException
import kotlin.concurrent.Volatile
import kotlin.time.Duration

/*
 * Happy Eyeballs version 2 (RFC 8305) for the engines' TCP connects: every address a name resolves to, the two families
 * interleaved (section 4), attempts started one connection attempt delay apart or as soon as the previous one failed
 * (section 5), the first connected socket wins and the others are cancelled or, if they connected too, closed (section 6).
 * There is no resolution delay (section 3): getaddrinfo and InetAddress.getAllByName return both families in one answer.
 */

/**
 * An IP address and a TCP port, for the engines' connects: [bytes] holds 4 (IPv4) or 16 (IPv6) bytes in network order,
 * [scopeId] the zone of a link-local IPv6 address (0: none).
 */
@InternalKuicksilverApi
public class TcpAddress(
    bytes: ByteArray,
    /** The TCP port, 0..65535. */
    public val port: Int,
    /** The IPv6 scope (zone) id; 0 for IPv4 and for addresses without one. */
    public val scopeId: Int = 0,
) {
    private val ip: ByteArray = bytes.copyOf()

    init {
        require(ip.size == 4 || ip.size == 16) { "an IP address has 4 or 16 bytes, not ${ip.size}" }
        require(port in 0..0xffff) { "port out of range: $port" }
    }

    /** The address bytes (a copy): 4 for IPv4, 16 for IPv6. */
    public val bytes: ByteArray get() = ip.copyOf()

    /** Whether this is an IPv6 address. */
    public val isIpv6: Boolean get() = ip.size == 16

    /** The address as text without brackets: dotted decimal, or RFC 5952 IPv6 with `%scope` when it has one. */
    public val hostText: String get() = ipText(ip) + if (scopeId != 0) "%${scopeId.toUInt()}" else ""

    /** The same address with [port]. */
    public fun withPort(port: Int): TcpAddress = if (port == this.port) this else TcpAddress(ip, port, scopeId)

    override fun equals(other: Any?): Boolean =
        other is TcpAddress && other.port == port && other.scopeId == scopeId && other.ip.contentEquals(ip)

    override fun hashCode(): Int = (ip.contentHashCode() * 31 + port) * 31 + scopeId

    override fun toString(): String = if (isIpv6) "[$hostText]:$port" else "$hostText:$port"
}

/**
 * The addresses [host] resolves to for [port], in the resolver's order (RFC 6724 destination address selection where the
 * platform does it; on the JVM, `java.net.preferIPv6Addresses` decides which family comes first, IPv4 by default).
 *
 * - An address literal (brackets allowed) never reaches the resolver: a dotted-decimal IPv4 address (four octets
 *   0..255) is parsed here, an IPv6 one (anything with a `:`) by `getaddrinfo` with `AI_NUMERICHOST` or the JVM's literal
 *   parser, which do not look anything up; an invalid one fails with an [IOException].
 * - A name is resolved by `InetAddress.getAllByName` (JVM, Android) or `getaddrinfo` (Kotlin/Native), which block a
 *   thread and cannot be interrupted. Lookups run on a view of [Dispatchers.IO] limited to [MAX_CONCURRENT_LOOKUPS]
 *   threads, so a resolver that stalls holds at most that many and never the threads the socket loops run on (the rest
 *   of `Dispatchers.IO`, threat model 3.21); and one lookup of a name is in flight at a time, shared by every caller
 *   that asks for it meanwhile, so a storm of requests to one stalled name holds one thread. A caller does not wait for
 *   a lookup once it is cancelled: a connect timeout ends a slow resolution as it ends a slow connect, while the lookup
 *   itself finishes on its thread and is then forgotten (nothing is cached past it).
 *
 * Fails with an [IOException] when the name does not resolve or resolves to no address.
 */
@InternalKuicksilverApi
public suspend fun resolveTcp(
    host: String,
    port: Int,
): List<TcpAddress> {
    require(port in 0..0xffff) { "port out of range: $port" }
    val name = if (host.length >= 2 && host.first() == '[' && host.last() == ']') host.substring(1, host.length - 1) else host
    parseIpv4Literal(name)?.let { return listOf(TcpAddress(it, port)) }
    val found =
        if (':' in name) {
            platformResolveTcp(name, port, numericHost = true) // an IPv6 literal: parsed, never looked up
        } else {
            sharedLookup(name).map { it.withPort(port) }
        }
    if (found.isEmpty()) throw IOException("$name resolved to no address")
    return found.distinct()
}

/**
 * How many name lookups run at once, process-wide. `getaddrinfo` and `getAllByName` block their thread for as long as
 * the system resolver takes (a stalled DNS server: tens of seconds), and [Dispatchers.IO] (64 threads by default) also
 * runs the engines' socket loops; 8 leaves those loops nearly all of it while lookups of different names still proceed
 * in parallel (Chromium runs 6 system lookups at once).
 */
internal const val MAX_CONCURRENT_LOOKUPS: Int = 8

@OptIn(ExperimentalCoroutinesApi::class)
private val lookupDispatcher = Dispatchers.IO.limitedParallelism(MAX_CONCURRENT_LOOKUPS)

/** The lookups in flight, by name; each removes itself when it completes. */
private val lookupLock = Mutex()
private val lookupsInFlight = HashMap<String, Deferred<List<TcpAddress>>>()

/** Replaces the platform's blocking lookup of a name (tests: a resolver that stalls); null in production. */
@Volatile
internal var blockingLookupForTest: ((String) -> List<TcpAddress>)? = null

/**
 * The addresses of [name] (port 0) from the lookup in flight for it, or a new one on [lookupDispatcher]. The lookup is
 * not a child of the caller: a cancelled caller leaves it to the others waiting for it, or to finish on its own.
 */
@OptIn(DelicateCoroutinesApi::class)
private suspend fun sharedLookup(name: String): List<TcpAddress> {
    val lookup =
        lookupLock.withLock {
            lookupsInFlight[name] ?: GlobalScope
                .async(lookupDispatcher, CoroutineStart.LAZY) {
                    try {
                        blockingLookupForTest?.invoke(name) ?: platformResolveTcp(name, 0, numericHost = false)
                    } finally {
                        val self = coroutineContext[Job]
                        withContext(NonCancellable) {
                            lookupLock.withLock { if (lookupsInFlight[name] === self) lookupsInFlight.remove(name) }
                        }
                    }
                }.also {
                    lookupsInFlight[name] = it
                    it.start()
                }
        }
    return lookup.await()
}

/** The lookups in flight (tests). */
internal suspend fun lookupsInFlightForTest(): Int = lookupLock.withLock { lookupsInFlight.size }

/** The four bytes of a dotted-decimal IPv4 literal (each octet 0..255, at most three digits), or null. */
internal fun parseIpv4Literal(name: String): ByteArray? {
    val parts = name.split('.')
    if (parts.size != 4) return null
    val out = ByteArray(4)
    for ((i, p) in parts.withIndex()) {
        if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' }) return null
        val v = p.toInt()
        if (v > 255) return null
        out[i] = v.toByte()
    }
    return out
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

/**
 * Opens a TCP connection to exactly [address], as [connectTcp] does for one resolved address (on Kotlin/Native a socket
 * of this module, not ktor-network's native connect: Ktor issue KTOR-10017, security, under coordinated disclosure).
 * Fails with an [IOException] when the connection cannot be made; a cancelled connect closes its socket.
 */
@InternalKuicksilverApi
public expect suspend fun connectTcpAddress(
    selector: SelectorManager,
    address: TcpAddress,
): Socket

/**
 * Opens a TCP connection to [host] and [port] with Happy Eyeballs (RFC 8305): [resolve] gives the addresses, the families
 * are interleaved ([interleaveFamilies]), and a new attempt starts every [attemptDelay] or as soon as the previous one
 * failed; the first connected socket is returned, the other attempts are cancelled and sockets that connected too are
 * closed. [Duration.INFINITE] tries the addresses one after another. When every attempt fails, the last failure is thrown
 * with the others suppressed. The race has no deadline of its own: the caller bounds it (the engines' connect timeout).
 */
@InternalKuicksilverApi
public suspend fun connectTcpRacing(
    selector: SelectorManager,
    host: String,
    port: Int,
    attemptDelay: Duration,
    resolve: suspend (String, Int) -> List<TcpAddress> = ::resolveTcp,
): Socket {
    require(attemptDelay.isPositive()) { "attemptDelay must be positive, was $attemptDelay" }
    val addrs = interleaveFamilies(resolve(host, port))
    if (addrs.isEmpty()) throw IOException("$host resolved to no address")
    return happyEyeballs(addrs, attemptDelay, connect = { connectTcpAddress(selector, it) }, close = { it.close() })
}

/**
 * [addrs] with the two families alternating (RFC 8305 section 4, First Address Family Count 1): the family of the first
 * address leads, as the resolver ordered it (RFC 6724), and the order within each family is kept.
 */
internal fun interleaveFamilies(addrs: List<TcpAddress>): List<TcpAddress> {
    if (addrs.isEmpty()) return addrs
    val firstV6 = addrs.first().isIpv6
    val lead = addrs.filter { it.isIpv6 == firstV6 }
    val other = addrs.filter { it.isIpv6 != firstV6 }
    val out = ArrayList<TcpAddress>(addrs.size)
    for (i in 0 until maxOf(lead.size, other.size)) {
        if (i < lead.size) out += lead[i]
        if (i < other.size) out += other[i]
    }
    return out
}

/**
 * The race of RFC 8305 section 5 over [addrs], in order: each attempt is a child coroutine running [connect]; the next
 * one starts when [attemptDelay] has passed since the last start or when an attempt failed, whichever comes first
 * ([Duration.INFINITE]: only on failure, one at a time). The first result wins; the other attempts are cancelled, and a
 * result that arrives anyway (a connect that completed as it was cancelled) is given to [close]. When every attempt fails,
 * the last failure is thrown with the earlier ones suppressed. Cancelling the caller cancels every attempt, and closes a
 * winner it can no longer return.
 */
@OptIn(ExperimentalCoroutinesApi::class)
internal suspend fun <S> happyEyeballs(
    addrs: List<TcpAddress>,
    attemptDelay: Duration,
    connect: suspend (TcpAddress) -> S,
    close: (S) -> Unit,
): S {
    require(addrs.isNotEmpty()) { "no address to connect to" }
    // outside the scope: a caller cancelled after an attempt won (while the losers wind down) still closes the winner
    val won = CompletableDeferred<S>()
    try {
        coroutineScope {
            val failures = Channel<Throwable>(Channel.UNLIMITED)
            val errors = ArrayList<Throwable>(addrs.size)
            var started = 0

            fun startNext() {
                val address = addrs[started++]
                launch {
                    val s =
                        try {
                            connect(address)
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Throwable) {
                            failures.trySend(e)
                            return@launch
                        }
                    // a loser that connected after all: nobody takes its socket
                    if (!won.complete(s)) runCatching { close(s) }
                }
            }

            startNext()
            while (!won.isCompleted) {
                select<Unit> {
                    won.onJoin {}
                    failures.onReceive { e ->
                        errors += e
                        if (errors.size == addrs.size) throw lastWithSuppressed(errors)
                        if (started < addrs.size) startNext()
                    }
                    if (started < addrs.size && !attemptDelay.isInfinite()) onTimeout(attemptDelay) { startNext() }
                }
            }
            coroutineContext.cancelChildren()
        }
    } catch (e: Throwable) {
        if (won.isCompleted) runCatching { close(won.getCompleted()) }
        throw e
    }
    return won.getCompleted()
}

private fun lastWithSuppressed(errors: List<Throwable>): Throwable {
    val last = errors.last()
    for (e in errors) if (e !== last) last.addSuppressed(e)
    return last
}

private fun Byte.u(): Int = toInt() and 0xff

/**
 * The text of the IPv4 (4 bytes) or IPv6 (16 bytes) address [ip]: dotted decimal, or RFC 5952 (lower-case hex, the longest
 * run of zero groups as `::`, an IPv4-mapped address as `::ffff:a.b.c.d`).
 */
internal fun ipText(ip: ByteArray): String {
    if (ip.size == 4) return ip.joinToString(".") { it.u().toString() }
    // an IPv4-mapped peer of a dual-stack listener, written as inet_ntop (and ktor-network) does
    if ((0 until 10).all { ip[it].toInt() == 0 } && ip[10].u() == 0xff && ip[11].u() == 0xff) {
        return "::ffff:" + ipText(ip.copyOfRange(12, 16))
    }
    val groups = IntArray(8) { (ip[2 * it].u() shl 8) or ip[2 * it + 1].u() }
    var bestStart = -1
    var bestLength = 1 // RFC 5952 4.2.2: a single zero group is not compressed
    var i = 0
    while (i < 8) {
        if (groups[i] != 0) {
            i++
            continue
        }
        var j = i
        while (j < 8 && groups[j] == 0) j++
        if (j - i > bestLength) {
            bestStart = i
            bestLength = j - i
        }
        i = j
    }
    if (bestStart < 0) return groups.joinToString(":") { it.toString(16) }
    val head = (0 until bestStart).joinToString(":") { groups[it].toString(16) }
    val tail = (bestStart + bestLength until 8).joinToString(":") { groups[it].toString(16) }
    return "$head::$tail"
}
