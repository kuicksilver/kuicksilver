// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.Socket
import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.onTimeout
import kotlinx.coroutines.selects.select
import kotlinx.io.IOException
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
 * platform does it; on the JVM, `java.net.preferIPv6Addresses` decides which family comes first, IPv4 by default). An
 * address literal (brackets allowed) is returned as it is, without a lookup. A name is resolved on [Dispatchers.IO] by
 * `InetAddress.getAllByName` (JVM, Android) or `getaddrinfo` (Kotlin/Native), in a lookup the caller does not wait for
 * once it is cancelled: a connect timeout ends a slow resolution as it ends a slow connect. Fails with an [IOException]
 * when the name does not resolve or resolves to no address.
 */
@InternalKuicksilverApi
public suspend fun resolveTcp(
    host: String,
    port: Int,
): List<TcpAddress> {
    require(port in 0..0xffff) { "port out of range: $port" }
    val name = if (host.length >= 2 && host.first() == '[' && host.last() == ']') host.substring(1, host.length - 1) else host
    val found = if (isIpLiteral(name)) platformResolveTcp(name, port) else resolveDetached(name, port)
    if (found.isEmpty()) throw IOException("$name resolved to no address")
    return found.distinct()
}

/** A blocking lookup run where the caller can leave it: getaddrinfo cannot be interrupted, so it finishes on its own. */
@OptIn(DelicateCoroutinesApi::class)
private suspend fun resolveDetached(
    name: String,
    port: Int,
): List<TcpAddress> = GlobalScope.async(Dispatchers.IO) { platformResolveTcp(name, port) }.await()

/** Whether [name] is an IP address literal (IPv6 with an optional zone, or dotted-decimal IPv4), which needs no lookup. */
internal fun isIpLiteral(name: String): Boolean = ':' in name || IPV4_LITERAL.matches(name)

private val IPV4_LITERAL = Regex("""\d{1,3}(\.\d{1,3}){3}""")

/** The platform's blocking resolution of [name] (a name or a literal) for [port]: `getAllByName` or `getaddrinfo`. */
internal expect fun platformResolveTcp(
    name: String,
    port: Int,
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
