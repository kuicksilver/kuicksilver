// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.ktor.network.SystemResolution
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.ktor.network.parseIpv4Literal
import io.kuicksilver.ktor.network.resolveFamily
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.io.IOException

/**
 * An IP address, as a [Dns] answers: IPv4 (4 bytes) or IPv6 (16 bytes, with the [scopeId] of a link-local address).
 * Equal when the bytes and the scope are.
 */
@ExperimentalKuicksilverApi
public class IpAddress private constructor(
    private val ip: ByteArray,
    /** The IPv6 zone (scope) id of a link-local address, as the system numbers interfaces; 0 for none and for IPv4. */
    public val scopeId: Int,
) {
    /** The address in network byte order (a copy): 4 bytes for IPv4, 16 for IPv6. */
    public val bytes: ByteArray get() = ip.copyOf()

    /** Whether this is an IPv6 address (an IPv4-mapped one included). */
    public val isIpv6: Boolean get() = ip.size == 16

    /** Equal when the bytes and the scope are. */
    override fun equals(other: Any?): Boolean = other is IpAddress && other.scopeId == scopeId && other.ip.contentEquals(ip)

    /** Consistent with [equals]. */
    override fun hashCode(): Int = ip.contentHashCode() * 31 + scopeId

    /** Dotted decimal, or RFC 5952 text for IPv6 with `%scope` when it has one; no brackets. */
    override fun toString(): String = TcpAddress(ip, 0, scopeId).hostText

    internal fun toTcp(): TcpAddress = TcpAddress(ip, 0, scopeId)

    /** Builds addresses. */
    public companion object {
        /**
         * The address of [bytes] (copied): 4 for IPv4, 16 for IPv6. A [scopeId] other than 0 is for IPv6 only. Anything
         * else fails with [IllegalArgumentException].
         */
        public fun of(
            bytes: ByteArray,
            scopeId: Int = 0,
        ): IpAddress {
            require(bytes.size == 4 || bytes.size == 16) { "an IP address has 4 or 16 bytes, not ${bytes.size}" }
            require(scopeId == 0 || bytes.size == 16) { "only an IPv6 address has a scope id" }
            return IpAddress(bytes.copyOf(), scopeId)
        }

        /**
         * The address [text] writes: a dotted-decimal IPv4 address (four decimal octets 0..255 without leading zeros, which
         * other parsers read as octal) or an IPv6 address (RFC 4291 section 2.2), with or without brackets, and with a
         * numeric `%zone` (an interface index). Never a lookup: anything else, a host name included, fails with
         * [IllegalArgumentException].
         */
        public fun parse(text: String): IpAddress {
            val s = socketHost(text)
            require(':' in s || s == text) { "brackets are for IPv6 addresses only: $text" }
            val pct = s.indexOf('%')
            val literal = if (pct >= 0) s.substring(0, pct) else s
            val bytes =
                if (':' in literal) parseIpLiteral(literal)?.takeIf { it.size == 16 } else parseIpv4Literal(literal)
            require(bytes != null) { "not an IP address literal: $text" }
            var scope = 0
            if (pct >= 0) {
                val zone = s.substring(pct + 1)
                require(bytes.size == 16 && zone.length in 1..10 && zone.all { it in '0'..'9' }) {
                    "the zone of an IP address literal is an interface index: $text"
                }
                scope = zone.toLong().takeIf { it <= 0xffffffffL }?.toInt() ?: throw IllegalArgumentException("zone out of range: $text")
            }
            return IpAddress(bytes, scope)
        }
    }
}

/**
 * The name resolution of the Ktor client engine (`KuicksilverEngineConfig.dns`), after OkHttp's `Dns`: the addresses of a
 * host name, which the engine then connects to with Happy Eyeballs (RFC 8305) over TCP (HTTP/1.1, HTTP/2) and QUIC
 * (HTTP/3). [Dns.System] is the default; an application gives its own to use another DNS server (DNS over HTTPS, say), a
 * fixed address for a name, or a policy of its own. It must be safe for concurrent use. docs/guide/ktor.md, "Name
 * resolution".
 *
 * The contract:
 *
 * - [lookup] suspends and must not block its thread: the engine calls it in the call's coroutine, on the engine's
 *   dispatcher, never under an engine lock. Wrap a blocking resolver with [Dns.blocking], which runs it on threads of its
 *   own.
 * - It is part of connecting: the connect timeout (`connectTimeout`, or `HttpTimeout`'s) bounds it with the rest, and a
 *   lookup still running then is cancelled and the call fails with Ktor's `ConnectTimeoutException`; so is it when the call
 *   is cancelled. A `CancellationException` it throws while its caller is still active (a `withTimeout` of its own) is a
 *   failed lookup, not a cancellation.
 * - Any exception it throws is a failed lookup, as is an empty list or one without a usable address: the connection fails
 *   with the engine's `IOException` for a name that does not resolve ("could not be resolved", with the resolver's
 *   exception as the cause; "resolved to no address"). An `IOException` is kept as it is; another exception is wrapped.
 * - The order of the answer is a tie-break only: the engine sorts the addresses by RFC 6724 section 6 and interleaves the
 *   two families (RFC 8305 section 4, "the client MUST sort the addresses"), as it does the system's. Duplicates are
 *   dropped, an IPv4-mapped IPv6 address counts as the IPv4 address, and at most [Dns.MAX_ADDRESSES_PER_FAMILY] addresses of
 *   each family are kept, the first ones. Unspecified (0.0.0.0/8, `::`), multicast (224.0.0.0/4, `ff00::/8`) and limited
 *   broadcast (255.255.255.255) addresses are dropped, never connected to: RFC 1122 section 3.2.1.3 and RFC 4291 section
 *   2.5.2 never allow them as a destination, RFC 9293 section 3.9.1 (MUST-46) makes a TCP open to them an error, and a
 *   connect to 0.0.0.0 reaches the host's own listeners on Linux and macOS. The system's answers get the same check.
 * - It gets host names only, without brackets or port. An IP address literal in a URL is its own address and never reaches
 *   it (one no connection may go to, such as `0.0.0.0` or `ff02::1`, fails the call); nor does a host with the form of an
 *   IPv4 address that is not a dotted quad (`127.1` is 127.0.0.1, as every platform reads it; `010.0.0.1` or `0x7f.1` read
 *   differently by different platforms, and `256.1.1.1`, fail the call: no host name has that form, RFC 1123 section
 *   2.1). The engine reads such hosts the same way with [Dns.System].
 * - It is asked once per name per request: both sides of the HTTP/3 and TCP race, and a fallback, connect to that one
 *   answer. The engine keeps no answer beyond the request: caching (and its TTL) is the resolver's. A [FamilyDns] is asked
 *   for each address family on its own instead (RFC 8305 section 3), the two at once.
 * - What it is asked for: the origin's name for a direct connection, over TCP and QUIC, WebSocket and WebTransport alike;
 *   an `Alt-Svc` alternative's host and an HTTPS record's TargetName (the A and AAAA records an HTTPS answer carries are
 *   used as RFC 9460 section 5 says, and the resolver is asked for the families they lack); a proxy's name. Through an HTTP
 *   proxy and a `socks5h` proxy the origin's name goes to the proxy and is never resolved here; through `socks5` it is
 *   resolved here and the proxy gets the addresses. Not through it: HTTPS records (`http3.httpsRecords`), the NAT64 prefix
 *   discovery (`ipv4only.arpa`), and a proxy auto-configuration script's `dnsResolve`, which stay with the system.
 *
 * The answers are trusted as routing only, never as the server's identity: TLS sends the URL's host name as SNI and
 * verifies the certificate (and pins) against that name, whatever address the resolver gave, over TCP and QUIC (threat
 * model 3.25). Connections are pooled per origin, never per address: two destinations of one origin (its host and an
 * alternative) whose answers hold the address an HTTP/3 connection uses share it (RFC 9114 section 3.3), with the origin's
 * TLS settings either way; no connection is shared across origins.
 */
@ExperimentalKuicksilverApi
public fun interface Dns {
    /** The addresses of [host] (a host name, never an address literal), both families; see [Dns] for the contract. */
    public suspend fun lookup(host: String): List<IpAddress>

    /** The system's resolver and the adapter for blocking resolvers. */
    public companion object {
        /**
         * The system's resolver, the engine's default (as before 0.3.0): `getaddrinfo` once per address family on a bounded
         * pool of threads, its answers kept for the platform's cache lifetimes (docs/guide/ktor.md, "Happy Eyeballs"). A
         * resolver of your own may delegate to it for the names it does not handle. As a [FamilyDns] it answers each
         * family on its own; an address literal it answers without a lookup.
         */
        public val System: Dns = SystemDns

        /**
         * At most this many addresses of each family are kept from one answer (64 in all): at a connection attempt delay of
         * 250 ms that is 16 s of attempts, beyond any connect timeout that makes sense.
         */
        public const val MAX_ADDRESSES_PER_FAMILY: Int = MAX_DNS_ADDRESSES_PER_FAMILY

        /**
         * A [Dns] over a blocking [lookup] (an OkHttp `Dns`, a call into a native resolver), run on [dispatcher]: by
         * default a view of `Dispatchers.IO` limited to 8 threads, shared by every resolver made this way in the process,
         * whatever engine uses it, so lookups that stall hold at most those and never the threads the engine's sockets run
         * on. The other side of that bound: 8 lookups that hang hold all 8 threads, and every other lookup of the default
         * pool, of any engine, waits behind them until one returns (their calls fail at their connect timeouts). Give a
         * resolver that may hang a [dispatcher] of its own to keep it from starving the others. A caller that is cancelled
         * or whose connect timeout ends stops waiting at once and takes its lookup off the queue if it has not started; a
         * started blocking call cannot be interrupted, it goes on to its end on its thread and its answer is dropped.
         */
        public fun blocking(
            dispatcher: CoroutineDispatcher = blockingLookups,
            lookup: (host: String) -> List<IpAddress>,
        ): Dns = BlockingDns(dispatcher, lookup)
    }
}

/**
 * A [Dns] that answers each address family on its own, so that Happy Eyeballs can start connecting on the first family's
 * answer while the other is still out (RFC 8305 section 3: "send both AAAA and A DNS queries", "treat DNS resolution as
 * asynchronous"). The engine asks for both families at once, IPv6 first, each once per name per request; an address of the
 * other family in an answer is dropped.
 */
@ExperimentalKuicksilverApi
public interface FamilyDns : Dns {
    /** The addresses of one family of [host]: IPv6 ([ipv6]) or IPv4; an empty list when it has none of that family. */
    public suspend fun lookup(
        host: String,
        ipv6: Boolean,
    ): List<IpAddress>

    /**
     * Both families, asked for at once, IPv6 first in the list: what came, or the first family's failure when both
     * failed.
     */
    override suspend fun lookup(host: String): List<IpAddress> =
        coroutineScope {
            val v6 = async(start = CoroutineStart.UNDISPATCHED) { catching { lookup(host, true).filter { it.isIpv6 } } }
            val v4 = async(start = CoroutineStart.UNDISPATCHED) { catching { lookup(host, false).filter { !it.isIpv6 } } }
            val a6 = v6.await()
            val a4 = v4.await()
            if (a6.isFailure && a4.isFailure) throw a6.exceptionOrNull()!!
            a6.getOrNull().orEmpty() + a4.getOrNull().orEmpty()
        }
}

private suspend fun <T> catching(block: suspend () -> T): Result<T> =
    try {
        Result.success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: Throwable) {
        Result.failure(e)
    }

/** [Dns.MAX_ADDRESSES_PER_FAMILY]. */
internal const val MAX_DNS_ADDRESSES_PER_FAMILY: Int = 32

/** How many blocking lookups of [Dns.blocking] run at once by default, process-wide. */
internal const val MAX_BLOCKING_LOOKUPS: Int = 8

@OptIn(ExperimentalCoroutinesApi::class)
private val blockingLookups: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(MAX_BLOCKING_LOOKUPS)

private object SystemDns : FamilyDns {
    override suspend fun lookup(
        host: String,
        ipv6: Boolean,
    ): List<IpAddress> {
        val name = socketHost(host)
        val found =
            if (':' in name || parseIpv4Literal(name) != null) SystemResolution(name, 0).addresses(ipv6) else resolveFamily(name, ipv6)
        return found.map { IpAddress.of(it.bytes, it.scopeId) }
    }

    override fun toString(): String = "Dns.System"
}

private class BlockingDns(
    private val dispatcher: CoroutineDispatcher,
    private val blockingLookup: (String) -> List<IpAddress>,
) : Dns {
    /** Not a child of the caller: a cancelled caller stops waiting, and the blocking call ends on its thread. */
    @OptIn(DelicateCoroutinesApi::class)
    override suspend fun lookup(host: String): List<IpAddress> {
        val lookup = GlobalScope.async(dispatcher) { blockingLookup(host) }
        try {
            return lookup.await()
        } catch (e: CancellationException) {
            // the caller went: a lookup still waiting for a thread never runs (one that runs goes on to its end), so callers
            // that give up do not pile lookups up behind a resolver that hangs
            lookup.cancel()
            throw e
        }
    }

    override fun toString(): String = "Dns.blocking($blockingLookup)"
}

/**
 * Reports the lookups of one request to the engine's [KuicksilverEventListener] ([KuicksilverEventListener.dnsStart],
 * [KuicksilverEventListener.dnsEnd]): one start and one end per lookup, the end with the addresses or the failure.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal class DnsObserver(
    private val events: EngineEvents,
    private val request: io.ktor.client.request.HttpRequestData,
) {
    /** [lookup] of [host] ([ipv6]: the family, null for both) between a start and an end event. */
    suspend fun observe(
        host: String,
        ipv6: Boolean?,
        lookup: suspend () -> List<TcpAddress>,
    ): List<TcpAddress> {
        events.emit("dnsStart") { dnsStart(request, host, ipv6) }
        val found =
            try {
                lookup()
            } catch (e: Throwable) {
                events.emit("dnsEnd") { dnsEnd(request, host, ipv6, emptyList(), e) }
                throw e
            }
        events.emit("dnsEnd") { dnsEnd(request, host, ipv6, found.map { IpAddress.of(it.bytes, it.scopeId) }, null) }
        return found
    }
}

/** [lookup] through [this] observer, or as it is without one. */
internal suspend fun DnsObserver?.observing(
    host: String,
    ipv6: Boolean?,
    lookup: suspend () -> List<TcpAddress>,
): List<TcpAddress> = this?.observe(host, ipv6, lookup) ?: lookup()

/**
 * The resolver of one [RequestDns] over this application [Dns]: one family of a host name (port 0) as the engine connects
 * to it ([usableAnswer]). A plain [Dns] is asked once per name and its answer split by family ([OncePerName]); a
 * [FamilyDns] once per name and family (the [RequestDns] shares each family's answer within the request). A host with the
 * form of an IPv4 address never reaches it: [RequestDns] answers it ([numericAnswer]). A failure becomes the lookup's
 * ([asking]).
 */
internal fun Dns.familyResolver(observer: DnsObserver? = null): suspend (String, Boolean) -> List<TcpAddress> {
    val dns = this
    if (dns is FamilyDns) {
        // the per-family events are the RequestDns's, which calls this once per name and family
        return { name, ipv6 -> usableAnswer(asking(name) { dns.lookup(name, ipv6) }, ipv6) }
    }
    // one lookup of both families: its events are here, once, not per family
    val once = OncePerName { name -> observer.observing(name, null) { usableAnswer(asking(name) { dns.lookup(name) }, null) } }
    return { name, ipv6 -> once.get(name).filter { it.isIpv6 == ipv6 } }
}

/**
 * [block], the application's lookup of [name]: an `IOException` as it is, another exception wrapped in one, and a
 * `CancellationException` thrown while the caller is still active (the resolver's own timeout) as a failure, so it does not
 * pass for the call's cancellation.
 */
private suspend fun <T> asking(
    name: String,
    block: suspend () -> T,
): T =
    try {
        block()
    } catch (e: CancellationException) {
        currentCoroutineContext().ensureActive()
        throw IOException("the lookup of $name was cancelled by the resolver itself", e)
    } catch (e: IOException) {
        throw e
    } catch (e: Exception) {
        throw IOException("the lookup of $name failed: $e", e)
    }

/**
 * The address of [name] when it has the form of an IPv4 literal other than a dotted quad (which [RequestDns] answers
 * itself), as inet_aton reads it where every platform reads it alike (`127.1`, `2130706433`); null for a host name. One
 * that platforms read differently (octal, hex) or that is no address fails: it is no host name either (RFC 1123 section 2.1).
 */
internal fun numericAnswer(
    name: String,
    ipv6: Boolean,
): List<TcpAddress>? {
    val h = name.lowercase().removeSuffix(".")
    if (!AltSvcDestination.numericV4(h)) return null
    val v4 =
        AltSvcDestination.inetAton(h)
            ?: throw IOException("$name is neither a host name nor an IP address that every platform reads alike; it is not looked up")
    val address = TcpAddress(ByteArray(4) { v4[it].toByte() }, 0)
    requireDestination(name, address)
    return if (ipv6) emptyList() else listOf(address)
}

/**
 * Fails with an [IOException] when [address], which [host] (an address literal of a URL, or a numeric host) names itself,
 * is one no connection may go to ([usableAsDestination]): the URL asks for it, so it is not dropped as a resolver's answer
 * is, the request fails before any packet.
 */
internal fun requireDestination(
    host: String,
    address: TcpAddress,
) {
    if (!usableAsDestination(address)) {
        throw IOException(
            "$host is an address no connection may go to (unspecified, multicast or broadcast: RFC 1122 section 3.2.1.3, " +
                "RFC 4291 section 2.5.2, RFC 9293 section 3.9.1)",
        )
    }
}

/**
 * What the engine connects to of [answer]: the addresses of one family ([ipv6]; null: both) in the resolver's order, an
 * IPv4-mapped address as the IPv4 address, without duplicates, without destinations no packet may go to (unspecified,
 * multicast, limited broadcast: [usableDestination]), at most [MAX_DNS_ADDRESSES_PER_FAMILY] of each family (the rest of
 * the list is not looked at once both are full).
 */
internal fun usableAnswer(
    answer: List<IpAddress>,
    ipv6: Boolean?,
): List<TcpAddress> {
    val out = ArrayList<TcpAddress>()
    val seen = HashSet<TcpAddress>()
    var v4 = 0
    var v6 = 0
    for (a in answer) {
        val full4 = ipv6 == true || v4 >= MAX_DNS_ADDRESSES_PER_FAMILY
        val full6 = ipv6 == false || v6 >= MAX_DNS_ADDRESSES_PER_FAMILY
        if (full4 && full6) break
        val t = usableDestination(a) ?: continue
        if (if (t.isIpv6) full6 else full4) continue
        if (!seen.add(t)) continue
        out += t
        if (t.isIpv6) v6++ else v4++
    }
    return out
}

/** [a] as a destination (port 0), an IPv4-mapped address as IPv4; null for one no connection may go to ([usableAsDestination]). */
private fun usableDestination(a: IpAddress): TcpAddress? {
    val t = a.toTcp()
    if (!usableAsDestination(t)) return null
    val b = t.bytes
    return if (isIpv4Mapped(b)) TcpAddress(b.copyOfRange(12, 16), 0) else t
}

/**
 * Whether a connection may go to [t]: not "this network" (0.0.0.0/8, RFC 1122 section 3.2.1.3: "MUST NOT be sent, except
 * as a source address"), the unspecified IPv6 address (RFC 4291 section 2.5.2), multicast (224.0.0.0/4, ff00::/8; RFC 9293
 * section 3.9.1, MUST-46, and no QUIC connection either) or the limited broadcast address, IPv4-mapped forms included.
 * Every resolver's answer is held to it, the system's too ([RequestDns]), and an address literal written in a URL fails
 * ([requireDestination]).
 */
internal fun usableAsDestination(t: TcpAddress): Boolean {
    var b = t.bytes
    if (isIpv4Mapped(b)) b = b.copyOfRange(12, 16)
    if (b.size == 4) {
        val first = b[0].toInt() and 0xff
        return !(first == 0 || first in 224..239 || b.all { it == 0xff.toByte() })
    }
    return !(b.all { it == 0.toByte() } || b[0] == 0xff.toByte())
}

private fun isIpv4Mapped(b: ByteArray): Boolean =
    b.size == 16 && (0 until 10).all { b[it] == 0.toByte() } && b[10] == 0xff.toByte() && b[11] == 0xff.toByte()

/**
 * One call of [lookup] per name, its result (or failure) shared by every caller that asks for that name meanwhile and after;
 * a caller cancelled while its call runs leaves no answer behind, and a caller waiting for it asks again.
 */
internal class OncePerName<T>(
    private val lookup: suspend (String) -> T,
) {
    private val lock = Mutex()
    private val once = HashMap<String, CompletableDeferred<Result<T>>>()

    suspend fun get(name: String): T {
        while (true) {
            var mine = false
            val d =
                lock.withLock {
                    once[name]?.takeUnless { it.isCancelled } ?: CompletableDeferred<Result<T>>().also {
                        mine = true
                        once[name] = it
                    }
                }
            if (mine) {
                d.complete(
                    try {
                        Result.success(lookup(name))
                    } catch (e: CancellationException) {
                        d.cancel()
                        throw e
                    } catch (e: Throwable) {
                        Result.failure(e)
                    },
                )
            }
            val answer =
                try {
                    d.await()
                } catch (e: CancellationException) {
                    currentCoroutineContext().ensureActive() // the caller that asked went away: ask again
                    continue
                }
            return answer.getOrThrow()
        }
    }
}
