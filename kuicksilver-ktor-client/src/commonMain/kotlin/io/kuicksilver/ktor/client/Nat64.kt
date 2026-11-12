// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.kuicksilver.ktor.client.dns.DnsException
import io.kuicksilver.ktor.client.dns.DnsFormatException
import io.kuicksilver.ktor.client.dns.DnsMessage
import io.kuicksilver.ktor.client.dns.DnsReader
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.ktor.network.sourceAddressFor
import io.kuicksilver.tls.KslDns
import io.kuicksilver.tls.KslDnsAnswer
import io.kuicksilver.tls.KslNet
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.concurrent.Volatile
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

/**
 * A NAT64 prefix (Pref64::/n of RFC 7050) of one of the lengths RFC 6052 section 2.2 allows: "The prefixes can only have
 * one of the following lengths: 32, 40, 48, 56, 64, or 96."
 */
internal class Pref64(
    prefix: ByteArray,
    val length: Int,
) {
    private val bytes: ByteArray = ByteArray(16).also { prefix.copyInto(it, 0, 0, minOf(prefix.size, length / 8)) }

    init {
        require(length in LENGTHS) { "a NAT64 prefix is /32, /40, /48, /56, /64 or /96, not /$length" }
    }

    /**
     * The IPv4-embedded IPv6 address of [v4] (RFC 6052 section 2.3): "Concatenate the prefix, the 32 bits of the IPv4
     * address, and the suffix (if needed) to obtain a 128-bit address", with the octet "u" (bits 64 to 71) zero: "If the
     * prefix length is less than 96 bits, insert the null octet "u" at the appropriate position (bits 64 to 71)". The
     * suffix is zero ("These bits are reserved for future extensions and SHOULD be set to zero").
     */
    fun synthesize(v4: ByteArray): ByteArray {
        require(v4.size == 4) { "an IPv4 address has 4 bytes" }
        val out = bytes.copyOf()
        var at = length / 8
        for (b in v4) {
            if (at == 8) at++ // the "u" octet stays zero
            out[at++] = b
        }
        return out
    }

    /** Whether the IPv6 address [a] lies under this prefix. */
    fun covers(a: ByteArray): Boolean = a.size == 16 && (0 until length / 8).all { a[it] == bytes[it] }

    /** The IPv4 address [a] embeds at this prefix's length (RFC 6052 section 2.3, extraction), or null when "u" is not zero. */
    fun extract(a: ByteArray): ByteArray? = extractAt(a, length)

    /**
     * Whether this prefix may be used: a global unicast prefix (`2000::/3`), the Well-Known Prefix `64:ff9b::/96` or one
     * of the local-use `64:ff9b:1::/48` (RFC 8215). A DNS64 answer naming anything else (a link-local or loopback prefix,
     * IPv4-mapped space) would send IPv4 traffic somewhere no NAT64 is.
     */
    fun plausible(): Boolean {
        val b0 = bytes[0].toInt() and 0xff
        if (b0 and 0xe0 == 0x20) return true
        if (this == WELL_KNOWN) return true
        val localUse = byteArrayOf(0, 0x64, 0xff.toByte(), 0x9b.toByte(), 0, 1)
        return length >= 48 && (0 until 6).all { bytes[it] == localUse[it] }
    }

    override fun equals(other: Any?): Boolean = other is Pref64 && other.length == length && other.bytes.contentEquals(bytes)

    override fun hashCode(): Int = bytes.contentHashCode() * 31 + length

    override fun toString(): String = "${TcpAddress(bytes, 0).hostText}/$length"

    companion object {
        val LENGTHS: List<Int> = listOf(32, 40, 48, 56, 64, 96)

        /** The Well-Known Prefix of RFC 6052 section 2.1, `64:ff9b::/96`. */
        val WELL_KNOWN: Pref64 = Pref64(byteArrayOf(0, 0x64, 0xff.toByte(), 0x9b.toByte()), 96)

        /** "For the other prefix lengths, remove the "u" octet ... then extract the 32 bits following the prefix." */
        fun extractAt(
            a: ByteArray,
            length: Int,
        ): ByteArray? {
            if (a.size != 16 || length !in LENGTHS) return null
            if (length < 96 && a[8].toInt() != 0) return null // "These bits MUST be set to zero."
            val out = ByteArray(4)
            var at = length / 8
            for (i in 0 until 4) {
                if (at == 8) at++
                out[i] = a[at++]
            }
            return out
        }

        /** The well-known IPv4 addresses of `ipv4only.arpa` (RFC 7050 section 2.2): 192.0.0.170 and 192.0.0.171. */
        private val WKA: List<ByteArray> =
            listOf(byteArrayOf(192.toByte(), 0, 0, 170.toByte()), byteArrayOf(192.toByte(), 0, 0, 171.toByte()))

        /**
         * The Pref64::/n of [aaaa], the IPv6 addresses an AAAA query for `ipv4only.arpa` returned, in their order and once
         * each (RFC 7050 section 3): "the node SHALL determine the used address format by searching the received IPv6
         * addresses for the WKN's well-known IPv4 addresses ... at the locations specified by \[RFC6052\], Section 2.2. The
         * node MUST check on octet boundaries to ensure a 32-bit well-known IPv4 address value is present only once in an
         * IPv6 address. In case another instance of the value is found inside the IPv6 address, the node SHALL repeat the
         * search with the other well-known IPv4 address." An address where neither is found once at a single location
         * gives none ("the Pref64::/n cannot be determined").
         */
        fun fromIpv4OnlyArpa(aaaa: List<ByteArray>): List<Pref64> {
            val out = LinkedHashSet<Pref64>()
            for (a in aaaa) {
                if (a.size != 16) continue
                for (wka in WKA) {
                    if (occurrences(a, wka) > 1) continue
                    val at = LENGTHS.filter { extractAt(a, it)?.contentEquals(wka) == true }
                    if (at.size == 1) {
                        Pref64(a, at.single()).takeIf { it.plausible() }?.let { out += it }
                        break
                    }
                }
            }
            return out.toList()
        }

        /** How often [v] occurs in [a] on octet boundaries, also across the "u" octet (as the encodings place it). */
        private fun occurrences(
            a: ByteArray,
            v: ByteArray,
        ): Int {
            var n = 0
            for (i in 0..a.size - 4) if ((0 until 4).all { a[i + it] == v[it] }) n++
            for (length in listOf(40, 48, 56)) if (extractAt(a, length)?.contentEquals(v) == true) n++
            return n
        }
    }
}

/** An answer to an address query: the addresses with their TTLs, or none with the negative-caching TTL when known. */
internal class AddressRecords(
    val addresses: List<Pair<ByteArray, Long>>,
    val negativeTtl: Long? = null,
)

/**
 * The A ([DnsMessage.TYPE_A]) or AAAA records of [qname] in the response [msg] (RFC 1035 section 4.1), after its CNAMEs;
 * the negative-caching TTL from the SOA of an answer without them (RFC 2308 section 5). Throws [DnsException] for a
 * truncated response or an RCODE other than NOERROR and NXDOMAIN, [DnsFormatException] for a malformed message.
 */
internal fun addressRecordsOf(
    msg: ByteArray,
    qname: String,
    type: Int,
): AddressRecords {
    if (msg.size > DnsMessage.MAX_MESSAGE) throw DnsFormatException("a message of ${msg.size} bytes")
    val want = qname.trimEnd('.').lowercase()
    val r = DnsReader(msg, 0, msg.size)
    r.u16()
    val flags = r.u16()
    val qd = r.u16()
    val an = r.u16()
    val ns = r.u16()
    if (flags and 0x8000 == 0) throw DnsFormatException("not a response")
    if (qd != 1) throw DnsFormatException("$qd questions")
    r.u16()
    if (r.name(compression = true) != want || r.u16() != type || r.u16() != 1) throw DnsFormatException("the answer to another question")
    val cnames = HashMap<String, String>()
    val found = HashMap<String, MutableList<Pair<ByteArray, Long>>>()
    var negativeTtl: Long? = null
    val size = if (type == DnsMessage.TYPE_AAAA) 16 else 4
    for (section in 0 until 2) {
        repeat(if (section == 0) an else ns) {
            val owner = r.name(compression = true)
            val t = r.u16()
            val c = r.u16()
            val ttl = r.u32().let { if (it > Int.MAX_VALUE) 0L else it } // RFC 2181 section 8
            val len = r.u16()
            val at = r.pos
            r.skip(len)
            if (c != 1) return@repeat
            when {
                section == 0 && t == type && len == size -> {
                    found.getOrPut(owner) { ArrayList() } += msg.copyOfRange(at, at + len) to ttl
                }

                section == 0 && t == DnsMessage.TYPE_CNAME -> {
                    cnames.getOrPut(owner) { DnsReader(msg, at, at + len).name(compression = true) }
                }

                section == 1 && t == DnsMessage.TYPE_SOA -> {
                    val soa = DnsReader(msg, at, at + len)
                    soa.name(compression = true)
                    soa.name(compression = true)
                    repeat(4) { soa.u32() }
                    negativeTtl = minOf(ttl, soa.u32().let { if (it > Int.MAX_VALUE) 0L else it })
                }
            }
        }
    }
    if (flags and 0x0200 != 0) throw DnsException("truncated response (TC)")
    val rcode = flags and 0xf
    if (rcode != 0 && rcode != 3) throw DnsException("RCODE $rcode")
    var name = want
    var hops = 0
    while (name !in found && hops++ < 16) name = cnames[name] ?: break
    return AddressRecords(if (rcode == 3) emptyList() else found[name].orEmpty(), negativeTtl)
}

/** The A or AAAA records of [name] in an answer of the system resolver ([KslDns]); null when it cannot be used. */
internal fun addressRecordsOf(
    answer: KslDnsAnswer,
    name: String,
    type: Int,
): AddressRecords? =
    try {
        when (answer) {
            is KslDnsAnswer.Message -> {
                addressRecordsOf(answer.bytes, name, type)
            }

            is KslDnsAnswer.Records -> {
                val size = if (type == DnsMessage.TYPE_AAAA) 16 else 4
                // a record list carries no SOA: a negative answer comes without its TTL
                AddressRecords(
                    answer.records.filter { it.rdata.size == size }.map {
                        it.rdata to
                            it.ttlSeconds.coerceIn(0, Int.MAX_VALUE.toLong())
                    },
                )
            }
        }
    } catch (_: DnsException) {
        null
    }

/**
 * The [type] records of [name] from the system resolver within [timeout] (RFC 7050 discovery: AAAA of `ipv4only.arpa`),
 * with their TTLs: `ksl_dns_query` on the JVM and Kotlin/Native, `DnsResolver` on Android (API 29 and up). Null when the
 * lookup failed or cannot be made here.
 */
internal expect suspend fun platformAddressQuery(
    name: String,
    type: Int,
    timeout: Duration,
): AddressRecords?

/**
 * The network's NAT64 prefixes as the platform knows them (Android, API 30: `LinkProperties.getNat64Prefix` when the
 * application gave the engine a `ConnectivityManager`), or null when it cannot tell: then RFC 7050 discovery.
 */
internal expect fun platformNat64Prefixes(): List<Pref64>?

/**
 * NAT64 for Happy Eyeballs on an IPv6-only network (RFC 8305 section 7), for platforms that do not translate themselves:
 * "On platforms that do not support 464XLAT, the Happy Eyeballs engine SHOULD follow the recommendations in this section
 * to properly support IPv6-only networks with NAT64 and DNS64."
 *
 * - The network ([ipv6OnlyNetwork]): "The features described in this section SHOULD only be enabled when the host detects
 *   one of these networks. A simple heuristic to achieve that is to check if the network offers routable IPv6 addressing,
 *   does not offer routable IPv4 addressing, and offers a DNS resolver address.": a global IPv6 source address for a
 *   global destination and no IPv4 one (or only a link-local one), asked of the system without sending a packet. A
 *   platform that runs 464XLAT has an IPv4 address and route and is not taken for such a network.
 * - The destination ([synthesize]): an IPv4 address is synthesized only when the host has no route to it (a VPN's or a
 *   LAN's IPv4 routes stay in use), never a loopback, link-local, multicast or "this network" address, and never a
 *   non-global one with the Well-Known Prefix (RFC 6052 section 3.1: "The Well-Known Prefix MUST NOT be used to represent
 *   non-global IPv4 addresses"). Without a prefix the address is handed out as it is.
 * - The prefixes: the platform's own where it synthesizes ([platformSynthesize]: Apple's `getaddrinfo` with
 *   `AI_DEFAULT`) or tells them ([platformPrefixes]: Android's `LinkProperties.getNat64Prefix`), else RFC 7050 section 3, an AAAA query for `ipv4only.arpa` ([query]), made only when an address needs
 *   synthesis, one at a time however many requests need it. Every plausible prefix of the answer is used, in its order
 *   ("IPv6 addresses MUST be synthesized by using all discovered Pref64::/n prefixes in the received order"; section 3.2:
 *   "simply attempt to use the learned Pref64::/n", which the race does). "The node SHALL cache the replies ... and it
 *   SHOULD repeat the discovery process ten seconds before the TTL of the Well-Known Name's synthetic AAAA resource record
 *   expires": the cached prefixes keep serving while a refresh runs in the background, a TTL counts as at least
 *   [MIN_TTL]; a negative answer is not asked again within its TTL ("MUST obey the Time to Live") or [NEGATIVE_TTL] where
 *   the platform hands out records without the SOA; a failed or timed out query is not asked again for [FAILURE_BACKOFF].
 *   The prefixes belong to the network they were learnt on: a change of the host's IPv6 /64 drops them, as does [reset]
 *   ("when a new network interface is connected to a new network").
 */
internal class Nat64(
    private val clock: ExpiryClock = ExpiryClock(),
    private val sourceFor: (TcpAddress) -> TcpAddress? = ::sourceAddressFor,
    private val query: suspend () -> AddressRecords? = { platformAddressQuery(WELL_KNOWN_NAME, DnsMessage.TYPE_AAAA, DISCOVERY_TIMEOUT) },
    private val platformSynthesize: (ByteArray) -> List<ByteArray>? = KslNet::nat64Synthesize,
    private val platformPrefixes: () -> List<Pref64>? = ::platformNat64Prefixes,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
) {
    private class Discovered(
        val prefixes: List<Pref64>,
        val ttlMillis: Long,
        val at: ExpiryClock.Mark,
        /** The first 64 bits of the host's IPv6 source address when they were learnt. */
        val network: List<Byte>?,
    )

    private class Detected(
        val ipv6Only: Boolean,
        val network: List<Byte>?,
        val at: ExpiryClock.Mark,
    )

    private val lock = Mutex()

    @Volatile
    private var discovered: Discovered? = null

    @Volatile
    private var failedAt: ExpiryClock.Mark? = null

    @Volatile
    private var detected: Detected? = null

    private var inFlight: Deferred<Unit>? = null

    /** Forgets the network: a new one. */
    fun reset() {
        discovered = null
        detected = null
        failedAt = null
    }

    private fun detect(): Detected {
        detected?.takeIf { clock.elapsedMillis(it.at) < DETECT_MILLIS }?.let { return it }
        val v6 = sourceFor(PROBE_V6)
        val v4 = sourceFor(PROBE_V4)
        val routableV6 = v6 != null && isGlobalIpv6(v6)
        val routableV4 = v4 != null && !isLinkLocalOrLoopbackV4(v4)
        return Detected(routableV6 && !routableV4, v6?.bytes?.copyOf(8)?.toList(), clock.mark()).also { detected = it }
    }

    /** Whether this host is on an IPv6-only network (the heuristic of section 7), as of at most [DETECT_MILLIS] ago. */
    fun ipv6OnlyNetwork(): Boolean = detect().ipv6Only

    /**
     * [v4] (4 bytes) for a connection with [port]: the IPv6 addresses synthesized for it when this is an IPv6-only network
     * and the host has no route to it, else [v4] itself (also when no prefix is known).
     */
    suspend fun synthesize(
        v4: ByteArray,
        port: Int,
    ): List<TcpAddress> {
        val native = listOf(TcpAddress(v4, port))
        if (!ipv6OnlyNetwork() || !synthesizable(v4) || sourceFor(TcpAddress(v4, 9)) != null) return native
        val global = isGlobalV4(v4)
        platformSynthesize(v4)?.let { own ->
            // the platform's own synthesis obeys RFC 6052 section 3.1 too: no non-global address under 64:ff9b::/96
            val allowed = own.filter { global || !Pref64.WELL_KNOWN.covers(it) }
            return allowed.map { TcpAddress(it, port) }.ifEmpty { native }
        }
        val known = platformPrefixes()?.filter { it.plausible() }?.takeIf { it.isNotEmpty() } ?: prefixes()
        val usable = known.filter { global || it != Pref64.WELL_KNOWN }
        return usable.map { TcpAddress(it.synthesize(v4), port) }.ifEmpty { native }
    }

    /**
     * The network's Pref64::/n learnt by RFC 7050 discovery (empty: none, or not known yet after a failure). A fresh answer is
     * used at once; one in its last ten seconds is used while a refresh runs; without one the caller waits for the query
     * in flight, which no caller's cancellation stops.
     */
    suspend fun prefixes(): List<Pref64> {
        val wait =
            lock.withLock {
                val network = detect().network
                val d = discovered?.takeIf { it.network == network } ?: null.also { discovered = null }
                val age = d?.let { clock.elapsedMillis(it.at) }
                when {
                    d != null && age!! < d.ttlMillis - (if (d.prefixes.isEmpty()) 0 else REFRESH_BEFORE_MILLIS) -> {
                        return d.prefixes
                    }

                    failedAt?.let { clock.elapsedMillis(it) < FAILURE_BACKOFF.inWholeMilliseconds } == true -> {
                        return d?.takeIf { age!! < it.ttlMillis }?.prefixes.orEmpty()
                    }
                }
                val job = inFlight ?: scope.async { discover(network) }.also { inFlight = it }
                // a positive answer still in its TTL serves while the refresh runs
                if (d != null && d.prefixes.isNotEmpty() && age!! < d.ttlMillis) return d.prefixes
                job
            }
        wait.await()
        return lock.withLock { discovered?.prefixes.orEmpty() }
    }

    private suspend fun discover(network: List<Byte>?) {
        val answer =
            try {
                query()
            } catch (e: CancellationException) {
                withContext(NonCancellable) { lock.withLock { inFlight = null } }
                throw e
            } catch (_: Exception) {
                null
            }
        lock.withLock {
            inFlight = null
            if (answer == null) {
                failedAt = clock.mark()
                return
            }
            failedAt = null
            val prefixes = Pref64.fromIpv4OnlyArpa(answer.addresses.map { it.first })
            val ttlSeconds =
                if (answer.addresses.isEmpty()) {
                    answer.negativeTtl ?: NEGATIVE_TTL.inWholeSeconds
                } else {
                    maxOf(answer.addresses.minOf { it.second }, MIN_TTL.inWholeSeconds)
                }
            discovered = Discovered(prefixes, ttlSeconds * 1000, clock.mark(), network)
        }
    }

    companion object {
        /** RFC 7050 section 2.2, the Well-Known IPv4-only Name. */
        const val WELL_KNOWN_NAME: String = "ipv4only.arpa"

        /** How long the discovery query may take. */
        val DISCOVERY_TIMEOUT: Duration = 2.seconds

        /** A negative answer without its SOA (Apple, Windows) is not asked again within this time (RFC 2308 section 5: "one to three hours"). */
        val NEGATIVE_TTL: Duration = 3.hours

        /** The shortest life of a positive answer: a TTL of a few seconds would otherwise mean a query per request. */
        val MIN_TTL: Duration = 60.seconds

        /** After a failed or timed out query, no new one for this long (the system resolver already retried it). */
        val FAILURE_BACKOFF: Duration = 30.seconds

        /** "ten seconds before the TTL ... expires" */
        const val REFRESH_BEFORE_MILLIS: Long = 10_000L

        /** How long one look at the host's routes holds (a network change the engine sees resets it at once). */
        const val DETECT_MILLIS: Long = 5_000L

        /** The process's state: the routes and the resolver are the process's. */
        val system: Nat64 = Nat64()

        /** Tests with a resolver of their own: never an IPv6-only network, whatever the machine is on. */
        fun offForTest(): Nat64 = Nat64(ExpiryClock { 0L }, { null }, { null }, { null }, { null })

        // global destinations only to ask the routing table: a connected UDP socket sends nothing
        private val PROBE_V6 =
            TcpAddress(byteArrayOf(0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88.toByte(), 0x88.toByte()), 53)
        private val PROBE_V4 = TcpAddress(byteArrayOf(8, 8, 8, 8), 53)

        /** A global unicast IPv6 address (`2000::/3`): "routable IPv6 addressing". */
        internal fun isGlobalIpv6(a: TcpAddress): Boolean = a.isIpv6 && (a.bytes[0].toInt() and 0xe0) == 0x20

        private fun isLinkLocalOrLoopbackV4(a: TcpAddress): Boolean {
            val b = a.bytes
            if (b.size != 4) return true
            val b0 = b[0].toInt() and 0xff
            return b0 == 127 || (b0 == 169 && (b[1].toInt() and 0xff) == 254)
        }

        /** Not "this network" (0/8), loopback (127/8), link-local (169.254/16), multicast or reserved (224/3): never synthesized. */
        internal fun synthesizable(v4: ByteArray): Boolean {
            val b0 = v4[0].toInt() and 0xff
            val b1 = v4[1].toInt() and 0xff
            return b0 != 0 && b0 != 127 && !(b0 == 169 && b1 == 254) && b0 < 224
        }

        /**
         * Whether [v4] is global (RFC 6052 section 3.1 forbids the Well-Known Prefix for the others): not one of the
         * special-use blocks of RFC 5735 section 3 nor RFC 6598's shared address space.
         */
        internal fun isGlobalV4(v4: ByteArray): Boolean {
            val b0 = v4[0].toInt() and 0xff
            val b1 = v4[1].toInt() and 0xff
            val b2 = v4[2].toInt() and 0xff
            return !(
                b0 == 0 || b0 == 10 || b0 == 127 || b0 >= 224 ||
                    (b0 == 100 && b1 in 64..127) ||
                    (b0 == 169 && b1 == 254) ||
                    (b0 == 172 && b1 in 16..31) ||
                    (b0 == 192 && b1 == 0 && (b2 == 0 || b2 == 2)) ||
                    (b0 == 192 && b1 == 168) ||
                    (b0 == 198 && (b1 == 18 || b1 == 19)) ||
                    (b0 == 198 && b1 == 51 && b2 == 100) ||
                    (b0 == 203 && b1 == 0 && b2 == 113)
            )
        }
    }
}
