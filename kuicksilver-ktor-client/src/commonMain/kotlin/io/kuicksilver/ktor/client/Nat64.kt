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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
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

    /** The IPv4 address [a] embeds at this prefix's length (RFC 6052 section 2.3, extraction), or null when "u" is not zero. */
    fun extract(a: ByteArray): ByteArray? = extractAt(a, length)

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
         * addresses for the WKN's well-known IPv4 addresses ... at the locations specified by [RFC6052], Section 2.2. The
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
                        out += Pref64(a, at.single())
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
 * NAT64 for Happy Eyeballs on an IPv6-only network (RFC 8305 section 7), for platforms that do not translate themselves:
 * "On platforms that do not support 464XLAT, the Happy Eyeballs engine SHOULD follow the recommendations in this section
 * to properly support IPv6-only networks with NAT64 and DNS64."
 *
 * - When: "The features described in this section SHOULD only be enabled when the host detects one of these networks. A
 *   simple heuristic to achieve that is to check if the network offers routable IPv6 addressing, does not offer routable
 *   IPv4 addressing, and offers a DNS resolver address." [ipv6OnlyNetwork] asks the system for a source address of a
 *   global destination of each family (no packet sent): a global IPv6 source and no IPv4 one, or only a link-local one.
 *   A platform that does run 464XLAT (Android's clatd, iOS) has an IPv4 address and route for it, so it is not taken for
 *   such a network and its own translation goes on. The resolver is the one that answers the discovery below.
 * - Pref64::/n: RFC 7050 section 3, an AAAA query for `ipv4only.arpa` ([platformAddressQuery]), every prefix of the answer
 *   in its order ([Pref64.fromIpv4OnlyArpa]). "The node SHALL cache the replies it receives during the Pref64::/n
 *   discovery procedure, and it SHOULD repeat the discovery process ten seconds before the TTL of the Well-Known Name's
 *   synthetic AAAA resource record expires"; after a negative answer "the node MUST obey the Time to Live (TTL) [RFC1035]
 *   of the response before resending the AAAA resource record query" (its SOA's, or [NEGATIVE_TTL] when the platform
 *   hands out records without it, as Apple and Windows do: at least as long as resolvers keep a negative answer). A
 *   failed or timed out query is asked again at the next need (its retries are the system resolver's). [reset] forgets
 *   everything: "when a new network interface is connected to a new network".
 * - Synthesis ([synthesize]): RFC 7050 section 3, "IPv6 addresses MUST be synthesized by using all discovered Pref64::/n
 *   prefixes in the received order", each by RFC 6052 section 2.3.
 */
internal class Nat64(
    private val clock: ExpiryClock = ExpiryClock(),
    private val sourceFor: (TcpAddress) -> TcpAddress? = ::sourceAddressFor,
    private val query: suspend () -> AddressRecords? = { platformAddressQuery(WELL_KNOWN_NAME, DnsMessage.TYPE_AAAA, DISCOVERY_TIMEOUT) },
) {
    private class Discovered(
        val prefixes: List<Pref64>,
        val ttlMillis: Long,
        val at: ExpiryClock.Mark,
    )

    private class Detected(
        val ipv6Only: Boolean,
        val at: ExpiryClock.Mark,
    )

    private val lock = Mutex()

    @Volatile
    private var discovered: Discovered? = null

    @Volatile
    private var detected: Detected? = null

    /** Forgets the network: a new one. */
    fun reset() {
        discovered = null
        detected = null
    }

    /** Whether this host is on an IPv6-only network (the heuristic of section 7), as of at most [DETECT_MILLIS] ago. */
    fun ipv6OnlyNetwork(): Boolean {
        detected?.takeIf { clock.elapsedMillis(it.at) < DETECT_MILLIS }?.let { return it.ipv6Only }
        val v6 = sourceFor(PROBE_V6)
        val v4 = sourceFor(PROBE_V4)
        val routableV6 = v6 != null && isGlobalIpv6(v6)
        val routableV4 = v4 != null && !isLinkLocalOrLoopbackV4(v4)
        return (routableV6 && !routableV4).also { detected = Detected(it, clock.mark()) }
    }

    /**
     * The network's Pref64::/n when this is an IPv6-only network with DNS64 ([ipv6OnlyNetwork] and a positive discovery),
     * empty otherwise: then nothing is synthesized and the IPv4 addresses are used as they are.
     */
    suspend fun prefixes(): List<Pref64> {
        if (!ipv6OnlyNetwork()) return emptyList()
        discovered?.takeIf { fresh(it) }?.let { return it.prefixes }
        return lock.withLock {
            discovered?.takeIf { fresh(it) }?.let { return@withLock it.prefixes }
            val answer =
                try {
                    query()
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    null
                }
            if (answer == null) {
                // failed or timed out: no caching of a failure; a positive discovery still in its TTL goes on serving
                return@withLock discovered?.takeIf { clock.elapsedMillis(it.at) < it.ttlMillis }?.prefixes.orEmpty()
            }
            val prefixes = Pref64.fromIpv4OnlyArpa(answer.addresses.map { it.first })
            val ttlSeconds =
                if (answer.addresses.isEmpty()) {
                    answer.negativeTtl ?: NEGATIVE_TTL.inWholeSeconds
                } else {
                    answer.addresses.minOf { it.second }
                }
            Discovered(prefixes, ttlSeconds * 1000, clock.mark()).also { discovered = it }.prefixes
        }
    }

    /** Whether [d] is still to be used without asking again: positive until ten seconds before its TTL, negative for its TTL. */
    private fun fresh(d: Discovered): Boolean {
        val age = clock.elapsedMillis(d.at)
        return if (d.prefixes.isEmpty()) age < d.ttlMillis else age < d.ttlMillis - REFRESH_BEFORE_MILLIS
    }

    companion object {
        /** RFC 7050 section 2.2, the Well-Known IPv4-only Name. */
        const val WELL_KNOWN_NAME: String = "ipv4only.arpa"

        /** How long the discovery query may take (a request on an IPv6-only network waits for it once per TTL). */
        val DISCOVERY_TIMEOUT: Duration = 2.seconds

        /** A negative answer without its SOA (Apple, Windows) is not asked again within this time (RFC 2308 section 5: "one to three hours"). */
        val NEGATIVE_TTL: Duration = 3.hours

        /** "ten seconds before the TTL ... expires" */
        const val REFRESH_BEFORE_MILLIS: Long = 10_000L

        /** How long one look at the host's routes holds (a network change the engine sees resets it at once). */
        const val DETECT_MILLIS: Long = 5_000L

        /** The process's state: the routes and the resolver are the process's. */
        val system: Nat64 = Nat64()

        /** Tests with a resolver of their own: never an IPv6-only network, whatever the machine is on. */
        fun offForTest(): Nat64 = Nat64(ExpiryClock { 0L }, { null }, { null })

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
    }

    /** [v4] (4 bytes) as the IPv6 addresses of [prefixes], in their order, with [port]. */
    fun synthesize(
        v4: ByteArray,
        prefixes: List<Pref64>,
        port: Int,
    ): List<TcpAddress> = prefixes.map { TcpAddress(it.synthesize(v4), port) }
}
