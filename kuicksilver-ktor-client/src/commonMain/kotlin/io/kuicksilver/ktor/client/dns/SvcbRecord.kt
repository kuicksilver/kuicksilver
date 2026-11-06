// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.dns

import kotlin.random.Random

/** A DNS answer the client cannot use: a server failure, a truncated response, or a malformed message ([DnsFormatException]). */
internal open class DnsException(
    message: String,
) : Exception(message)

/** A DNS message or SVCB RDATA that breaks its wire format (RFC 1035 section 4.1, RFC 9460 section 2.2). */
internal class DnsFormatException(
    message: String,
) : DnsException(message)

/**
 * One SVCB or HTTPS resource record (RFC 9460 section 2.2) as this client reads it.
 *
 * @property priority SvcPriority: 0 is AliasMode, anything else ServiceMode, lower first.
 * @property target TargetName in presentation format, lower case, without the final dot; "." is the root.
 * @property alpn the `alpn` ids (section 7.1.1), each byte as one character (ISO 8859-1), so no id is altered.
 * @property noDefaultAlpn whether `no-default-alpn` is present.
 * @property port the `port` key (section 7.2), or null.
 * @property ipv4Hints the `ipv4hint` addresses (section 7.3), 4 bytes each; checked, not used to connect.
 * @property ipv6Hints the `ipv6hint` addresses, 16 bytes each; checked, not used to connect.
 * @property ttlSeconds the TTL: the smallest of the record's and those of the CNAMEs that led to it.
 * @property owner the record's owner name (after CNAMEs), lower case.
 */
internal class SvcbRecord(
    val priority: Int,
    val target: String,
    val alpn: List<String>,
    val noDefaultAlpn: Boolean,
    val port: Int?,
    val ipv4Hints: List<ByteArray>,
    val ipv6Hints: List<ByteArray>,
    val ttlSeconds: Long,
    val owner: String,
) {
    /** AliasMode (RFC 9460 section 2.4.2). */
    val isAlias: Boolean get() = priority == 0

    /** The host of a ServiceMode endpoint: [target], or [owner] when it is "." (RFC 9460 section 2.5.2). */
    val serviceHost: String get() = if (target == ".") owner else target

    override fun equals(other: Any?): Boolean =
        other is SvcbRecord && priority == other.priority && target == other.target && alpn == other.alpn &&
            noDefaultAlpn == other.noDefaultAlpn && port == other.port && ttlSeconds == other.ttlSeconds && owner == other.owner &&
            sameAddresses(ipv4Hints, other.ipv4Hints) && sameAddresses(ipv6Hints, other.ipv6Hints)

    override fun hashCode(): Int = ((priority * 31 + target.hashCode()) * 31 + alpn.hashCode()) * 31 + (port ?: -1)

    override fun toString(): String =
        "$owner $ttlSeconds HTTPS $priority $target alpn=$alpn${if (noDefaultAlpn) " no-default-alpn" else ""}" +
            (port?.let { " port=$it" } ?: "")

    private fun sameAddresses(
        a: List<ByteArray>,
        b: List<ByteArray>,
    ): Boolean = a.size == b.size && a.indices.all { a[it].contentEquals(b[it]) }
}

/**
 * The SVCB/HTTPS RDATA codec (RFC 9460 section 2.2), sans-IO. Reads only inside the RDATA it is given, and allocates no
 * more than its length.
 */
internal object SvcbCodec {
    private const val KEY_MANDATORY = 0
    private const val KEY_ALPN = 1
    private const val KEY_NO_DEFAULT_ALPN = 2
    private const val KEY_PORT = 3
    private const val KEY_IPV4HINT = 4
    private const val KEY_IPV6HINT = 6

    /** The keys this client supports, so a `mandatory` list may name them (section 8); `ech` (5) is not among them. */
    private val SUPPORTED = setOf(KEY_MANDATORY, KEY_ALPN, KEY_NO_DEFAULT_ALPN, KEY_PORT, KEY_IPV4HINT, KEY_IPV6HINT)

    /** More SvcParams than this in one record: the record is skipped, not read (a bound on the work per record). */
    const val MAX_PARAMS = 64

    /**
     * The record in `b[off until off + len]` of [owner] with [ttl]; null when the record is well-formed but unusable: a
     * `mandatory` key this client does not support (section 8), `no-default-alpn` without `alpn` (section 7.1.1), or more
     * than [MAX_PARAMS] keys. Throws [DnsFormatException] for a malformed record (section 2.2, section 7), which makes the
     * whole RRSet unusable: the caller drops it.
     */
    fun parseRdata(
        b: ByteArray,
        off: Int,
        len: Int,
        owner: String,
        ttl: Long,
    ): SvcbRecord? {
        if (off < 0 || len < 0 || off + len > b.size) throw DnsFormatException("RDATA outside the message")
        val r = DnsReader(b, off, off + len)
        val priority = r.u16()
        // the TargetName MUST NOT be compressed (section 2.2)
        val target = r.name(compression = false)
        // the format of the SvcParams is checked in either mode: keys in strictly increasing order, values inside the RDATA
        val keys = ArrayList<Int>()
        val starts = ArrayList<Int>()
        val lengths = ArrayList<Int>()
        while (r.remaining > 0) {
            val key = r.u16()
            val size = r.u16()
            if (keys.isNotEmpty() && key <= keys.last()) throw DnsFormatException("SvcParamKey $key out of order")
            starts += r.pos
            r.skip(size)
            keys += key
            lengths += size
        }
        // AliasMode: recipients MUST ignore the SvcParams (section 2.4.2)
        if (priority == 0) return SvcbRecord(0, target, emptyList(), false, null, emptyList(), emptyList(), ttl, owner)
        if (keys.size > MAX_PARAMS) return null
        var mandatory: List<Int> = emptyList()
        var alpn: List<String> = emptyList()
        var noDefaultAlpn = false
        var port: Int? = null
        var ipv4: List<ByteArray> = emptyList()
        var ipv6: List<ByteArray> = emptyList()
        for (i in keys.indices) {
            val s = starts[i]
            val n = lengths[i]
            when (keys[i]) {
                KEY_MANDATORY -> {
                    mandatory = mandatoryKeys(b, s, n)
                }

                KEY_ALPN -> {
                    alpn = alpnIds(b, s, n)
                }

                KEY_NO_DEFAULT_ALPN -> {
                    if (n != 0) throw DnsFormatException("no-default-alpn with a value") else noDefaultAlpn = true
                }

                KEY_PORT -> {
                    if (n != 2) throw DnsFormatException("port of $n bytes") else port = DnsReader(b, s, s + 2).u16()
                }

                KEY_IPV4HINT -> {
                    ipv4 = addresses(b, s, n, 4)
                }

                KEY_IPV6HINT -> {
                    ipv6 = addresses(b, s, n, 16)
                }

                else -> {} // ech and the keys this client does not know: ignored unless mandatory (below)
            }
        }
        // every key the mandatory list names must be in the record (section 8)
        for (k in mandatory) if (k !in keys) throw DnsFormatException("mandatory key $k missing")
        if (mandatory.any { it !in SUPPORTED }) return null
        if (noDefaultAlpn && alpn.isEmpty()) return null
        return SvcbRecord(priority, target, alpn, noDefaultAlpn, port, ipv4, ipv6, ttl, owner)
    }

    /** `mandatory` (section 8): a non-empty list of keys in strictly increasing order, never naming itself. */
    private fun mandatoryKeys(
        b: ByteArray,
        s: Int,
        n: Int,
    ): List<Int> {
        if (n == 0 || n % 2 != 0) throw DnsFormatException("mandatory of $n bytes")
        val r = DnsReader(b, s, s + n)
        val out = ArrayList<Int>(n / 2)
        while (r.remaining > 0) {
            val k = r.u16()
            if (k == KEY_MANDATORY) throw DnsFormatException("mandatory lists itself")
            if (out.isNotEmpty() && k <= out.last()) throw DnsFormatException("mandatory keys out of order")
            out += k
        }
        return out
    }

    /** `alpn` (section 7.1.1): one or more non-empty length-prefixed ids that fill the value exactly. */
    private fun alpnIds(
        b: ByteArray,
        s: Int,
        n: Int,
    ): List<String> {
        if (n == 0) throw DnsFormatException("empty alpn")
        val r = DnsReader(b, s, s + n)
        val out = ArrayList<String>()
        while (r.remaining > 0) {
            val l = r.u8()
            if (l == 0) throw DnsFormatException("empty alpn-id")
            val at = r.pos
            r.skip(l)
            out += CharArray(l) { (b[at + it].toInt() and 0xff).toChar() }.concatToString()
        }
        return out
    }

    /** `ipv4hint`/`ipv6hint` (section 7.3): one or more addresses of [size] bytes. */
    private fun addresses(
        b: ByteArray,
        s: Int,
        n: Int,
        size: Int,
    ): List<ByteArray> {
        if (n == 0 || n % size != 0) throw DnsFormatException("address hint of $n bytes")
        return List(n / size) { b.copyOfRange(s + it * size, s + (it + 1) * size) }
    }
}

/**
 * A bounds-checked cursor over `b[start until end]` of a DNS message (RFC 1035 section 4.1); every read checks the bounds
 * first and fails with [DnsFormatException]. Names may use compression pointers into the whole of [b] when allowed: each
 * must point strictly before the pointer, and a name follows at most [MAX_POINTERS] of them.
 */
internal class DnsReader(
    private val b: ByteArray,
    start: Int,
    private val end: Int,
) {
    var pos: Int = start
        private set

    val remaining: Int get() = end - pos

    fun u8(): Int {
        need(1)
        return b[pos++].toInt() and 0xff
    }

    fun u16(): Int {
        need(2)
        val v = (b[pos].toInt() and 0xff) shl 8 or (b[pos + 1].toInt() and 0xff)
        pos += 2
        return v
    }

    fun u32(): Long {
        need(4)
        var v = 0L
        repeat(4) { v = v shl 8 or (b[pos + it].toLong() and 0xff) }
        pos += 4
        return v
    }

    fun skip(n: Int) {
        need(n)
        pos += n
    }

    private fun need(n: Int) {
        if (n < 0 || n > end - pos) throw DnsFormatException("truncated")
    }

    /**
     * A domain name in presentation format, lower case, without the final dot ("." for the root). Bytes other than
     * letters, digits, `-` and `_` are written `\DDD`, so a label holding a dot cannot pass for two labels.
     */
    fun name(compression: Boolean): String {
        val sb = StringBuilder()
        var p = pos
        var limit = end // the first pointer leaves the record's bounds: a target is anywhere earlier in the message
        var jumps = 0
        var wire = 1 // the name's wire length, the root label included (at most 255)
        var resume = -1
        while (true) {
            if (p >= limit) throw DnsFormatException("truncated name")
            val l = b[p].toInt() and 0xff
            when {
                l == 0 -> {
                    p++
                    break
                }

                l and 0xc0 == 0xc0 -> {
                    if (!compression) throw DnsFormatException("compressed name where none is allowed")
                    if (p + 1 >= limit) throw DnsFormatException("truncated pointer")
                    val to = (l and 0x3f) shl 8 or (b[p + 1].toInt() and 0xff)
                    if (to >= p) throw DnsFormatException("compression pointer that does not point back")
                    if (++jumps > MAX_POINTERS) throw DnsFormatException("too many compression pointers")
                    if (resume < 0) resume = p + 2
                    p = to
                    limit = b.size
                }

                l and 0xc0 != 0 -> {
                    throw DnsFormatException("label type ${l shr 6}")
                }

                else -> {
                    wire += l + 1
                    if (wire > MAX_NAME) throw DnsFormatException("name over $MAX_NAME bytes")
                    if (p + 1 + l > limit) throw DnsFormatException("truncated label")
                    if (sb.isNotEmpty()) sb.append('.')
                    for (i in p + 1..p + l) appendLabelByte(sb, b[i].toInt() and 0xff)
                    p += l + 1
                }
            }
        }
        pos = if (resume >= 0) resume else p
        return if (sb.isEmpty()) "." else sb.toString()
    }

    private fun appendLabelByte(
        sb: StringBuilder,
        c: Int,
    ) {
        when (c) {
            in 'a'.code..'z'.code, in '0'.code..'9'.code, '-'.code, '_'.code -> sb.append(c.toChar())
            in 'A'.code..'Z'.code -> sb.append((c + 32).toChar())
            else -> sb.append('\\').append(c.toString().padStart(3, '0'))
        }
    }

    companion object {
        /** RFC 1035 section 2.3.4. */
        const val MAX_NAME = 255
        const val MAX_LABEL = 63

        /** A bound on the pointers one name may follow; a legitimate name needs one per label at most. */
        const val MAX_POINTERS = 128
    }
}

/**
 * The name to ask for the HTTPS records of `https://host:port` (RFC 9460 section 9.1): the host for port 443, else
 * `_<port>._https.<host>`; lower case, without a final dot.
 */
internal fun httpsQueryName(
    host: String,
    port: Int,
): String {
    val h = host.trimEnd('.').lowercase()
    return if (port == 443) h else "_$port._https.$h"
}

/**
 * The ServiceMode record to try HTTP/3 with: the one with the lowest SvcPriority whose `alpn` has `h3` and whose
 * endpoint is a host name; null when there is none, or when the RRSet has an AliasMode record (its ServiceMode records
 * are then ignored, RFC 9460 section 2.4.1).
 */
internal fun pickH3(records: List<SvcbRecord>): SvcbRecord? {
    if (records.any { it.isAlias }) return null
    return records.filter { "h3" in it.alpn && isHostName(it.serviceHost) }.minByOrNull { it.priority }
}

/**
 * The TargetName of the RRSet's AliasMode record, one picked at random when there are several (RFC 9460 section
 * 2.4.2); "." means the service does not exist (section 2.5.1); null when the RRSet has none.
 */
internal fun aliasTarget(
    records: List<SvcbRecord>,
    random: Random = Random,
): String? {
    val aliases = records.filter { it.isAlias }
    return if (aliases.isEmpty()) null else aliases[random.nextInt(aliases.size)].target
}

/** A name a socket can connect to: letters, digits, `-` and `_` in dot-separated labels (no `\DDD` escapes). */
internal fun isHostName(name: String): Boolean = name != "." && name.isNotEmpty() && '\\' !in name
