// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.dns

/**
 * What a DNS response says for the HTTPS record client ([DnsMessage.read]).
 *
 * @property records the RRset of the name asked for, after CNAMEs (empty: none).
 * @property negativeTtl how long "none" may be cached (RFC 2308 section 5), null when the response gives no SOA.
 * @property related other HTTPS RRsets of the response, by owner (an alias target's, for example).
 * @property addresses A and AAAA addresses of the response by owner, 4 or 16 bytes each, with their smallest TTL.
 */
internal class DnsAnswer(
    val records: List<SvcbRecord>,
    val negativeTtl: Long? = null,
    val related: Map<String, List<SvcbRecord>> = emptyMap(),
    val addresses: Map<String, Pair<List<ByteArray>, Long>> = emptyMap(),
)

/**
 * DNS messages for the HTTPS records (RFC 1035 section 4.1), sans-IO: the query and the records of its answer.
 */
internal object DnsMessage {
    const val TYPE_A = 1
    const val TYPE_SOA = 6
    const val TYPE_CNAME = 5
    const val TYPE_AAAA = 28
    const val TYPE_HTTPS = 65
    private const val CLASS_IN = 1
    private const val RCODE_NXDOMAIN = 3

    /** CNAMEs followed at most inside one answer; a longer chain or a loop leaves the name without records. */
    private const val MAX_CNAMES = 16

    /**
     * A recursive query for [name]/[type] in class IN: ID 0 (RFC 8484 section 4.1 asks for it in DNS over HTTPS; a system
     * resolver sets its own), RD set, one question, no other section. Throws [IllegalArgumentException] for a name that is
     * empty, has an empty label, a label over 63 bytes or is over 255 bytes in wire format.
     */
    fun query(
        name: String,
        type: Int = TYPE_HTTPS,
    ): ByteArray {
        val labels = name.trimEnd('.').split('.')
        require(labels.all { it.isNotEmpty() && it.length <= DnsReader.MAX_LABEL && it.all { c -> c.code in 0x21..0x7e } }) {
            "not a DNS name: $name"
        }
        val wire = labels.sumOf { it.length + 1 } + 1
        require(wire <= DnsReader.MAX_NAME) { "a DNS name of $wire bytes: $name" }
        val out = ByteArray(12 + wire + 4)
        out[2] = 0x01 // RD
        out[5] = 1 // QDCOUNT
        var p = 12
        for (l in labels) {
            out[p++] = l.length.toByte()
            for (c in l) out[p++] = c.code.toByte()
        }
        out[p++] = 0
        out[p++] = (type shr 8).toByte()
        out[p++] = type.toByte()
        out[p++] = 0
        out[p] = CLASS_IN.toByte()
        return out
    }

    /**
     * The records of type [type] that answer [qname] in the response [msg], after the CNAME chain the answer section gives
     * for it; each record's TTL is the smallest along the chain. NXDOMAIN and an answer without them (NODATA) give an
     * empty list. Throws [DnsException] for a truncated response or another RCODE, and [DnsFormatException] for a message
     * that breaks the wire format, one that is not the response to that question, or a malformed record in the RRSet
     * (RFC 9460 section 2.2: the client rejects the whole RRSet).
     */
    fun answers(
        msg: ByteArray,
        qname: String,
        type: Int = TYPE_HTTPS,
    ): List<SvcbRecord> = read(msg, qname, type).records

    /**
     * Everything in the response [msg] to [qname]/[type] that the HTTPS record client uses: the records of the name after
     * its CNAME chain ([answers]), the negative-caching TTL of an answer without them (RFC 2308 section 5: the smaller of
     * the SOA record's TTL and its MINIMUM, null without an SOA in the authority section), and the other records of
     * [type] and the A/AAAA records the answer and additional sections carry for other names (RFC 9460 section 5: they
     * "SHOULD be placed in cache before performing any follow-up queries"; an RRset of [type] that is malformed is left
     * out, section 2.2). Throws as [answers].
     */
    fun read(
        msg: ByteArray,
        qname: String,
        type: Int = TYPE_HTTPS,
    ): DnsAnswer {
        val r = DnsReader(msg, 0, msg.size)
        r.u16() // ID: matched by the transport (the system resolver, or the DoH exchange that carried it)
        val flags = r.u16()
        val qd = r.u16()
        val an = r.u16()
        val ns = r.u16()
        val ar = r.u16()
        if (flags and 0x8000 == 0) throw DnsFormatException("not a response")
        if ((flags shr 11) and 0xf != 0) throw DnsFormatException("opcode ${(flags shr 11) and 0xf}")
        val want = normalize(qname)
        if (qd != 1) throw DnsFormatException("$qd questions")
        val qn = r.name(compression = true)
        val qt = r.u16()
        val qc = r.u16()
        if (qn != want || qt != type || qc != CLASS_IN) throw DnsFormatException("the answer to another question ($qn $qt)")
        val cnames = HashMap<String, Pair<String, Long>>()
        val found = ArrayList<Triple<String, Long, IntRange>>() // owner, TTL, RDATA of [type], answer and additional sections
        val addresses = LinkedHashMap<String, MutableList<Pair<ByteArray, Long>>>()
        var negativeTtl: Long? = null
        for (section in 0 until 3) {
            val count =
                if (section == 0) {
                    an
                } else if (section == 1) {
                    ns
                } else {
                    ar
                }
            repeat(count) {
                val owner = r.name(compression = true)
                val t = r.u16()
                val c = r.u16()
                val ttl = r.u32().let { if (it > Int.MAX_VALUE) 0L else it } // RFC 2181 section 8: a TTL with the top bit set is 0
                val len = r.u16()
                val at = r.pos
                r.skip(len)
                if (c != CLASS_IN) return@repeat
                when {
                    section == 1 && t == TYPE_SOA -> {
                        val soa = DnsReader(msg, at, at + len)
                        soa.name(compression = true)
                        soa.name(compression = true)
                        repeat(4) { soa.u32() }
                        val minimum = soa.u32().let { if (it > Int.MAX_VALUE) 0L else it }
                        negativeTtl = minOf(ttl, minimum)
                    }

                    section == 1 -> {}

                    t == type -> {
                        found += Triple(owner, ttl, at until at + len)
                    }

                    t == TYPE_CNAME && section == 0 -> {
                        val target = DnsReader(msg, at, at + len).name(compression = true)
                        cnames.getOrPut(owner) { target to ttl }
                    }

                    (t == TYPE_A && len == 4) || (t == TYPE_AAAA && len == 16) -> {
                        addresses.getOrPut(owner) { ArrayList() } += msg.copyOfRange(at, at + len) to ttl
                    }
                }
            }
        }
        // after the sections are read: a cut message fails whatever it answers
        if (flags and 0x0200 != 0) throw DnsException("truncated response (TC)")
        val rcode = flags and 0xf
        if (rcode != 0 && rcode != RCODE_NXDOMAIN) throw DnsException("RCODE $rcode")
        var name = want
        var ttl = Long.MAX_VALUE
        var steps = 0
        val chain = linkedSetOf(want)
        var chainEnds = rcode != RCODE_NXDOMAIN
        while (chainEnds && found.none { it.first == name }) {
            val next = cnames[name]
            if (next == null || ++steps > MAX_CNAMES) {
                chainEnds = false
                break
            }
            ttl = minOf(ttl, next.second)
            name = next.first
            chain += name
        }

        fun rrset(owner: String): List<SvcbRecord> =
            found.filter { it.first == owner }.mapNotNull { (o, t, rd) ->
                SvcbCodec.parseRdata(msg, rd.first, rd.last - rd.first + 1, o, minOf(t, if (o == name) ttl else Long.MAX_VALUE))
            }
        val records = if (chainEnds) rrset(name) else emptyList()
        // RFC 2181 section 5.4.1: of the other records only those the answer leads to are kept, the CNAME chain and the
        // TargetNames (and theirs, in turn); anything else in the sections could plant records for unrelated names
        val allowed = HashSet<String>(chain)
        val pending = ArrayDeque<List<SvcbRecord>>().apply { add(records) }
        val related = LinkedHashMap<String, List<SvcbRecord>>()
        while (pending.isNotEmpty()) {
            for (r in pending.removeFirst()) {
                val target = if (r.isAlias) r.target else r.serviceHost
                if (target == "." || !allowed.add(target)) continue
                var n = target
                var hops = 0
                while (++hops <= MAX_CNAMES) n = cnames[n]?.first?.also { allowed += it } ?: break
                for (owner in listOf(target) + allowed.filter { it != target }) {
                    if (owner in related || owner == name || found.none { it.first == owner }) continue
                    try {
                        rrset(owner).also {
                            related[owner] = it
                            pending.add(it)
                        }
                    } catch (_: SvcbMalformedException) {
                        // section 2.2: that RRset is rejected; it does not spoil the one asked for
                    }
                }
            }
        }
        val addrs =
            addresses.filterKeys { it in allowed }.mapValues { (_, l) -> l.map { it.first } to l.minOf { it.second } }
        return DnsAnswer(records, negativeTtl, related, addrs)
    }

    /** [name] as [DnsReader.name] writes it: lower case, no final dot. */
    private fun normalize(name: String): String = name.trimEnd('.').lowercase().ifEmpty { "." }
}

/**
 * The HTTPS records of [name] in an answer of the system resolver: a whole message goes through [DnsMessage.answers];
 * a record list (Apple, Windows, which hand out records) through [SvcbCodec.parseRdata], each with its owner and TTL.
 * Empty for a malformed RRset (RFC 9460 section 2.2: rejected, the connection goes on without SVCB); null when the
 * answer cannot be used.
 */
@OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
internal fun httpsRecordsOf(
    answer: io.kuicksilver.tls.KslDnsAnswer,
    name: String,
): DnsAnswer? =
    try {
        when (answer) {
            is io.kuicksilver.tls.KslDnsAnswer.Message -> {
                DnsMessage.read(answer.bytes, name)
            }

            is io.kuicksilver.tls.KslDnsAnswer.Records -> {
                answer.records
                    .mapNotNull {
                        SvcbCodec.parseRdata(
                            it.rdata,
                            0,
                            it.rdata.size,
                            it.owner.trimEnd('.').lowercase(),
                            it.ttlSeconds.coerceIn(0, Int.MAX_VALUE.toLong()),
                        )
                    }.let { DnsAnswer(it) } // no SOA reaches us this way: "none" is not cached (RFC 2308 section 5)
            }
        }
    } catch (_: SvcbMalformedException) {
        DnsAnswer(emptyList()) // RFC 9460 section 2.2: the RRset is rejected, the connection goes on without SVCB
    } catch (_: DnsException) {
        null
    }
