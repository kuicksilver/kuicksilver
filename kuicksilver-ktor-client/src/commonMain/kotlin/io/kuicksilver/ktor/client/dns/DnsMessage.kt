// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.dns

/**
 * What a DNS response says for the HTTPS record client ([DnsMessage.read]).
 *
 * @property records the RRset of the name asked for, after CNAMEs (empty: none).
 * @property negativeTtl how long "none" may be cached (RFC 2308 section 5), null when the response gives no SOA.
 * @property related other HTTPS RRsets of the response, by TargetName (an alias target's, for example): the RRset of
 *   that name after its CNAMEs, as a query for it would answer.
 * @property addresses A and AAAA addresses of the response by owner, 4 or 16 bytes each, with their smallest TTL: only
 *   owners with both an A and an AAAA RRset in the response, which can stand in for an address lookup; also by a
 *   TargetName that is a CNAME to such an owner.
 * @property cnames the CNAMEs a TargetName of [related] or [addresses] went through, by TargetName (none: not a CNAME).
 * @property chain the name asked and its CNAMEs: [related] and [addresses] of names at or under one of these may be cached
 *   beyond this resolution, the others serve it only (they are another zone's data).
 */
internal class DnsAnswer(
    val records: List<SvcbRecord>,
    val negativeTtl: Long? = null,
    val related: Map<String, List<SvcbRecord>> = emptyMap(),
    val addresses: Map<String, Pair<List<ByteArray>, Long>> = emptyMap(),
    val chain: Set<String> = emptySet(),
    val cnames: Map<String, List<String>> = emptyMap(),
) {
    /**
     * Whether what this answer files under [owner] is in the bailiwick of the query (RFC 2181 section 5.4.1): [owner] and
     * every name of its [cnames] are at or under a name of [chain].
     */
    fun inBailiwick(owner: String): Boolean = under(owner) && cnames[owner].orEmpty().all(::under)

    private fun under(name: String): Boolean = chain.any { name == it || name.endsWith(".$it") }
}

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
     * The largest DNS message: over TCP "The message is prefixed with a two byte length field which gives the message
     * length" (RFC 1035 section 4.2.2), and for DNS over HTTPS "This media type restricts the maximum size of the DNS
     * message to 65535 bytes" (RFC 8484 section 6).
     */
    const val MAX_MESSAGE = 65_535

    /**
     * Other RRsets of the type asked for that are followed at most in one answer ([DnsAnswer.related]): twice the AliasMode
     * steps SVCB resolution takes ([HttpsRecords.MAX_ALIASES]).
     */
    const val MAX_RELATED = 16

    /** Units of work (a record read or parsed, a CNAME followed) between two calls of the checkpoint of [read]. */
    private const val CHECKPOINT_EVERY = 64

    /**
     * A recursive query for [name]/[type] in class IN: ID 0 (RFC 8484 section 4.1: DoH clients "SHOULD use a DNS ID of 0
     * in every DNS request"; a system resolver sets its own), RD set, one question, no other section. Throws [IllegalArgumentException] for a name that is
     * empty, has an empty label, a label over 63 bytes or is over 255 bytes in wire format.
     */
    fun query(
        name: String,
        type: Int = TYPE_HTTPS,
    ): ByteArray {
        require(isAskable(name)) { "not a DNS name: $name" }
        val labels = name.trimEnd('.').split('.')
        val wire = labels.sumOf { it.length + 1 } + 1
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
     * the SOA record's TTL and its MINIMUM, and no longer than a CNAME that led to the name without them; null without
     * an SOA in the authority section), and the other records of [type] and the A/AAAA records the answer and additional
     * sections carry for other names (RFC 9460 section 5: they "SHOULD be placed in cache before performing any follow-up
     * queries"; an RRset of [type] that is malformed is left out, section 2.2). Throws as [answers], and [DnsFormatException] for a message over [MAX_MESSAGE] bytes.
     *
     * The work is linear in the message (the DNS is "an untrusted channel that might be controlled by an attacker", RFC
     * 9460 section 9.2.2): every name is looked at once, at most 16 CNAMEs are followed from one name and at most
     * [MAX_RELATED] other RRsets. [checkpoint] is called every few records; a lookup passes its coroutine's `ensureActive`,
     * so its timeout or cancellation stops a read in progress (whatever it throws ends the read).
     */
    fun read(
        msg: ByteArray,
        qname: String,
        type: Int = TYPE_HTTPS,
        checkpoint: () -> Unit = {},
    ): DnsAnswer {
        // anything longer is no DNS message over TCP or HTTPS (MAX_MESSAGE), and the work below is linear in this bound
        if (msg.size > MAX_MESSAGE) throw DnsFormatException("a message of ${msg.size} bytes, over the DNS maximum of $MAX_MESSAGE")
        var steps = 0

        // every unit of work below (a record read or parsed, a CNAME followed) counts; the caller's checkpoint every
        // CHECKPOINT_EVERY units lets a lookup's timeout or cancellation stop a read in progress
        fun tick() {
            if (++steps % CHECKPOINT_EVERY == 0) checkpoint()
        }
        val r = DnsReader(msg, 0, msg.size)
        r.u16() // ID: matched by the transport (the system resolver, or the exchange that carried it: HttpsRecordSource.Exchange)
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
        val found = HashMap<String, MutableList<Pair<Long, IntRange>>>() // TTL and RDATA of [type] by owner: answer and additional sections
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
                tick()
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
                        found.getOrPut(owner) { ArrayList() } += ttl to (at until at + len)
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
        // the CNAME chain from the name asked, also for NXDOMAIN and NODATA. A negative answer is about the end of the
        // chain (RFC 2308 section 1: "QNAME" is the name asked "or where this resolves to a CNAME, or CNAME chain, the data
        // field of the last CNAME"), and holds for the name asked only while each CNAME may be cached, its TTL being "the
        // time interval that the resource record may be cached before the source of the information should again be
        // consulted" (RFC 1035 section 3.2.1)
        var name = want
        var chainTtl = Long.MAX_VALUE
        var hops = 0
        val chain = linkedSetOf(want)
        var ends = true // whether the chain ends at a name (no loop, not longer than MAX_CNAMES)
        while (name !in found) {
            val next = cnames[name] ?: break
            if (++hops > MAX_CNAMES) {
                ends = false
                break
            }
            tick()
            chainTtl = minOf(chainTtl, next.second)
            name = next.first
            chain += name
        }

        // the records of [owner], each TTL no longer than [cap]: the smallest TTL of the CNAMEs that led there
        fun rrset(
            owner: String,
            cap: Long,
        ): List<SvcbRecord> =
            found[owner].orEmpty().mapNotNull { (ttl, rd) ->
                tick()
                SvcbCodec.parseRdata(msg, rd.first, rd.last - rd.first + 1, owner, minOf(ttl, cap))
            }
        val records = if (ends && rcode != RCODE_NXDOMAIN) rrset(name, chainTtl) else emptyList()
        // RFC 2181 section 5.4.1: of the other records only those the answer leads to are kept, the CNAME chain and the
        // TargetNames (and theirs, in turn); anything else in the sections could plant records for unrelated names. Each
        // TargetName is looked at once (a work list), and at most MAX_RELATED RRsets are followed. A TargetName that is a
        // CNAME has the records at the end of its chain, as a query for it would ("after following CNAMEs as normal", RFC
        // 9460 section 3, step 3): they are filed under the TargetName, which is the name SVCB resolution asks for next
        val allowed = HashSet<String>(chain)
        val work = ArrayDeque<String>()
        val chainEnd = HashMap<String, Pair<String, Long>>() // TargetName -> the end of its CNAME chain and the chain's TTL
        val via = HashMap<String, List<String>>() // TargetName -> the names its CNAME chain went to

        fun admit(rs: List<SvcbRecord>) {
            for (rec in rs) {
                val target = if (rec.isAlias) rec.target else rec.serviceHost
                if (target == "." || !allowed.add(target)) continue
                work += target
                var n = target
                var ttl = Long.MAX_VALUE
                val path = ArrayList<String>()
                for (i in 1..MAX_CNAMES) {
                    tick()
                    if (n in found) break
                    val next = cnames[n] ?: break
                    ttl = minOf(ttl, next.second)
                    n = next.first
                    allowed += n
                    path += n
                }
                chainEnd[target] = n to ttl
                if (path.isNotEmpty()) via[target] = path
            }
        }
        admit(records)
        val related = LinkedHashMap<String, List<SvcbRecord>>()
        var followed = 0
        while (work.isNotEmpty() && followed < MAX_RELATED) {
            val target = work.removeFirst()
            val (owner, ttl) = chainEnd.getValue(target)
            if (owner == name || owner !in found) continue
            followed++
            try {
                rrset(owner, ttl).also {
                    related[target] = it
                    admit(it)
                }
            } catch (_: SvcbMalformedException) {
                // section 2.2: that RRset is rejected; it does not spoil the one asked for
            }
        }
        // an owner's addresses only when both families came: one alone may be an answer cut short (RFC 9460 section 5.2:
        // a resolver may omit RRsets), so the lookup that asks for both is not skipped (section 3: AAAA "and/or" A); a
        // TargetName that is a CNAME gets those at the end of its chain, no longer than the chain's TTL
        val addrs = LinkedHashMap<String, Pair<List<ByteArray>, Long>>()
        for ((owner, l) in addresses) {
            if (owner in allowed && l.any { it.first.size == 4 } && l.any { it.first.size == 16 }) {
                addrs[owner] = l.map { it.first } to l.minOf { it.second }
            }
        }
        for ((target, end) in chainEnd) {
            val (owner, ttl) = end
            if (owner != target) addrs[owner]?.let { (list, t) -> addrs.getOrPut(target) { list to minOf(t, ttl) } }
        }
        return DnsAnswer(records, negativeTtl?.let { minOf(it, chainTtl) }, related, addrs, chain, via)
    }

    /**
     * Whether [name] can be put in a query: labels of 1..63 printable ASCII bytes, at most 255 bytes in wire format. A
     * host in Unicode is not: DNS carries A-labels (RFC 5890 section 2.3.2.1), and the engine does not convert to them.
     */
    fun isAskable(name: String): Boolean {
        val labels = name.trimEnd('.').split('.')
        return labels.all { it.isNotEmpty() && it.length <= DnsReader.MAX_LABEL && it.all { c -> c.code in 0x21..0x7e } } &&
            labels.sumOf { it.length + 1 } + 1 <= DnsReader.MAX_NAME
    }

    /** [name] as [DnsReader.name] writes it: lower case, no final dot. */
    private fun normalize(name: String): String = name.trimEnd('.').lowercase().ifEmpty { "." }
}

/**
 * The HTTPS records of [name] in an answer of the system resolver: a whole message goes through [DnsMessage.read] (with
 * [checkpoint]); a record list (Apple, Windows, which hand out records) through [SvcbCodec.parseRdata], each with its
 * owner and TTL.
 * Empty for a malformed RRset (RFC 9460 section 2.2: rejected, the connection goes on without SVCB); null when the
 * answer cannot be used.
 */
@OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
internal fun httpsRecordsOf(
    answer: io.kuicksilver.tls.KslDnsAnswer,
    name: String,
    checkpoint: () -> Unit = {},
): DnsAnswer? =
    try {
        when (answer) {
            is io.kuicksilver.tls.KslDnsAnswer.Message -> {
                DnsMessage.read(answer.bytes, name, checkpoint = checkpoint)
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
