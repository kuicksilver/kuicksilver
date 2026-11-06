// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.dns

/**
 * DNS messages for the HTTPS records (RFC 1035 section 4.1), sans-IO: the query and the records of its answer.
 */
internal object DnsMessage {
    const val TYPE_CNAME = 5
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
    ): List<SvcbRecord> {
        val r = DnsReader(msg, 0, msg.size)
        r.u16() // ID: matched by the transport (the system resolver, or the DoH exchange that carried it)
        val flags = r.u16()
        val qd = r.u16()
        val an = r.u16()
        r.u16() // NSCOUNT, ARCOUNT: not read
        r.u16()
        if (flags and 0x8000 == 0) throw DnsFormatException("not a response")
        if ((flags shr 11) and 0xf != 0) throw DnsFormatException("opcode ${(flags shr 11) and 0xf}")
        val want = normalize(qname)
        if (qd != 1) throw DnsFormatException("$qd questions")
        val qn = r.name(compression = true)
        val qt = r.u16()
        val qc = r.u16()
        if (qn != want || qt != type || qc != CLASS_IN) throw DnsFormatException("the answer to another question ($qn $qt)")
        val cnames = HashMap<String, Pair<String, Long>>()
        val found = ArrayList<Triple<String, Long, IntRange>>() // owner, TTL, RDATA
        repeat(an) {
            val owner = r.name(compression = true)
            val t = r.u16()
            val c = r.u16()
            val ttl = r.u32().let { if (it > Int.MAX_VALUE) 0L else it } // RFC 2181 section 8: a TTL with the top bit set is 0
            val len = r.u16()
            val at = r.pos
            r.skip(len)
            if (c != CLASS_IN) return@repeat
            when (t) {
                type -> {
                    found += Triple(owner, ttl, at until at + len)
                }

                TYPE_CNAME -> {
                    val target = DnsReader(msg, at, at + len).name(compression = true)
                    cnames.getOrPut(owner) { target to ttl }
                }
            }
        }
        // after the sections are read: a cut message fails whatever it answers
        if (flags and 0x0200 != 0) throw DnsException("truncated response (TC)")
        val rcode = flags and 0xf
        if (rcode == RCODE_NXDOMAIN) return emptyList()
        if (rcode != 0) throw DnsException("RCODE $rcode")
        var name = want
        var ttl = Long.MAX_VALUE
        var steps = 0
        while (found.none { it.first == name }) {
            val next = cnames[name] ?: return emptyList()
            if (++steps > MAX_CNAMES) return emptyList()
            ttl = minOf(ttl, next.second)
            name = next.first
        }
        return found.filter { it.first == name }.mapNotNull { (owner, t, rd) ->
            SvcbCodec.parseRdata(msg, rd.first, rd.last - rd.first + 1, owner, minOf(t, ttl))
        }
    }

    /** [name] as [DnsReader.name] writes it: lower case, no final dot. */
    private fun normalize(name: String): String = name.trimEnd('.').lowercase().ifEmpty { "." }
}
