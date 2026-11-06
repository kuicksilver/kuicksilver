// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.dns

/** Writes DNS wire format for tests: SVCB RDATA from a parsed [SvcbRecord], names, resource records and whole responses. */
internal object SvcbTestEncoder {
    /** [r] back to RDATA: the keys this client reads, in increasing order (RFC 9460 section 2.2). */
    fun encode(r: SvcbRecord): ByteArray {
        val out = ArrayList<Byte>()
        out.u16(r.priority)
        out.addAll(name(r.target).toList())
        if (r.isAlias) return out.toByteArray()
        if (r.alpn.isNotEmpty()) {
            val v = ArrayList<Byte>()
            for (id in r.alpn) {
                v += id.length.toByte()
                for (c in id) v += c.code.toByte()
            }
            out.param(1, v.toByteArray())
        }
        if (r.noDefaultAlpn) out.param(2, ByteArray(0))
        r.port?.let { out.param(3, byteArrayOf((it shr 8).toByte(), it.toByte())) }
        if (r.ipv4Hints.isNotEmpty()) out.param(4, r.ipv4Hints.reduce { a, b -> a + b })
        if (r.ipv6Hints.isNotEmpty()) out.param(6, r.ipv6Hints.reduce { a, b -> a + b })
        return out.toByteArray()
    }

    /** [n] (presentation format, `\DDD` escapes, "." for the root) in uncompressed wire format. */
    fun name(n: String): ByteArray {
        if (n == "." || n.isEmpty()) return byteArrayOf(0)
        val out = ArrayList<Byte>()
        val label = ArrayList<Byte>()
        var i = 0

        fun flush() {
            out += label.size.toByte()
            out.addAll(label)
            label.clear()
        }
        while (i < n.length) {
            val c = n[i]
            when {
                c == '\\' && i + 3 < n.length && n[i + 1].isDigit() -> {
                    label += n.substring(i + 1, i + 4).toInt().toByte()
                    i += 4
                    continue
                }

                c == '\\' -> {
                    label += n[i + 1].code.toByte()
                    i += 2
                    continue
                }

                c == '.' -> {
                    flush()
                }

                else -> {
                    label += c.code.toByte()
                }
            }
            i++
        }
        if (label.isNotEmpty()) flush()
        out += 0
        return out.toByteArray()
    }

    /** One resource record: [owner], [type], class IN, [ttl], [rdata]. */
    fun rr(
        owner: String,
        type: Int,
        ttl: Long,
        rdata: ByteArray,
    ): ByteArray {
        val out = ArrayList<Byte>()
        out.addAll(name(owner).toList())
        out.u16(type)
        out.u16(1)
        out.u16((ttl shr 16).toInt())
        out.u16(ttl.toInt())
        out.u16(rdata.size)
        out.addAll(rdata.toList())
        return out.toByteArray()
    }

    /** A response to `qname`/`qtype` with [answers] (already encoded by [rr]) and [rcode]; QR and RD/RA set. */
    fun response(
        qname: String,
        answers: List<ByteArray>,
        qtype: Int = 65,
        rcode: Int = 0,
        id: Int = 0,
        flags: Int = 0x8180 or rcode,
    ): ByteArray {
        val out = ArrayList<Byte>()
        out.u16(id)
        out.u16(flags)
        out.u16(1)
        out.u16(answers.size)
        out.u16(0)
        out.u16(0)
        out.addAll(name(qname).toList())
        out.u16(qtype)
        out.u16(1)
        for (a in answers) out.addAll(a.toList())
        return out.toByteArray()
    }

    private fun MutableList<Byte>.u16(v: Int) {
        add((v shr 8).toByte())
        add(v.toByte())
    }

    private fun MutableList<Byte>.param(
        key: Int,
        value: ByteArray,
    ) {
        u16(key)
        u16(value.size)
        addAll(value.toList())
    }
}
