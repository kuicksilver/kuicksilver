// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.hpack

/**
 * HPACK encoder (RFC 7541) for one direction of a connection. The dynamic table is at most [maxTableSize] (our own
 * ceiling, 4096 by default) and at most the peer's SETTINGS_HEADER_TABLE_SIZE ([setPeerMaxTableSize]); [peerTableSize]
 * is the size the peer's decoder starts with (the protocol's 4096). A change is signalled at the start of the next block,
 * the smallest size first when it changed more than once (section 4.2).
 *
 * What is indexed (section 7.1): credentials are never indexed (section 7.1.3: `authorization`,
 * `proxy-authorization`, `set-cookie`, and `cookie` values under 20 bytes, which are easy to guess); values that change
 * with every message (`:path`, `content-length`, dates, validators, `location`) and fields larger than half the table
 * are sent without indexing; everything else is added to the table.
 */
internal class HpackEncoder(
    private val maxTableSize: Int = 4_096,
    peerTableSize: Int = 4_096,
) {
    /** How literals are coded: [AUTO] picks Huffman when it is shorter (section 5.2 leaves the choice to the encoder). */
    enum class HuffmanMode { AUTO, ALWAYS, NEVER }

    var huffman: HuffmanMode = HuffmanMode.AUTO

    /** Test hook (RFC 7541 appendix C): every literal is added to the table, whatever its name. */
    var indexEverything: Boolean = false

    private val table = DynamicTable(minOf(maxTableSize, peerTableSize))
    private var pendingMin = if (table.capacity != peerTableSize) table.capacity else -1

    val tableCapacity: Int get() = table.capacity

    /** The peer's SETTINGS_HEADER_TABLE_SIZE (RFC 9113 section 6.5.2): the table follows min(it, [maxTableSize]). */
    fun setPeerMaxTableSize(v: Long) {
        val c = minOf(v, maxTableSize.toLong()).toInt()
        if (c == table.capacity) return
        pendingMin = if (pendingMin < 0) c else minOf(pendingMin, c)
        table.setCapacity(c)
    }

    /**
     * Encodes [fields] as one field block. A field whose name is in [neverIndexed] (compared in lowercase) is sent as a
     * literal never indexed (section 6.2.3), like the credentials above: the application marked it sensitive, or it
     * forwards a field it received so (section 7.1.3).
     */
    fun encode(
        fields: List<Pair<String, String>>,
        neverIndexed: Set<String> = emptySet(),
    ): ByteArray {
        val out = HpackWriter()
        if (pendingMin >= 0) {
            out.writeInt(0x20, 5, pendingMin)
            if (pendingMin != table.capacity) out.writeInt(0x20, 5, table.capacity)
            pendingMin = -1
        }
        val marked = if (neverIndexed.isEmpty()) neverIndexed else neverIndexed.mapTo(HashSet()) { it.lowercase() }
        for ((name, value) in fields) encodeField(out, name, value, name in marked)
        return out.toByteArray()
    }

    private fun encodeField(
        out: HpackWriter,
        name: String,
        value: String,
        marked: Boolean,
    ) {
        val sensitive = marked || (!indexEverything && isSensitive(name, value))
        if (!sensitive) {
            val s = StaticTable.find(name, value)
            if (s > 0) return out.writeInt(0x80, 7, s)
            val d = table.find(name, value)
            if (d > 0) return out.writeInt(0x80, 7, StaticTable.SIZE + d)
        }
        val nameIndex =
            StaticTable.findName(name).takeIf { it > 0 } ?: table.findName(name).let { if (it > 0) StaticTable.SIZE + it else 0 }
        val index = !sensitive && (indexEverything || (name !in NOT_INDEXED && entrySize(name, value) <= table.capacity / 2))
        when {
            index -> out.writeInt(0x40, 6, nameIndex)
            sensitive -> out.writeInt(0x10, 4, nameIndex)
            else -> out.writeInt(0x00, 4, nameIndex)
        }
        if (nameIndex == 0) out.writeString(name, useHuffman(name))
        out.writeString(value, useHuffman(value))
        if (index) table.insert(name, value)
    }

    private fun useHuffman(s: String): Boolean =
        when (huffman) {
            HuffmanMode.ALWAYS -> true
            HuffmanMode.NEVER -> false
            HuffmanMode.AUTO -> Huffman.encodedLength(s.latin1()) < s.length
        }

    private companion object {
        val NEVER_INDEXED = setOf("authorization", "proxy-authorization", "set-cookie")
        val NOT_INDEXED =
            setOf(":path", "content-length", "date", "etag", "last-modified", "if-modified-since", "if-none-match", "location", "age")

        fun isSensitive(
            name: String,
            value: String,
        ): Boolean = name in NEVER_INDEXED || (name == "cookie" && value.length < 20)
    }
}
