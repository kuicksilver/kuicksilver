// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.hpack

/**
 * HPACK decoder (RFC 7541 sections 2-6) for one direction of a connection. [maxTableSize] is our
 * SETTINGS_HEADER_TABLE_SIZE (the protocol's initial 4096 by default), the ceiling of every dynamic table size update.
 *
 * Limits (threat model 3.23): the decoded field list is counted as RFC 9113 section 6.5.2 counts it (name + value + 32 per
 * field); once it passes [maxHeaderListSize] the sink gets no more fields, but the block is still decoded to its end so
 * the dynamic table stays in step with the peer's encoder (RFC 9113 section 8.2: the field block MUST be processed
 * unless the connection is closed). An index into the table is a reference, not a copy, so a block of indexed fields
 * allocates nothing; every literal is bounded by [maxStringLength] before it is allocated, and by the bytes left in the
 * block. The whole block is at most the caller's limit (RFC 9113 section 4.3: the connection core collects CONTINUATION
 * frames up to the field list limit before it calls [decode]). Every error is an [HpackError] (COMPRESSION_ERROR).
 */
internal class HpackDecoder(
    maxTableSize: Int = 4_096,
    var maxHeaderListSize: Int = 65_536,
    private val maxStringLength: Int = maxHeaderListSize,
) {
    private val table = DynamicTable(maxTableSize)

    /** The SETTINGS_HEADER_TABLE_SIZE in force: a size update above it is an error (section 6.3). */
    var maxTableSize: Int = maxTableSize
        private set

    /** The smallest limit since the last block when it fell below the table's size: the next block must start with an update to at most it (section 4.2). */
    private var requiredUpdate = -1

    /** Literal bytes allocated by the last [decode] (a test hook for the decompression limits). */
    var lastAllocated: Long = 0
        private set

    /** The dynamic table, for tests: (name, value) from newest to oldest, and its size. */
    internal fun tableEntries(): List<Pair<String, String>> = (1..table.count).map { table.get(it)!! }

    internal val tableSize: Int get() = table.size

    /**
     * Our SETTINGS_HEADER_TABLE_SIZE changed and was acknowledged: later updates must not exceed [v]. When it falls below
     * the table's current maximum the encoder must shrink the table with an update at the start of the next block.
     */
    fun setMaxTableSize(v: Int) {
        maxTableSize = v
        if (v < table.capacity) requiredUpdate = if (requiredUpdate < 0) v else minOf(requiredUpdate, v)
    }

    /**
     * Decodes one complete field block, passing each field to [sink] in order. Returns true when the field list fits
     * [maxHeaderListSize]; false when it does not (the sink stopped at the limit; the table is still up to date).
     */
    fun decode(
        block: ByteArray,
        off: Int = 0,
        len: Int = block.size - off,
        sink: (name: String, value: String) -> Unit,
    ): Boolean = decodeFields(block, off, len) { n, v, _ -> sink(n, v) }

    /**
     * [decode], with each field's representation: [sink]'s `neverIndexed` is true for a literal header field never
     * indexed (section 6.2.3), which an intermediary MUST forward with the same representation (section 7.1.3).
     */
    fun decodeFields(
        block: ByteArray,
        off: Int = 0,
        len: Int = block.size - off,
        sink: (name: String, value: String, neverIndexed: Boolean) -> Unit,
    ): Boolean {
        val r = HpackReader(block, off, off + len, maxStringLength)
        var listSize = 0L
        var fits = true
        var fieldSeen = false
        try {
            while (r.remaining > 0) {
                val b = r.peek()
                if (b and 0xe0 == 0x20) {
                    // dynamic table size update (section 6.3): only at the start of a block (section 4.2)
                    if (fieldSeen) throw HpackError("dynamic table size update after a field")
                    val v = r.readInt(5)
                    if (v > maxTableSize) throw HpackError("dynamic table size update $v above the limit $maxTableSize")
                    if (requiredUpdate >= 0 && v <= requiredUpdate) requiredUpdate = -1
                    table.setCapacity(v)
                    continue
                }
                if (requiredUpdate >=
                    0
                ) {
                    throw HpackError("the block does not start with the required table size update (at most $requiredUpdate)")
                }
                fieldSeen = true
                val name: String
                val value: String
                var neverIndexed = false
                when {
                    b and 0x80 != 0 -> { // indexed field (section 6.1)
                        val f = lookup(r.readInt(7))
                        name = f.first
                        value = f.second
                    }

                    b and 0x40 != 0 -> { // literal with incremental indexing (section 6.2.1)
                        name = literalName(r, 6)
                        value = r.readString()
                        table.insert(name, value)
                    }

                    else -> { // literal without indexing (0000, section 6.2.2) or never indexed (0001, section 6.2.3)
                        neverIndexed = b and 0x10 != 0
                        name = literalName(r, 4)
                        value = r.readString()
                    }
                }
                if (fits) {
                    listSize += entrySize(name, value)
                    if (listSize > maxHeaderListSize) fits = false else sink(name, value, neverIndexed)
                }
            }
            if (requiredUpdate >= 0) throw HpackError("the block does not carry the required table size update")
        } finally {
            lastAllocated = r.allocated
        }
        return fits
    }

    private fun literalName(
        r: HpackReader,
        prefixBits: Int,
    ): String {
        val idx = r.readInt(prefixBits)
        return if (idx == 0) r.readString() else lookup(idx).first
    }

    /** Index space of section 2.3.3: 1..61 static, then the dynamic table from its newest entry; anything else is an error. */
    private fun lookup(index: Int): Pair<String, String> {
        if (index == 0) throw HpackError("index 0")
        if (index <= StaticTable.SIZE) return StaticTable.entry(index)
        return table.get(index - StaticTable.SIZE) ?: throw HpackError("index $index beyond the dynamic table (${table.count} entries)")
    }
}
