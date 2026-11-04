// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.hpack

/** Size of an entry (RFC 7541 section 4.1): name and value octets plus 32. */
internal fun entrySize(
    name: String,
    value: String,
): Int = name.length + value.length + 32

/**
 * The HPACK dynamic table (RFC 7541 sections 2.3.2, 4): FIFO, the newest entry at index 1 (address space index 62,
 * section 2.3.3). Modelled on kuicksilver-http3's QPACK table, without QPACK's absolute indexes.
 */
internal class DynamicTable(
    capacity: Int,
) {
    /** The maximum size (section 4.2). */
    var capacity: Int = capacity
        private set
    private val names = ArrayDeque<String>()
    private val values = ArrayDeque<String>()

    /** The sum of the entry sizes (section 4.1). */
    var size: Int = 0
        private set

    val count: Int get() = names.size

    /** The entry at [index], 1 = newest; null outside the table. */
    fun get(index: Int): Pair<String, String>? = if (index < 1 || index > names.size) null else names[index - 1] to values[index - 1]

    /** Adds an entry, evicting from the oldest; an entry larger than [capacity] empties the table and is not added (section 4.4). */
    fun insert(
        name: String,
        value: String,
    ) {
        val s = entrySize(name, value)
        while (names.isNotEmpty() && size + s > capacity) evictOne()
        if (s > capacity) return
        names.addFirst(name)
        values.addFirst(value)
        size += s
    }

    /** A new maximum size; entries are evicted until the table fits (section 4.3). */
    fun setCapacity(c: Int) {
        capacity = c
        while (size > capacity) evictOne()
    }

    /** Index (1 = newest) of this exact field, or -1. */
    fun find(
        name: String,
        value: String,
    ): Int {
        for (i in names.indices) if (names[i] == name && values[i] == value) return i + 1
        return -1
    }

    /** Index (1 = newest) of an entry with this name, or -1. */
    fun findName(name: String): Int {
        for (i in names.indices) if (names[i] == name) return i + 1
        return -1
    }

    private fun evictOne() {
        val n = names.removeLast()
        val v = values.removeLast()
        size -= entrySize(n, v)
    }
}
