// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.qpack

/** Size of an entry (RFC 9204 section 3.2.1): name and value octets plus 32. */
internal fun entrySize(
    name: String,
    value: String,
): Long = name.length + value.length + 32L

/** The QPACK dynamic table (RFC 9204 section 3.2), addressed by absolute index (0 = first entry ever inserted). */
internal class DynamicTable(
    capacity: Long,
) {
    var capacity: Long = capacity
        private set
    private val names = ArrayDeque<String>()
    private val values = ArrayDeque<String>()

    /** Entries ever inserted (the Insert Count). */
    var insertCount: Long = 0
        private set
    var size: Long = 0
        private set

    /** Absolute index of the oldest entry still present. */
    val dropped: Long get() = insertCount - names.size

    /** Inserts, evicting the oldest entries; false when the entry is larger than the whole table (nothing changes then). */
    fun insert(
        name: String,
        value: String,
    ): Boolean {
        val s = entrySize(name, value)
        if (s > capacity) return false
        while (size + s > capacity) evictOne()
        names.addLast(name)
        values.addLast(value)
        size += s
        insertCount++
        return true
    }

    fun absolute(index: Long): Pair<String, String>? {
        if (index < dropped || index >= insertCount) return null
        val i = (index - dropped).toInt()
        return names[i] to values[i]
    }

    fun setCapacity(c: Long) {
        capacity = c
        while (size > capacity) evictOne()
    }

    /** Bytes that would have to be evicted to fit [needed] more, counted from the oldest entry: the absolute indexes that go are < the returned value. */
    fun evictionBoundary(needed: Long): Long {
        var free = capacity - size
        var idx = dropped
        while (free < needed && idx < insertCount) {
            val (n, v) = absolute(idx)!!
            free += entrySize(n, v)
            idx++
        }
        return if (free >= needed) idx else Long.MAX_VALUE
    }

    /** Newest absolute index with this exact field, or -1. */
    fun findExact(
        name: String,
        value: String,
    ): Long {
        for (i in names.size - 1 downTo 0) {
            if (names[i] == name &&
                values[i] == value
            ) {
                return dropped + i
            }
        }
        return -1
    }

    fun findName(name: String): Long {
        for (i in names.size - 1 downTo 0) if (names[i] == name) return dropped + i
        return -1
    }

    private fun evictOne() {
        val n = names.removeFirst()
        val v = values.removeFirst()
        size -= entrySize(n, v)
    }
}
