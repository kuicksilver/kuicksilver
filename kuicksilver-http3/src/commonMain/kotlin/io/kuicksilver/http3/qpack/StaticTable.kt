// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.qpack

/** The QPACK static table (RFC 9204 section 3.1, Appendix A). */
internal object StaticTable {
    const val SIZE: Int = 99
    private val exact: Map<Pair<String, String>, Int> by lazy {
        buildMap {
            for (i in SIZE - 1 downTo 0) {
                put(StaticTableData.NAMES[i] to StaticTableData.VALUES[i], i)
            }
        }
    }
    private val byName: Map<String, Int> by lazy { buildMap { for (i in SIZE - 1 downTo 0) put(StaticTableData.NAMES[i], i) } }

    fun name(i: Int): String = StaticTableData.NAMES[i]

    fun value(i: Int): String = StaticTableData.VALUES[i]

    /** Index of the exact entry, or -1. */
    fun find(
        name: String,
        value: String,
    ): Int = exact[name to value] ?: -1

    /** Lowest index with this name, or -1. */
    fun findName(name: String): Int = byName[name] ?: -1
}
