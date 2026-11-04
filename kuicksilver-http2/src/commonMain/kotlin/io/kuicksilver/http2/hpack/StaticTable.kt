// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.hpack

/** The HPACK static table (RFC 7541 section 2.3.1, Appendix A), indexed from 1. */
internal object StaticTable {
    const val SIZE: Int = 61
    private val exact: Map<Pair<String, String>, Int> by lazy {
        buildMap { for (i in SIZE downTo 1) put(StaticTableData.NAMES[i - 1] to StaticTableData.VALUES[i - 1], i) }
    }
    private val byName: Map<String, Int> by lazy { buildMap { for (i in SIZE downTo 1) put(StaticTableData.NAMES[i - 1], i) } }

    /** The entry at [index], 1..[SIZE]. */
    fun entry(index: Int): Pair<String, String> = StaticTableData.NAMES[index - 1] to StaticTableData.VALUES[index - 1]

    /** Index of the exact entry, or -1. */
    fun find(
        name: String,
        value: String,
    ): Int = exact[name to value] ?: -1

    /** Lowest index with this name, or -1. */
    fun findName(name: String): Int = byName[name] ?: -1
}
