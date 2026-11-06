// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertTrue

/** The memory benchmark (tools/bench/memory.sh) runs end to end and reports every figure; a small run, no numbers asserted. */
class MemoryBenchTest {
    @Test fun everySectionReportsItsFigures() {
        val lines = ArrayList<String>()
        runBlocking { MemoryBench.run(connections = 4, transferMiB = 1, out = { lines += it }) }
        for (prefix in listOf("core, idle, server side:", "endpoint, idle, server side:", "http3, idle, server side:", "server core inventory:",
            "http3 server connection inventory:", "core, transfer", "endpoint, transfer (ksl crypto, one stream, MemoryNetwork)", "endpoint, transfer (ksl crypto, one stream, loopback UDP)")) {
            assertTrue(lines.any { it.startsWith(prefix) }, "no \"$prefix\" line in:\n${lines.joinToString("\n")}")
        }
    }
}
