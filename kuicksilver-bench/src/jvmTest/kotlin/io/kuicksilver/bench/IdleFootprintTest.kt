// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * What one idle connection holds on the JVM heap, server side, as the memory benchmark's inventory counts it (everything the
 * connection reaches that another connection does not share): ceilings, so per-connection buffers made up front do not creep
 * back (P.5).
 */
class IdleFootprintTest {
    private fun inventory(section: String, label: String): Long {
        val lines = ArrayList<String>()
        runBlocking { MemoryBench.run(connections = 4, transferMiB = 1, only = setOf(section), out = { lines += it }) }
        val line = lines.first { it.startsWith("$label inventory:") }
        println(line)
        return line.substringAfter("inventory: ").substringBefore(" B").toLong()
    }

    /** An HTTP/3 connection that carried one request: its seven streams (control, QPACK, the request) and the datagram reader. */
    @Test fun anIdleHttp3ServerConnectionStaysUnderItsCeiling() {
        val bytes = inventory("http3", "http3 server connection")
        assertTrue(bytes <= HTTP3_CEILING, "an idle HTTP/3 server connection holds $bytes bytes (ceiling $HTTP3_CEILING); see its inventory above")
    }

    private companion object {
        const val HTTP3_CEILING = 120_000L
    }
}
