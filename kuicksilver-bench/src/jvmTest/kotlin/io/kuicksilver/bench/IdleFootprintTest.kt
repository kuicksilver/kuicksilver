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

    /** A QUIC server core after the handshake, no stream open (the benchmark's core section). */
    @Test fun anIdleQuicServerCoreStaysUnderItsCeiling() {
        val bytes = inventory("core", "server core")
        assertTrue(bytes <= CORE_CEILING, "an idle QUIC server core holds $bytes bytes (ceiling $CORE_CEILING); see its inventory above")
    }

    private companion object {
        // 79 320 measured (2026-11-06, JVM 21); 88-104 K with 4 KiB reassembly windows, 292 K with per-stream staging arrays.
        // The inventory varies by a few KB between runs with what the connection's coroutines hold when it is taken
        const val HTTP3_CEILING = 95_000L
        const val CORE_CEILING = 35_500L // 35 104 measured (2026-11-06, JVM 21); 36 160 with the DATAGRAM ring made up front
    }
}
