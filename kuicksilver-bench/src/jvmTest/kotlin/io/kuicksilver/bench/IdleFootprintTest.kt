// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.LeakRegistry
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * What one idle connection holds on the JVM heap, server side, as the memory benchmark's inventory counts it (everything the
 * connection reaches that another connection does not share): ceilings, so per-connection buffers made up front do not creep
 * back (P.5).
 */
@OptIn(InternalKuicksilverApi::class)
class IdleFootprintTest {
    private fun inventory(section: String, label: String): Long {
        val lines = ArrayList<String>()
        // as production runs: the leak sentinel off, whose tracking adds a completion handler per stream, session and
        // connection (a few hundred bytes per HTTP/3 connection that production never holds)
        val tracked = LeakRegistry.disable()
        try {
            runBlocking { MemoryBench.run(connections = 4, transferMiB = 1, only = setOf(section), out = { lines += it }) }
        } finally {
            if (tracked) LeakRegistry.enable(LeakRegistry.sitesKept) // as the sentinel's extension turned it on
        }
        val at = lines.indexOfFirst { it.startsWith("$label inventory:") }
        check(at >= 0) { "no $label inventory in the benchmark's output" }
        // the header and its rows (indented): what a failure's "see its inventory above" points at
        println(lines[at])
        lines.drop(at + 1).takeWhile { it.startsWith("  ") }.forEach(::println)
        return lines[at].substringAfter("inventory: ").substringBefore(" B").toLong()
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
        // 78.00-78.41 K measured (2026-11-26, JVM 21, macOS arm64, 16 runs), the inventory taken once every space has given
        // back the records it does not keep idle (MemoryBench waits for it, and prints the records kept per space: 0, 0, 2
        // in every run). A space's sent-packet records were as many as it ever had in flight at once and stayed: 87.7 K on
        // the macOS runner (2026-11-25), 8 records pooled where runs here pooled 3 or 4 (744 B each with their frame
        // arrays), and after a large transfer one per packet of the window. A space empty for an idle period (three PTOs,
        // at least 1 s) now halves its spare records per period down to 2 (LossDetection.settleIdle), a discarded space
        // keeps none, and neither the acknowledged list nor the probe list holds a record past its use. What still varies
        // (410 B) is the control-frame queue and the session's waiters. The ceiling leaves 1.6 K, two records and that
        // spread, for the CI runner, which only the records set apart before; the modes below (an 8 KiB segment kept, 6 K
        // and more made up front) land well above it.
        // 81.2-85.7 K measured (2026-11-20, JVM 21, macOS arm64, 36 runs; 84.0-84.8 K in 29 of them). What varies between
        // runs is how many sent-packet records each number space keeps pooled for reuse (744 B each with their frame
        // arrays: 0 to 2 more) and the control-frame queue (160 B); the reset-tracking sets, which stayed allocated empty
        // after a stream reset (up to 912 B), are let go once empty now. The ceiling leaves one pooled record of room
        // above the highest run.
        // 84.1-84.4 K measured (2026-11-20, JVM 21, 8 runs; one 85.1 K, the reset-tracking maps of a stream reset in
        // flight; 84.5-85.3 K while the leak sentinel's completion handler per stream, session and connection was
        // counted, which production never holds: the inventory runs with the registry off now). 83.5-84.4 K measured
        // (2026-11-19, JVM 21; 84.7-85.4 K, 86.8 K on the macOS runner, while each request's STOP_SENDING watch,
        // started for the reset budget, waited for its stream's end and held the request until then; it ends with the
        // complete response now). 83.4 K measured (2026-11-16, JVM 21; 89.4 K while a critical stream's reader kept its
        // cancelled header deadline, a job with its cancellation's stack trace, for the connection's life). 82.1-82.8 K
        // measured (2026-11-15, JVM 21, 4 runs; 80.7-81.1 K before the streams' final sizes and stop watch and
        // WebTransport flow control, 88.5 K with their objects made up front: a Deferred and a flow pair per stream, an
        // exception with its stack trace for the half a unidirectional stream lacks, the WebTransport queues and
        // limiter per connection; now made by their first user). 78.6-79.6 K measured (2026-11-06, JVM 21, 12 runs).
        // Before, in about a third of the runs, 88.6-89.4 K: the HTTP/3 accept loop's coroutine frame still held the
        // last request stream and its 8 KiB input segment when that request had arrived while the loop waited
        // (docs/benchmarks.md, "Memory"); this ceiling catches that mode coming back. 88-104 K with 4 KiB reassembly
        // windows, 292 K with per-stream staging arrays
        const val HTTP3_CEILING = 80_000L
        // 33 752 measured (2026-11-26, JVM 21, every run): +8 B, the core's slot for the local transport parameters a qlog
        // trace logs with the peer's (quic-events-04 section 5.3); 33 928 on the macOS runner and here while the slot held
        // them, a TransportParameters and its version array (+176), for the life of every connection, traced or not. Only
        // a trace waiting for the peer's parameters keeps them now, and lets go once it logged both.
        // 33 744 measured (2026-11-26, JVM 21, every run): -2 320 B, three sent-packet records fewer (the Initial and
        // Handshake spaces, discarded, keep none; the acknowledged list let go of the one it still referenced: -2 232)
        // and each space's pool an array of 4 instead of an ArrayList of 10 (-144), less the idle mark and the
        // allocation count per space (+48) and the lists' peak (+8).
        // 36 064 measured (2026-11-20, JVM 21, every run): +144 B over 35 920 on main, the state of four 0.3.0
        // features, each a field or two per connection: DPLPMTUD's datagram size and sequence per sent packet (RFC 8899
        // section 4.3, black-hole detection by datagram; 4 pooled and acknowledged packets, +64) and the builder's
        // packets of the datagram in flight (+48: an array, 24 B less than the ArrayList it was); the client CID
        // credited to each path (+16, path diagnostics); the reassembly allocation budget (RangeBudget.bytes and
        // maxBytes, +32, picoquic #2333 class); ECH's session state (+8) and the core's flags (+8: the client's fixed
        // version, the flight before ech_required, the initial datagram size applied); less 32 B of empty crypto
        // windows now shared. 36 088 before the array. 35 912 measured (2026-11-16, JVM 21; 36 552 with the reset and
        // credit-hold sets, the socket capability map and two address arrays per peer connection ID made up front, now
        // by their first entry). 35 776 measured (2026-11-15, JVM 21; 35 864 with the 0-RTT hold's queue and set made
        // up front, now by the first hold). 35 552 measured (2026-11-11, JVM 21): the 0.3.0 RFC 9000/9002 state a
        // connection keeps from the start (its own IDs for removal by key, per-path ECN and persistent-congestion
        // marks, the 0-RTT packet range); 35 104 before (2026-11-06), 36 160 with the DATAGRAM ring made up front
        const val CORE_CEILING = 33_900L
    }
}
