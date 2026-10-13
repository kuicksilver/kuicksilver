// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.soak

import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.tls.TlsRole
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * qlog for the connections that failed only (`-Pkuicksilver.soak.qlog=<dir>`): every connection keeps its last [keep]
 * records in memory; a connection that ends by a timeout or an internal failure (a `connection_closed` with a `trigger`)
 * is written to [dir], and so is its peer's trace (the same original destination connection ID), when the peer's trace
 * ends or, if it ended already, from the last [held] traces kept after their end.
 */
@OptIn(ExperimentalAtomicApi::class)
internal class FailureQlog(
    private val dir: String,
    private val keep: Int = 20_000,
    private val held: Int = 256,
) : QlogSink {
    private class Ring(
        val name: String,
        val odcid: String,
        val records: ArrayDeque<String>,
    )

    private val failed = AtomicReference(emptySet<String>())
    private val ended = AtomicReference(emptyList<Ring>())

    override fun open(
        odcidHex: String,
        role: TlsRole,
    ): QlogTrace {
        val ring = Ring("${odcidHex}_${role.name.lowercase()}.sqlog", odcidHex, ArrayDeque())
        return object : QlogTrace {
            private var closed = false

            override fun write(record: String) {
                if (closed) return
                if (ring.records.size == keep) ring.records.removeFirst()
                ring.records.addLast(record)
            }

            override fun close() {
                if (closed) return
                closed = true
                val last = ring.records.lastOrNull().orEmpty()
                if ("connection_closed" in last && "\"trigger\"" in last) {
                    write(ring)
                    while (true) {
                        val f = failed.load()
                        if (failed.compareAndSet(f, f + ring.odcid)) break
                    }
                    ended.load().filter { it.odcid == ring.odcid }.forEach(::write)
                } else if (ring.odcid in failed.load()) {
                    write(ring)
                } else {
                    while (true) {
                        val e = ended.load()
                        if (ended.compareAndSet(e, (e + ring).takeLast(held))) break
                    }
                }
            }
        }
    }

    private fun write(ring: Ring) {
        runCatching { writeText(dir, ring.name, ring.records.joinToString("")) }
            .onFailure { println("[soak qlog] ${ring.name}: $it") }
        println("[soak qlog] wrote ${ring.name} (${ring.records.size} records)")
    }
}
