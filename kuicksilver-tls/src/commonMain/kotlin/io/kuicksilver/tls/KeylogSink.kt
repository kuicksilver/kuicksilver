// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi

/**
 * Receives RFC 9850 key log lines. The only way to obtain TLS secrets; `SSLKEYLOGFILE` is never read by the library
 * (docs/guide/tls.md, Key logging). Attaching a sink is a deliberate decision of the application (the library logs nothing). Lines are delivered as the handshake produces them.
 */
@DelicateKuicksilverApi
public fun interface KeylogSink {
    /**
     * Receives one line without its newline, e.g. `CLIENT_HANDSHAKE_TRAFFIC_SECRET <client random> <secret>`. It is called
     * inside the handshake, possibly from several connections at once, so it must be quick, thread-safe and must not throw:
     * an exception propagates into the handshake.
     */
    public fun log(line: String)

    /** Holds [inMemory]. */
    public companion object {
        /** Collects lines in memory (tests, diagnostics). */
        public fun inMemory(): InMemoryKeylog = InMemoryKeylog()
    }
}

/** Delivers ksl's buffered lines to a sink; EXPORTER_SECRET is dropped (RFC 9850 section 3: it would break channel bindings). */
@DelicateKuicksilverApi
internal fun KeylogSink.deliver(text: String) {
    text.lines().filter { it.isNotEmpty() && !it.startsWith("EXPORTER_SECRET") }.forEach(::log)
}

/**
 * A [KeylogSink] that keeps the lines in memory, for tests and diagnostics. Not synchronized: give each concurrently
 * running connection its own instance. The lines are secrets; never keep one in production.
 */
@DelicateKuicksilverApi
public class InMemoryKeylog : KeylogSink {
    private val buffer = StringBuilder()

    /** The lines received so far, in order, as a new list on each read. */
    public val lines: List<String> get() = buffer.lines().filter { it.isNotEmpty() }

    override fun log(line: String) {
        buffer.append(line).append('\n')
    }
}
