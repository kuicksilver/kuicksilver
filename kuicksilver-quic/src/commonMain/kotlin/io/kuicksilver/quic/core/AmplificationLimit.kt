// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

/** The server's 3x anti-amplification budget before the client's address is validated (RFC 9000 section 8.1). */
internal class AmplificationLimit(
    private val factor: Int = 3,
) {
    var received: Long = 0
        private set
    var sent: Long = 0
        private set
    var validated: Boolean = false

    fun onReceived(bytes: Int) {
        received += bytes
    }

    /** The address behind this path changed: the budget starts over (RFC 9000 section 8.1 is per address). */
    fun reset() {
        received = 0
        sent = 0
        validated = false
    }

    fun onSent(bytes: Int) {
        sent += bytes
    }

    /** Bytes that may still be sent now; unbounded once validated. */
    fun budget(): Long = if (validated) Long.MAX_VALUE else factor * received - sent
}
