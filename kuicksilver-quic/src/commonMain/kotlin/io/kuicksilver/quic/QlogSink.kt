// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.tls.TlsRole

/** Where qlog traces go (docs/guide/quic.md, "qlog"); `open` returns null to skip tracing for a connection. */
public interface QlogSink {
    /**
     * Called on the endpoint loop at a connection's first event, with its original destination connection ID in hex and our [role];
     * null skips tracing for that connection, and an exception disables it without touching the connection.
     */
    public fun open(
        odcidHex: String,
        role: TlsRole,
    ): QlogTrace?

    /**
     * Whether HTTP/3 events carry the values of header and trailer fields. False (the default): every field is written with
     * its name and the value `[redacted]`, except the values of `:method`, `:scheme`, `:status` and `:protocol`, which are
     * tokens the protocol defines (cookies, credentials and URLs never reach the trace). True writes every value as sent or
     * received: turn it on only for traces that are handled as secrets (threat model, CWE-532).
     */
    @ExperimentalKuicksilverApi
    public val logHeaderValues: Boolean get() = false
}

/** One connection's trace; records are JSON-SEQ lines. */
public interface QlogTrace : AutoCloseable {
    /**
     * Appends one record, already framed (RS before the JSON, newline after); called on the endpoint loop, so it must not block for long.
     * An exception closes the trace and stops tracing for the connection.
     */
    public fun write(record: String)
}
