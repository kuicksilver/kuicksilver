// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

/**
 * Whether a running server advertises HTTP/3 and accepts new HTTP/3 connections: the value of
 * [KuicksilverApplicationEngine.http3Advertising], changed at runtime without a restart (docs/guide/ktor.md, "Turning HTTP/3
 * off remotely"). It decides the engine's own `Alt-Svc` only while
 * [altSvc][KuicksilverApplicationEngine.Configuration.altSvc] is on, and only on ports that serve HTTP/3; an `Alt-Svc` the
 * application sets is sent as it is in every mode. New values may be added (docs/stability.md).
 */
@io.kuicksilver.annotations.ExperimentalKuicksilverApi
public enum class Http3Advertising {
    /** HTTP/1.1 responses advertise HTTP/3 with `Alt-Svc: h3=":<port>"; ma=86400`, and HTTP/3 is served (the default). */
    On,

    /**
     * HTTP/1.1 responses say `Alt-Svc: clear` (RFC 7838 section 3): a client drops every alternative it cached for the origin
     * and stops starting HTTP/3 connections from it. HTTP/3 goes on serving: connections already open, and new ones from clients
     * that learned the port elsewhere or have not seen a `clear` yet.
     */
    Clear,

    /**
     * [Clear], plus: every live HTTP/3 connection gets GOAWAY (RFC 9114 section 5.2; its requests in flight complete, then it
     * closes), and every new QUIC connection is refused at its first Initial with a stateless CONNECTION_CLOSE carrying
     * CONNECTION_REFUSED (RFC 9000 sections 10.2.3 and 20.1), so a client that still holds the alternative falls back to TCP at
     * once instead of waiting for a handshake timeout. The UDP socket stays bound, so going back to [On] needs no new bind.
     */
    Drain,
}
