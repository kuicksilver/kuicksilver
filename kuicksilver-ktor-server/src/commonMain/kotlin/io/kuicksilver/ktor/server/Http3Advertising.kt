// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

/**
 * Whether a running server advertises HTTP/3 and accepts new HTTP/3 connections: the value of
 * [KuicksilverApplicationEngine.http3Advertising], changed at runtime without a restart (docs/guide/ktor.md, "Turning
 * HTTP/3 off on the server"). It decides the engine's own `Alt-Svc` only while
 * [altSvc][KuicksilverApplicationEngine.Configuration.altSvc] is on, and only on ports that serve HTTP/3; an `Alt-Svc` the
 * application sets, and a 421 response, are left as they are in every mode. New values may be added (docs/stability.md).
 */
@io.kuicksilver.annotations.ExperimentalKuicksilverApi
public enum class Http3Advertising {
    /** HTTP/1.1 responses advertise HTTP/3 with `Alt-Svc: h3=":<port>"; ma=86400`, and HTTP/3 is served (the default). */
    On,

    /**
     * Responses say `Alt-Svc: clear` (RFC 7838 section 3: "the origin requests all alternatives for that origin to be
     * invalidated"), HTTP/1.1 and HTTP/3 ones alike (an alternative may clear its origin's entries, section 2.2), so clients
     * stop starting HTTP/3 connections from the cached alternative. HTTP/3 goes on serving: connections already open, and
     * new ones from clients that have not seen a `clear` yet.
     */
    Clear,

    /**
     * [Clear], plus: every live HTTP/3 connection gets GOAWAY (RFC 9114 section 5.2; its requests in flight complete, then
     * it closes), and every new QUIC connection is refused at its first Initial (RFC 9000 section 5.2.2: "If a server
     * refuses to accept a new connection, it SHOULD send an Initial packet containing a CONNECTION_CLOSE frame with error
     * code CONNECTION_REFUSED"; sections 10.2.3 and 20.1), statelessly and before `quicAdmission`, unless a hard limit
     * (`maxConnections`, `maxConnectionsPerIp`) drops the Initial first. A client that still holds the alternative falls
     * back to TCP at once instead of waiting for a handshake timeout. The UDP socket stays bound, so going back to [On]
     * needs no new bind.
     */
    Drain,
}
