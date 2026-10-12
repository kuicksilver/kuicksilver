// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

/** A snapshot of an endpoint's stateless work and admission outcomes; every value counts since the endpoint started. */
public class EndpointStats internal constructor(
    /** Initials discarded by the endpoint: queue overflow, hard limits (`maxConnections`, `maxConnectionsPerIp`), reflective source ports and [AdmissionDecision.Drop]. */
    public val initialsDropped: Long,
    /** Retry packets sent (RFC 9000 section 8.1.2). */
    public val retriesSent: Long,
    /** Initials whose Retry token was forged or expired, answered with INVALID_TOKEN (RFC 9000 section 8.1.3). */
    public val invalidTokens: Long,
    /** Version Negotiation packets sent (RFC 9000 section 6). */
    public val versionNegotiations: Long,
    /** Stateless Reset packets sent (RFC 9000 section 10.3). */
    public val statelessResets: Long,
    /** Stateless answers (Retry, Version Negotiation, Stateless Reset, INVALID_TOKEN or CONNECTION_REFUSED close) withheld by the per-address or total rate limit. */
    public val statelessRateLimited: Long,
    /** [AdmissionDecision.Retry] returned for an already validated address, or an exception out of [ConnectionAdmission.admit]; each one was dropped. */
    public val admissionContractViolations: Long,
    /** Connections this endpoint (loop) created so far: server connections admitted plus client connections opened; closed ones still count. */
    public val connectionsCreated: Long = 0,
) {
    override fun toString(): String =
        "EndpointStats(initialsDropped=$initialsDropped, retriesSent=$retriesSent, invalidTokens=$invalidTokens, versionNegotiations=$versionNegotiations, statelessResets=$statelessResets, statelessRateLimited=$statelessRateLimited, admissionContractViolations=$admissionContractViolations, connectionsCreated=$connectionsCreated)"
}
