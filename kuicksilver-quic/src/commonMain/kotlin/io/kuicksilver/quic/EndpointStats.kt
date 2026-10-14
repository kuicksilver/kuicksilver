// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/**
 * A snapshot of an endpoint's stateless work, admission outcomes and connection lifecycle; every counter counts since the
 * endpoint started. `QuicEndpoint.stats` sums it over every loop of the endpoint (docs/guide/quic.md, "Observability").
 * The loops keep plain counters, so taking a snapshot allocates this object only and costs nothing per packet; values are
 * read without a lock and may lag the loops by a few events.
 */
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
    /**
     * Connections this endpoint created so far: client connections opened, plus server connections admitted whose first
     * Initial decrypted (a forged or corrupted Initial creates none and counts in [datagramsDroppedUndecryptable]); closed
     * ones still count.
     */
    public val connectionsCreated: Long = 0,
    /** Connections the endpoint holds now, in any state until their closing period ends. */
    @property:ExperimentalKuicksilverApi
    public val connectionsActive: Long = 0,
    /** Server connections handed to `accept()` (at handshake completion, or at 0-RTT acceptance). */
    @property:ExperimentalKuicksilverApi
    public val connectionsAccepted: Long = 0,
    /**
     * Client attempts refused because the accept queue was full: at the Initial with a stateless CONNECTION_REFUSED, or at
     * handshake completion (`QuicEndpointConfig.acceptQueue`).
     */
    @property:ExperimentalKuicksilverApi
    public val connectionsRefusedAcceptQueue: Long = 0,
    /** Client attempts the [ConnectionAdmission] policy dropped or refused ([AdmissionDecision.Drop], [AdmissionDecision.Close]). */
    @property:ExperimentalKuicksilverApi
    public val connectionsRefusedAdmission: Long = 0,
    /** Client attempts dropped by the hard limits `maxConnections` and `maxConnectionsPerIp`. */
    @property:ExperimentalKuicksilverApi
    public val connectionsRefusedLimits: Long = 0,
    /** Client attempts refused with CONNECTION_REFUSED because the endpoint is shutting down (`QuicEndpoint.shutdown`). */
    @property:ExperimentalKuicksilverApi
    public val connectionsRefusedShutdown: Long = 0,
    /** Handshakes completed, client and server connections alike. */
    @property:ExperimentalKuicksilverApi
    public val handshakesCompleted: Long = 0,
    /** Connections that ended before their handshake completed because `QuicConfig.handshakeTimeout` (or the idle timeout) ran out. */
    @property:ExperimentalKuicksilverApi
    public val handshakesFailedTimeout: Long = 0,
    /** Connections that ended before their handshake completed with a TLS alert, ours or the peer's (code `0x0100 + alert`): a certificate, ALPN or version problem. */
    @property:ExperimentalKuicksilverApi
    public val handshakesFailedTls: Long = 0,
    /** Connections that ended before their handshake completed for any other reason: a refusal, a transport error, a close by either side. */
    @property:ExperimentalKuicksilverApi
    public val handshakesFailedOther: Long = 0,
    /** Client connections that sent 0-RTT (a resumed ticket that allowed early data). */
    @property:ExperimentalKuicksilverApi
    public val zeroRttOffered: Long = 0,
    /** Connections whose 0-RTT was accepted: client connections the server accepted, server connections that accepted the client's. */
    @property:ExperimentalKuicksilverApi
    public val zeroRttAccepted: Long = 0,
    /** Client connections whose 0-RTT the server rejected. */
    @property:ExperimentalKuicksilverApi
    public val zeroRttRejected: Long = 0,
    /** UDP datagrams received on the endpoint's sockets (a migrating client's extra sockets included). */
    @property:ExperimentalKuicksilverApi
    public val datagramsReceived: Long = 0,
    /** UDP datagrams handed to the endpoint's sockets, stateless answers included. */
    @property:ExperimentalKuicksilverApi
    public val datagramsSent: Long = 0,
    /** Datagrams the sockets did not take: a send that failed or took only part of a batch (see [sendFailures]); loss recovery repairs them. */
    @property:ExperimentalKuicksilverApi
    public val datagramsDroppedSocket: Long = 0,
    /** Datagrams dropped because a bounded queue was full: the Initial admission queue (`initialQueueCap`) or a loop's queue of datagrams forwarded by another loop. */
    @property:ExperimentalKuicksilverApi
    public val datagramsDroppedQueue: Long = 0,
    /** Datagrams that did not parse as QUIC, and client Initials whose protection did not verify (no state is kept for them). */
    @property:ExperimentalKuicksilverApi
    public val datagramsDroppedUndecryptable: Long = 0,
    /** Datagrams no connection took that got no answer: unknown connection IDs without a Stateless Reset, packets the cheap Initial checks discard, answers withheld by the rate limit. */
    @property:ExperimentalKuicksilverApi
    public val datagramsDroppedStateless: Long = 0,
    /** Paths that passed validation (RFC 9000 section 8.2): migrations, NAT rebindings and probes. */
    @property:ExperimentalKuicksilverApi
    public val pathValidations: Long = 0,
    /** Path validations that failed (RFC 9000 section 8.2.4). */
    @property:ExperimentalKuicksilverApi
    public val pathValidationFailures: Long = 0,
    /** Exceptions that escaped a coroutine of the endpoint loop (none is expected): counted instead of reaching the thread's uncaught-exception handler. */
    @property:ExperimentalKuicksilverApi
    public val uncaughtFailures: Long = 0,
    /** Socket sends that threw (a filter, an unreachable route); their datagrams count in [datagramsDroppedSocket]. */
    @property:ExperimentalKuicksilverApi
    public val sendFailures: Long = 0,
    /** Exceptions out of a [ConnectionListener] callback or a [KuicksilverLogger]. */
    @property:ExperimentalKuicksilverApi
    public val listenerFailures: Long = 0,
) {
    /** Field by field sum: a loop group's endpoint statistics. */
    internal operator fun plus(o: EndpointStats): EndpointStats =
        EndpointStats(
            initialsDropped + o.initialsDropped,
            retriesSent + o.retriesSent,
            invalidTokens + o.invalidTokens,
            versionNegotiations + o.versionNegotiations,
            statelessResets + o.statelessResets,
            statelessRateLimited + o.statelessRateLimited,
            admissionContractViolations + o.admissionContractViolations,
            connectionsCreated + o.connectionsCreated,
            connectionsActive + o.connectionsActive,
            connectionsAccepted + o.connectionsAccepted,
            connectionsRefusedAcceptQueue + o.connectionsRefusedAcceptQueue,
            connectionsRefusedAdmission + o.connectionsRefusedAdmission,
            connectionsRefusedLimits + o.connectionsRefusedLimits,
            connectionsRefusedShutdown + o.connectionsRefusedShutdown,
            handshakesCompleted + o.handshakesCompleted,
            handshakesFailedTimeout + o.handshakesFailedTimeout,
            handshakesFailedTls + o.handshakesFailedTls,
            handshakesFailedOther + o.handshakesFailedOther,
            zeroRttOffered + o.zeroRttOffered,
            zeroRttAccepted + o.zeroRttAccepted,
            zeroRttRejected + o.zeroRttRejected,
            datagramsReceived + o.datagramsReceived,
            datagramsSent + o.datagramsSent,
            datagramsDroppedSocket + o.datagramsDroppedSocket,
            datagramsDroppedQueue + o.datagramsDroppedQueue,
            datagramsDroppedUndecryptable + o.datagramsDroppedUndecryptable,
            datagramsDroppedStateless + o.datagramsDroppedStateless,
            pathValidations + o.pathValidations,
            pathValidationFailures + o.pathValidationFailures,
            uncaughtFailures + o.uncaughtFailures,
            sendFailures + o.sendFailures,
            listenerFailures + o.listenerFailures,
        )

    @OptIn(ExperimentalKuicksilverApi::class)
    override fun toString(): String =
        "EndpointStats(initialsDropped=$initialsDropped, retriesSent=$retriesSent, invalidTokens=$invalidTokens, " +
            "versionNegotiations=$versionNegotiations, statelessResets=$statelessResets, statelessRateLimited=$statelessRateLimited, " +
            "admissionContractViolations=$admissionContractViolations, connectionsCreated=$connectionsCreated, " +
            "connectionsActive=$connectionsActive, connectionsAccepted=$connectionsAccepted, " +
            "connectionsRefusedAcceptQueue=$connectionsRefusedAcceptQueue, connectionsRefusedAdmission=$connectionsRefusedAdmission, " +
            "connectionsRefusedLimits=$connectionsRefusedLimits, connectionsRefusedShutdown=$connectionsRefusedShutdown, " +
            "handshakesCompleted=$handshakesCompleted, handshakesFailedTimeout=$handshakesFailedTimeout, " +
            "handshakesFailedTls=$handshakesFailedTls, handshakesFailedOther=$handshakesFailedOther, zeroRttOffered=$zeroRttOffered, " +
            "zeroRttAccepted=$zeroRttAccepted, zeroRttRejected=$zeroRttRejected, datagramsReceived=$datagramsReceived, " +
            "datagramsSent=$datagramsSent, datagramsDroppedSocket=$datagramsDroppedSocket, datagramsDroppedQueue=$datagramsDroppedQueue, " +
            "datagramsDroppedUndecryptable=$datagramsDroppedUndecryptable, datagramsDroppedStateless=$datagramsDroppedStateless, " +
            "pathValidations=$pathValidations, pathValidationFailures=$pathValidationFailures, uncaughtFailures=$uncaughtFailures, " +
            "sendFailures=$sendFailures, listenerFailures=$listenerFailures)"
}
