// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlin.time.Duration

/**
 * A snapshot of the connection's recovery and path state (docs/architecture.md, "Cross-Cutting Concerns"). Counters run since the
 * connection started; RTT, window and MTU values belong to the active path. `QuicConnection.stats` builds it from any thread
 * while the endpoint loop goes on updating the connection, without a lock: each field is a value the loop held, but two
 * fields need not come from the same instant (bytesSent may already count a packet that packetsSent does not).
 *
 * @property minRtt Lowest RTT sample of the active path (RFC 9002 section 5.2).
 * @property smoothedRtt Smoothed RTT of the active path (RFC 9002 section 5.3); the initial RTT until the first sample.
 * @property rttVar RTT variation of the active path (RFC 9002 section 5.3).
 * @property cwnd Congestion window of the active path in bytes.
 * @property bytesInFlight Bytes sent on the active path and not yet acknowledged or declared lost.
 * @property lostPackets Packets declared lost (RFC 9002 section 6.1).
 * @property ptoCount Probe timeouts in a row without an acknowledgement (RFC 9002 section 6.2); 0 once an ACK arrives.
 * @property pathMtu Largest UDP payload in bytes the active path carries now: 1200 until PMTUD finds more (RFC 8899).
 * @property currentPath The path the connection sends on now.
 * @property datagramsDropped DATAGRAM payloads evicted from the full receive queue (RFC 9221), plus received UDP datagrams the
 *   connection discarded before processing (from an unknown server address, a late Initial, a full undecryptable-packet buffer).
 * @property packetsReceived QUIC packets received and decrypted.
 * @property packetsSent QUIC packets sent.
 * @property bytesReceived UDP payload bytes received, on every path.
 * @property bytesSent UDP payload bytes sent, on every path.
 * @property duplicatesDropped Packets discarded because their packet number had already been received.
 * @property undecryptableBuffered Packets held now until the keys to decrypt them arrive (RFC 9001 section 5.7).
 * @property reassemblyRanges Out-of-order ranges held now across the receive buffers of all streams.
 * @property pathBytesReceived Bytes received on [currentPath] alone; see [pathBytesSent].
 * @property ecnCeEvents Congestion events the peer's CE reports caused on our sending, at most one per recovery period; see
 *   [ecnCeReceived].
 */
public class ConnectionStats internal constructor(
    public val minRtt: Duration,
    public val smoothedRtt: Duration,
    public val rttVar: Duration,
    public val cwnd: Long,
    public val bytesInFlight: Long,
    public val lostPackets: Long,
    public val ptoCount: Int,
    public val pathMtu: Int,
    public val currentPath: PathId,
    public val datagramsDropped: Long,
    /** Sum of the per-connection memory ceilings (threat-model 3.2): the most memory this connection may ever hold. */
    public val memoryCeiling: Long,
    public val packetsReceived: Long,
    public val packetsSent: Long,
    public val bytesReceived: Long,
    public val bytesSent: Long,
    public val duplicatesDropped: Long,
    public val undecryptableBuffered: Int,
    /** Largest ACK range count over the three spaces and the reassembly ranges held across all streams (both are bounded per connection). */
    public val ackRanges: Int,
    public val reassemblyRanges: Int,
    /** Key updates so far, ours and the peer's (RFC 9001 section 6). */
    public val keyUpdates: Long,
    /** Packets that failed authentication under any key, Initial ones included (RFC 9001 section 6.6 integrity limit). */
    public val authenticationFailures: Long,
    /** Datagrams that looked like a Stateless Reset but carried no token of ours (RFC 9000 section 10.3.1). */
    public val invalidResets: Long,
    /** Glitch tokens the peer spent on useless work (docs/guide/quic.md, "Glitch protection"); 0 for an honest peer. */
    public val glitchTokensSpent: Long,
    /** Bytes sent and received on [currentPath] alone (RFC 9000 section 9.3.1: at most 3x the received bytes go out before the path is validated). */
    public val pathBytesSent: Long,
    public val pathBytesReceived: Long,
    /** ECN validation of the current path (RFC 9000 section 13.4.2). */
    public val ecnState: EcnState,
    /** CE marks counted on received datagrams over all packet number spaces; congestion events those marks caused on our sending (one per recovery period). */
    public val ecnCeReceived: Long,
    public val ecnCeEvents: Long,
    /** Datagrams the send queue dropped because they no longer fit the path MTU (after a black hole) or by policy. */
    public val datagramsDroppedSend: Long,
    /**
     * UDP datagrams of this connection the socket did not take: a send that failed (a filter, an unreachable route) or took
     * only part of a batch (a full send buffer). Loss recovery repairs them; a steady rise means the socket is the bottleneck.
     * It may over-count when the socket fails mid-batch: a send that throws counts its whole batch, although the slots
     * before the failing one may have left.
     */
    @property:ExperimentalKuicksilverApi
    public val datagramsDroppedSocket: Long,
)
