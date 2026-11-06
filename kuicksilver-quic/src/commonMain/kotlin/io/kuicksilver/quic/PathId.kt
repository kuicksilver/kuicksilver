// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlin.jvm.JvmInline

/**
 * Identifies a network path of a connection; an identifier rather than an index keeps the door open for multipath.
 *
 * @property value The raw identifier: 0 for the path the connection started on, then counting up as paths are added; never reused
 *   within a connection.
 */
@JvmInline
public value class PathId(
    public val value: Int,
) {
    /** Holds [Initial]. */
    public companion object {
        /** The path the connection was established on. */
        public val Initial: PathId = PathId(0)
    }
}

/** Validation state of a path (RFC 9000 section 8.2). */
public enum class PathState {
    /** Not validated yet and no challenge sent, or a path id the connection never issued. */
    Unknown,

    /**
     * A PATH_CHALLENGE is outstanding; it is repeated after 1, 1, 2, 4 ... x PTO until an answer or the timeout (RFC 9000 section 8.2.1).
     */
    Validating,

    /** The peer answered the challenge, or the handshake proved the address (RFC 9000 sections 8.1 and 8.2.3). */
    Validated,

    /** No answer within max(3 x PTO, 6 x initial RTT) (RFC 9000 section 8.2.4); a later probe may validate it again. */
    Failed,

    /** The path was closed and forgotten; nothing is sent on it any more. */
    Closed,
}

/** Why the connection moved to another path (RFC 9000 section 9). */
public enum class PathChangeReason {
    /** We moved the connection ourselves with `switchTo` or `migrate` (client only, RFC 9000 section 9.2). */
    ActiveMigration,

    /**
     * The peer's non-probing packets now come from a new IP address; the new path starts from the initial congestion window (section 9.3).
     */
    PeerMigration,

    /** The peer's address changed in its port only, a NAT rebinding: the path keeps its congestion window and RTT (section 9.3). */
    NatRebinding,

    /** The active path failed validation and the connection fell back to the last validated path (section 9.3.2). */
    ValidationFailed,

    /**
     * The connection moved to the server's preferred address (RFC 9000 section 9.6): on a client after validating it, on a server once
     * the client's packets arrived there and its address was validated on that socket. Added in 0.3.0.
     */
    PreferredAddress,
}

/** The socket a server listens on for its preferred address ([QuicServerConfig.Builder.preferredAddress]); a socket id, never a path id. */
internal val PREFERRED_SOCKET: PathId = PathId(-1)

/** Why a path failed validation ([ConnectionEvent.PathFailed], [PathEvent.Failed], [PathValidationException]). */
@ExperimentalKuicksilverApi
public enum class PathFailureReason {
    /** No PATH_RESPONSE within max(3 x PTO, 6 x initial RTT) of the last PATH_CHALLENGE period (RFC 9000 section 8.2.4). */
    ValidationTimeout,

    /**
     * The peer had not given us a connection ID we had not used yet, and none came within max(3 x PTO, 6 x initial RTT): a probe on a
     * new path must not reuse the active path's ID, or an observer could link the two (RFC 9000 section 9.5). Usually seen right
     * after the handshake, before the peer's NEW_CONNECTION_ID frames arrived; retrying once one arrives succeeds.
     */
    NoSpareConnectionId,
}

/**
 * Thrown by [QuicConnection.migrate] when the new path could not be validated; [reason] says why. An IllegalStateException, as the
 * failure was before this type existed.
 */
@ExperimentalKuicksilverApi
public class PathValidationException(
    /** Why the path failed. */
    public val reason: PathFailureReason,
) : IllegalStateException(
        when (reason) {
            PathFailureReason.ValidationTimeout -> "path validation failed"
            PathFailureReason.NoSpareConnectionId -> "path validation failed: no spare connection ID from the peer"
        },
    )

/** Why the transport refused a client's new path ([MigrationRefusedException]). */
@ExperimentalKuicksilverApi
public enum class MigrationRefusal {
    /** The handshake is not confirmed yet: no migration before (RFC 9000 section 9). */
    NotConfirmed,

    /** The server sent `disable_active_migration` (RFC 9000 sections 9 and 18.2). */
    DisabledByPeer,

    /** The server uses zero-length connection IDs: a new path would be linkable to the old one (RFC 9000 section 9.5). */
    ZeroLengthConnectionId,
}

/**
 * Thrown by [QuicConnection.addPath] (and so [QuicConnection.migrate] and a [NetworkMigrator]) when the transport refuses a
 * new path before anything is sent on it; [reason] says why. An IllegalStateException, as the refusal was before this type
 * existed.
 */
@ExperimentalKuicksilverApi
public class MigrationRefusedException(
    /** Why the path was refused. */
    public val reason: MigrationRefusal,
) : IllegalStateException(
        when (reason) {
            MigrationRefusal.NotConfirmed -> "migration before the handshake is confirmed (RFC 9000 section 9)"
            MigrationRefusal.DisabledByPeer -> "the peer advertised disable_active_migration"
            MigrationRefusal.ZeroLengthConnectionId -> "the peer uses a zero-length connection ID (RFC 9000 section 9.5)"
        },
    )

/** ECN codepoint of a datagram (RFC 9000 section 13.4). */
public enum class Ecn {
    /** Not ECN-capable (codepoint 00): what is sent while ECN is off or failed. */
    NotEct,

    /** ECT(1) (codepoint 01); we never send it, and a peer reporting it fails ECN validation (RFC 9000 section 13.4.2.1). */
    Ect1,

    /** ECT(0) (codepoint 10): the mark we send while ECN is being validated or works. */
    Ect0,

    /** Congestion Experienced (codepoint 11): a router signalled congestion; reported back in ACK_ECN (RFC 9000 section 13.4.1). */
    Ce,
}
