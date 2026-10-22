// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress

/**
 * What the endpoint knows about a new client when it asks [ConnectionAdmission.admit] (docs/guide/quic.md, "Admission and endpoint limits").
 *
 * The endpoint builds one per queued Initial that passed the cheap checks (1200 bytes, a supported version, a DCID of
 * at least 8 bytes, no reflective source port) and the hard limits (`maxConnections`, `acceptQueue`,
 * `maxConnectionsPerIp`); the policy never sees datagrams those checks dropped or refused.
 */
public class ConnectionAttempt internal constructor(
    /** The client's address and port as seen on the socket. */
    public val remote: InetSocketAddress,
    /** Server connections whose handshake has not been confirmed yet. */
    public val inflightHandshakes: Int,
    /** Every connection this endpoint holds, in any state. */
    public val connections: Int,
    /** Connections whose peer shares this client's IP address (port ignored). */
    public val connectionsFromAddress: Int,
    /** Bytes buffered by the unfinished handshakes: undecryptable packets held for later keys and out-of-order CRYPTO data. */
    public val handshakeBufferBytes: Long,
    /**
     * True when the Initial carried a Retry token or a NEW_TOKEN token this endpoint minted for this address (RFC 9000 sections
     * 8.1.2 and 8.1.3). A [AdmissionDecision.Retry] for an attempt that answered a Retry is a contract violation and is dropped;
     * one for a NEW_TOKEN holder is sent (the client then shows the Retry token instead).
     */
    public val addressValidated: Boolean,
) {
    override fun toString(): String =
        "ConnectionAttempt($remote, inflight=$inflightHandshakes, connections=$connections, fromAddress=$connectionsFromAddress, handshakeBuffer=$handshakeBufferBytes, validated=$addressValidated)"
}

/** The policy's answer to a [ConnectionAttempt]. */
public sealed interface AdmissionDecision {
    /** Create the connection. */
    public object Allow : AdmissionDecision {
        override fun toString(): String = "Allow"
    }

    /**
     * Answer with a Retry packet so the client proves its address first (RFC 9000 section 8.1.2); never for an attempt that
     * already answered one (its Retry token validated the address).
     */
    public object Retry : AdmissionDecision {
        override fun toString(): String = "Retry"
    }

    /** Discard the Initial silently; the client times out. */
    public object Drop : AdmissionDecision {
        override fun toString(): String = "Drop"
    }

    /** Refuse with a stateless Initial CONNECTION_CLOSE carrying [code] (RFC 9000 section 10.2.3), for example [TransportError.CONNECTION_REFUSED]. */
    public class Close(
        public val code: Long,
    ) : AdmissionDecision {
        init {
            require(code in 0..((1L shl 62) - 1)) { "error code must be 0..2^62-1" }
        }

        override fun equals(other: Any?): Boolean = other is Close && other.code == code

        override fun hashCode(): Int = code.hashCode()

        override fun toString(): String = "Close($code)"
    }
}

/**
 * Decides, per new client Initial, whether the endpoint creates a connection, asks for address validation, drops or
 * refuses (like s2n-quic's `endpoint::Limiter` and quinn's `Incoming`). Called on the endpoint loop for every
 * queued Initial, so it must be cheap and must not block. An exception from [admit] counts as [AdmissionDecision.Drop]
 * and is recorded in `EndpointStats.admissionContractViolations`: the endpoint fails closed.
 */
public fun interface ConnectionAdmission {
    /** The decision for one queued client Initial, called on the endpoint loop; an exception counts as [AdmissionDecision.Drop]. */
    public fun admit(attempt: ConnectionAttempt): AdmissionDecision

    /** The ready-made policies: [default] and [AlwaysRetry]. */
    public companion object {
        /**
         * The default policy: [AdmissionDecision.Allow] for an attempt whose address a token already validated
         * ([ConnectionAttempt.addressValidated]: a Retry or NEW_TOKEN token), since a Retry would only cost it a round trip;
         * otherwise [AdmissionDecision.Retry] when the attempt would be more than [maxInflightHandshakes] concurrent
         * handshakes (the 257th with the defaults) or the unfinished handshakes already hold more than
         * [maxHandshakeBufferBytes], and [AdmissionDecision.Allow] below that. The hard limits (`maxConnections`,
         * `maxConnectionsPerIp`, `acceptQueue`) still apply to validated clients.
         */
        public fun default(
            maxInflightHandshakes: Int = 256,
            maxHandshakeBufferBytes: Long = 8_388_608,
        ): ConnectionAdmission {
            require(maxInflightHandshakes >= 0 && maxHandshakeBufferBytes >= 0) {
                "maxInflightHandshakes and maxHandshakeBufferBytes must not be negative"
            }
            return ConnectionAdmission { a ->
                if (!a.addressValidated &&
                    (a.inflightHandshakes >= maxInflightHandshakes || a.handshakeBufferBytes > maxHandshakeBufferBytes)
                ) {
                    AdmissionDecision.Retry
                } else {
                    AdmissionDecision.Allow
                }
            }
        }

        /** Every unvalidated client gets a Retry first and is admitted once its token checks out (the interop runner's `retry` case; a server under attack). */
        public val AlwaysRetry: ConnectionAdmission =
            ConnectionAdmission { a ->
                if (a.addressValidated) AdmissionDecision.Allow else AdmissionDecision.Retry
            }
    }
}
