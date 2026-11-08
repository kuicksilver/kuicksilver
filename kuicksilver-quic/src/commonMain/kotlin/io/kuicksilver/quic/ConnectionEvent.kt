// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.QuicSessionTicket
import io.kuicksilver.tls.QuicTlsSession

/** Lifecycle of a connection as the core reports it. */
public enum class ConnectionState {
    /** The TLS handshake is running (RFC 9001 section 4). */
    Handshaking,

    /** The handshake completed on our side; the client waits for HANDSHAKE_DONE to confirm it (RFC 9001 section 4.1.1). */
    Established,

    /** The handshake is confirmed (RFC 9001 section 4.1.2): key updates and migration are allowed. */
    Confirmed,

    /** We sent CONNECTION_CLOSE and answer further packets with it for 3 x PTO (RFC 9000 section 10.2.1). */
    Closing,

    /** The peer closed or reset the connection; we send nothing for 3 x PTO (RFC 9000 section 10.2.2). */
    Draining,

    /** The connection is over and its native resources are freed. */
    Closed,
}

/** What the core tells its runtime through [ConnectionCore.nextEvent]. */
public sealed interface ConnectionEvent {
    /**
     * The handshake completed (RFC 9001 section 4.1.1): [ConnectionCore.peerCertificates] and [ConnectionCore.negotiatedAlpn] are readable.
     */
    public object HandshakeCompleted : ConnectionEvent

    /** The handshake paused for certificate verification: run `session.verifyPeer(chain)` off the loop and pass the result to [ConnectionCore.resumeVerify]. */
    public class VerifyRequested internal constructor(
        /** The peer's certificate chain as presented, leaf first. */
        public val chain: List<Certificate>,
        /** The TLS session that verifies [chain][ConnectionEvent.VerifyRequested.chain]. */
        public val session: QuicTlsSession,
    ) : ConnectionEvent

    /** The peer opened stream [id][ConnectionEvent.StreamOpened.id] (RFC 9000 section 3.2); a lower stream of the same type it skipped gets its own event first. */
    public class StreamOpened internal constructor(
        /** The stream the peer opened. */
        public val id: Long,
    ) : ConnectionEvent

    /** Stream [id][ConnectionEvent.StreamReadable.id] has new data, its end or its reset for [ConnectionCore.readStream]; raised again only after more arrives. */
    public class StreamReadable internal constructor(
        /** The stream with something to read. */
        public val id: Long,
    ) : ConnectionEvent

    /**
     * Stream [id][ConnectionEvent.StreamWritable.id] can make progress again: acknowledgements freed send-buffer room after [ConnectionCore.writeStream] took fewer bytes
     * than offered, or the peer raised its flow-control credit (MAX_STREAM_DATA, MAX_DATA; RFC 9000 section 4.1) while the stream had
     * data waiting to be sent. Retry the write; the event is a hint, a write may still take fewer bytes when other streams share the
     * buffer.
     */
    public class StreamWritable internal constructor(
        /** The stream that can be written to again. */
        public val id: Long,
    ) : ConnectionEvent

    /**
     * The peer abandoned stream [id][ConnectionEvent.StreamReset.id] with RESET_STREAM and application error [code][ConnectionEvent.StreamReset.code] (RFC 9000 section 19.4); its reads end with
     * -1. After RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset) it comes once the reliable bytes were read.
     */
    public class StreamReset internal constructor(
        /** The stream the peer reset. */
        public val id: Long,
        /** The application error code of the RESET_STREAM. */
        public val code: Long,
        /** RESET_STREAM_AT: the reliable bytes were read, and the reader may still hold some it has not handed over. */
        internal val afterData: Boolean = false,
    ) : ConnectionEvent

    /**
     * The peer sent STOP_SENDING with [code][ConnectionEvent.StopSendingReceived.code] for stream [id][ConnectionEvent.StopSendingReceived.id] (RFC 9000 section 19.5); the core already answered with RESET_STREAM carrying
     * the same code, or the code of our RESET_STREAM_AT when one went first (draft-ietf-quic-reliable-stream-reset section 5.2).
     */
    public class StopSendingReceived internal constructor(
        /** The stream the peer asked this endpoint to stop sending on. */
        public val id: Long,
        /** The application error code of the STOP_SENDING. */
        public val code: Long,
    ) : ConnectionEvent

    /**
     * Stream [id][ConnectionEvent.StreamFinished.id] is done in both directions — its sending half acknowledged or reset, its receiving half read to the end or reset
     * and consumed — and was retired: its state is gone and, for a peer stream, its credit returns through MAX_STREAMS. Raised once.
     */
    public class StreamFinished internal constructor(
        /** The stream that is done. */
        public val id: Long,
    ) : ConnectionEvent

    /**
     * The peer raised its stream limit ([bidi][ConnectionEvent.StreamsAvailable.bidi] or unidirectional) with MAX_STREAMS (RFC 9000 section 4.6) after
     * [ConnectionCore.openStream] was refused at the old one: retry the open. Raised once per refusal.
     */
    public class StreamsAvailable internal constructor(
        /** True for bidirectional streams, false for unidirectional ones. */
        public val bidi: Boolean,
    ) : ConnectionEvent

    /** The connection ended for [reason][ConnectionEvent.Closed.reason]; the last event of the connection, raised once. */
    public class Closed internal constructor(
        /** Why the connection ended. */
        public val reason: QuicException.ConnectionLost,
    ) : ConnectionEvent

    /** DPLPMTUD changed the datagram size of [path][ConnectionEvent.MtuUpdated.path] to [mtu][ConnectionEvent.MtuUpdated.mtu] bytes of UDP payload (RFC 8899); after a black hole it drops back to 1200. */
    public class MtuUpdated internal constructor(
        /** The path whose datagram size changed. */
        public val path: PathId,
        /** The new datagram size, in bytes of UDP payload. */
        public val mtu: Int,
    ) : ConnectionEvent

    /** DATAGRAM payloads wait in [ConnectionCore.readDatagram] (RFC 9221). */
    public object DatagramsReadable : ConnectionEvent

    /** [path][ConnectionEvent.PathValidated.path] answered our PATH_CHALLENGE (RFC 9000 section 8.2.3). */
    public class PathValidated internal constructor(
        /** The path that answered the challenge. */
        public val path: PathId,
    ) : ConnectionEvent

    /** [path][ConnectionEvent.PathFailed.path] never answered within the validation timeout (RFC 9000 section 8.2.4), or [reason][ConnectionEvent.PathFailed.reason] says why it could not be probed. */
    public class PathFailed
        internal constructor(
            /** The path that could not be validated. */
            public val path: PathId,
            /** Why the validation failed. */
            @property:ExperimentalKuicksilverApi public val reason: PathFailureReason,
        ) : ConnectionEvent {
            /** A validation that timed out ([PathFailureReason.ValidationTimeout]). */
            @OptIn(ExperimentalKuicksilverApi::class)
            internal constructor(path: PathId) : this(path, PathFailureReason.ValidationTimeout)
        }

    /** Packets now go to [new][ConnectionEvent.PathChanged.new] instead of [old][ConnectionEvent.PathChanged.old] (RFC 9000 section 9.3), for the given [reason][ConnectionEvent.PathChanged.reason]. */
    public class PathChanged internal constructor(
        /** The path packets went to before. */
        public val old: PathId,
        /** The path packets go to now. */
        public val new: PathId,
        /** Why the connection changed its path. */
        public val reason: PathChangeReason,
    ) : ConnectionEvent

    /**
     * Server: 0-RTT of this connection was accepted and its packets are read from now on, before the handshake completes;
     * client: the server accepted our 0-RTT (RFC 9001 section 4.6.2). Early data can be a replay (RFC 9846 section 8).
     */
    @ExperimentalKuicksilverApi
    public object EarlyDataAccepted : ConnectionEvent

    /**
     * Client: the server rejected our 0-RTT. Every stream we opened was reset (RFC 9001 section 4.6.2): nothing of them is
     * sent again, their IDs and the connection's credit start over from the server's new transport parameters, and the
     * application opens new streams for what it still wants to send.
     */
    @ExperimentalKuicksilverApi
    public object EarlyDataRejected : ConnectionEvent

    /**
     * Client with early data: a ticket for a later 0-RTT connection, with the server's transport parameters remembered
     * (RFC 9000 section 7.4.1). The receiver owns it: store it (single use) or close it.
     */
    @ExperimentalKuicksilverApi
    public class SessionTicket internal constructor(
        /** The ticket the server issued, to resume a later connection with. */
        public val ticket: QuicSessionTicket,
    ) : ConnectionEvent
}
