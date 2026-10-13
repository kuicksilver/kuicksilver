// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlinx.coroutines.CopyableThrowable
import kotlinx.io.IOException
import kotlin.time.Duration

/** Which side initiated a close or a stream reset. */
public enum class Initiator {
    /** This endpoint: the application's own call, or a transport error we detected. */
    Local,

    /** The other endpoint, through a frame it sent (CONNECTION_CLOSE, RESET_STREAM, STOP_SENDING). */
    Peer,
}

/**
 * The timer whose expiry closed the connection. A failed path validation is not a timeout of the connection: the path is
 * dropped, and when no validated path remains the connection ends with [QuicException.ConnectionLost.NoViablePath].
 */
public enum class TimeoutKind {
    /** Nothing was received for the idle timeout both peers agreed on (RFC 9000 section 10.1); see `QuicConfig.maxIdleTimeout`. */
    Idle,

    /** The handshake did not complete within `QuicConfig.handshakeTimeout`. */
    Handshake,
}

private const val MAX_CODE: Long = (1L shl 62) - 1

private fun checkCode(code: Long): Long {
    require(code in 0..MAX_CODE) { "error code must be 0..2^62-1, was $code" }
    return code
}

/**
 * Error model of the QUIC layer (docs/guide/quic.md, "Lifecycle and errors"). Every failure the application sees is a [QuicException]; cancellation is
 * never wrapped in one. Exceptions are copyable so coroutine machinery keeps the stack of the receiving side.
 */
public sealed class QuicException(
    message: String,
    cause: Throwable? = null,
) : IOException(message, cause),
    CopyableThrowable<QuicException> {
    /** The connection is gone; the same instance reaches every stream of the connection. */
    public sealed class ConnectionLost(
        message: String,
        cause: Throwable? = null,
    ) : QuicException(message, cause) {
        /**
         * CONNECTION_CLOSE with a transport error code (frame type 0x1c), or a local transport failure.
         *
         * @property code The transport error code (RFC 9000 section 20.1; a TLS alert as `0x0100 + alert`, see [TransportError]).
         * @property frameType The frame type that triggered the error (RFC 9000 section 19.19), 0 when no frame did.
         * @property reason The reason phrase; a peer's is decoded as UTF-8 (malformed bytes replaced) and kept within 1 KiB.
         * @property reasonBytes The reason phrase as it travelled on the wire, at most 1024 bytes.
         * @property initiator Who closed: we on a protocol error we detected, or the peer.
         */
        public class TransportClosed(
            public val code: Long,
            public val frameType: Long,
            public val reason: String,
            public val reasonBytes: ByteArray,
            public val initiator: Initiator,
            cause: Throwable? = null,
        ) : ConnectionLost(
                "transport closed by $initiator: code 0x${code.toString(16)}${if (reason.isEmpty()) "" else " ($reason)"}",
                cause,
            ) {
            init {
                checkCode(code)
            }

            override fun createCopy(): TransportClosed = TransportClosed(code, frameType, reason, reasonBytes, initiator, cause)
        }

        /**
         * CONNECTION_CLOSE with an application error code (frame type 0x1d).
         *
         * @property code The application error code; its meaning belongs to the application protocol (0 for `QuicConnection.close()`).
         * @property reason The reason phrase; the wire copy is cut to 1024 bytes, and a peer's is decoded within that.
         * @property initiator Who closed: our `close` or the peer's.
         */
        public class ApplicationClosed(
            public val code: Long,
            public val reason: String,
            public val initiator: Initiator,
        ) : ConnectionLost("application closed by $initiator: code $code${if (reason.isEmpty()) "" else " ($reason)"}") {
            init {
                checkCode(code)
            }

            override fun createCopy(): ApplicationClosed = ApplicationClosed(code, reason, initiator)
        }

        /**
         * A local timer expired ([TimeoutKind.Idle] or [TimeoutKind.Handshake]); the connection closed without a CONNECTION_CLOSE.
         *
         * @property kind Which timer expired.
         * @property duration The timeout that ran out: the effective idle timeout or `QuicConfig.handshakeTimeout`.
         */
        public class Timeout(
            public val kind: TimeoutKind,
            public val duration: Duration,
        ) : ConnectionLost("$kind timeout after $duration") {
            override fun createCopy(): Timeout = Timeout(kind, duration)
        }

        /**
         * The server offered none of our versions (RFC 9000 section 6).
         *
         * @property offered The version numbers listed in the server's Version Negotiation packet.
         * @property supported Our version numbers, from `QuicConfig.versions`.
         */
        public class VersionNegotiation(
            public val offered: List<Int>,
            public val supported: List<Int>,
        ) : ConnectionLost(
                "version negotiation failed: server offers ${offered.map {
                    "0x" +
                        it.toUInt().toString(
                            16,
                        )
                }}, we support ${supported.map { "0x" + it.toUInt().toString(16) }}",
            ) {
            override fun createCopy(): VersionNegotiation = VersionNegotiation(offered, supported)
        }

        /** The active path failed validation and no other validated path remains (RFC 9000 section 9.3.2). */
        public class NoViablePath : ConnectionLost("no viable path") {
            override fun createCopy(): NoViablePath = NoViablePath()
        }

        /** A Stateless Reset from the peer (RFC 9000 section 10.3): it lost its state; the connection drains without a CONNECTION_CLOSE. */
        public class StatelessReset : ConnectionLost("stateless reset received") {
            override fun createCopy(): StatelessReset = StatelessReset()
        }

        /**
         * The server rejected 0-RTT and its answer leaves no safe way to resend it in 1-RTT (another ALPN, or lower limits
         * than the 0-RTT data already used), or `EarlyDataState.Required` was asked for and 0-RTT was refused or unavailable.
         * The connection closed with NO_ERROR; retry on a new connection.
         */
        @ExperimentalKuicksilverApi
        public class ZeroRttRejected : ConnectionLost("0-RTT rejected") {
            override fun createCopy(): ZeroRttRejected = ZeroRttRejected()
        }

        /** A bug or an unexpected failure inside the stack: the connection is dropped silently (no CONNECTION_CLOSE leaves, the peer sees an idle timeout) and the cause is kept for the report. */
        public class Internal(
            message: String,
            cause: Throwable? = null,
        ) : ConnectionLost(message, cause) {
            override fun createCopy(): Internal = Internal(message ?: "", cause)
        }
    }

    /** A single stream failed; the connection lives on. */
    public sealed class StreamError(
        message: String,
    ) : QuicException(message) {
        /**
         * RESET_STREAM: the sender abandoned the stream.
         *
         * @property streamId The stream that was reset.
         * @property code The application error code carried by RESET_STREAM.
         * @property initiator [Initiator.Peer] on our `input` when the peer reset, [Initiator.Local] on our `output` after
         *   `QuicStream.reset`.
         */
        public class Reset(
            public val streamId: Long,
            public val code: Long,
            public val initiator: Initiator,
        ) : StreamError("stream $streamId reset by $initiator with code $code") {
            init {
                checkCode(code)
            }

            override fun createCopy(): Reset = Reset(streamId, code, initiator)
        }

        /**
         * STOP_SENDING: the receiver no longer wants the stream.
         *
         * @property streamId The stream that was stopped.
         * @property code The application error code carried by STOP_SENDING.
         * @property initiator [Initiator.Peer] on our `output` when the peer stopped, [Initiator.Local] on our `input` after
         *   `QuicStream.stopSending`.
         */
        public class Stopped(
            public val streamId: Long,
            public val code: Long,
            public val initiator: Initiator,
        ) : StreamError("stream $streamId stopped by $initiator with code $code") {
            init {
                checkCode(code)
            }

            override fun createCopy(): Stopped = Stopped(streamId, code, initiator)
        }
    }

    /**
     * `sendDatagram` with a payload above [QuicConnection.maxDatagramSize] (RFC 9221).
     *
     * @property size The payload's size in bytes.
     * @property max The largest payload accepted at the call.
     */
    public class DatagramTooLarge(
        public val size: Int,
        public val max: Int,
    ) : QuicException("datagram of $size bytes exceeds the maximum of $max") {
        override fun createCopy(): DatagramTooLarge = DatagramTooLarge(size, max)
    }

    /**
     * `sendDatagram` on a connection without datagram support (ours or the peer's).
     *
     * @property reason Which side turned datagrams off.
     */
    public class DatagramUnsupported(
        public val reason: DatagramUnsupportedReason,
    ) : QuicException("datagrams unsupported: $reason") {
        override fun createCopy(): DatagramUnsupported = DatagramUnsupported(reason)
    }

    /** The endpoint is closing: `connect` and `accept` after [QuicEndpoint.close] throw it. */
    public class EndpointClosing : QuicException("endpoint is closing") {
        override fun createCopy(): EndpointClosing = EndpointClosing()
    }
}
