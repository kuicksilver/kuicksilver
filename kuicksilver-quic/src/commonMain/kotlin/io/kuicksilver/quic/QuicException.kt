// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

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
         * @property initiator Who closed: we on a protocol error we detected, or the peer.
         */
        public class TransportClosed(
            public val code: Long,
            public val frameType: Long,
            public val reason: String,
            reasonBytes: ByteArray,
            public val initiator: Initiator,
            cause: Throwable? = null,
        ) : ConnectionLost(
                "transport closed by $initiator: code 0x${code.toString(16)}${if (reason.isEmpty()) "" else " ($reason)"}",
                cause,
            ) {
            private val wire: ByteArray = reasonBytes.copyOf()

            /** The reason phrase as it travelled on the wire, at most 1024 bytes; a fresh copy on every read. */
            public val reasonBytes: ByteArray get() = wire.copyOf()

            init {
                checkCode(code)
            }

            /** A copy of this exception, for the coroutines stack-trace recovery. */
            override fun createCopy(): TransportClosed = TransportClosed(code, frameType, reason, wire, initiator, cause)
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

            /** A copy of this exception, for the coroutines stack-trace recovery. */
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
            /** A copy of this exception, for the coroutines stack-trace recovery. */
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
            /** A copy of this exception, for the coroutines stack-trace recovery. */
            override fun createCopy(): VersionNegotiation = VersionNegotiation(offered, supported)
        }

        /**
         * The active path failed validation and no other validated path remains (RFC 9000 section 9.3.2); [cause], when set,
         * says why the path could not carry QUIC (a custom `DatagramIo` may report one).
         */
        public class NoViablePath(
            cause: Throwable? = null,
        ) : ConnectionLost(if (cause == null) "no viable path" else "no viable path: ${cause.message}", cause) {
            /** A copy of this exception, for the coroutines stack-trace recovery. */
            override fun createCopy(): NoViablePath = NoViablePath(cause)
        }

        /** A Stateless Reset from the peer (RFC 9000 section 10.3): it lost its state; the connection drains without a CONNECTION_CLOSE. */
        public class StatelessReset : ConnectionLost("stateless reset received") {
            /** A copy of this exception, for the coroutines stack-trace recovery. */
            override fun createCopy(): StatelessReset = StatelessReset()
        }

        /**
         * The server rejected 0-RTT and chose another ALPN than the ticket's, or `EarlyDataState.Required` was asked for and
         * 0-RTT was refused or unavailable. The connection closed with NO_ERROR; retry on a new connection. (Any other
         * rejection keeps the connection and fails the streams opened early with [StreamError.EarlyDataRejected].)
         */
        @ExperimentalKuicksilverApi
        public class ZeroRttRejected : ConnectionLost("0-RTT rejected") {
            /** A copy of this exception, for the coroutines stack-trace recovery. */
            override fun createCopy(): ZeroRttRejected = ZeroRttRejected()
        }

        /** A bug or an unexpected failure inside the stack: the connection is dropped silently (no CONNECTION_CLOSE leaves, the peer sees an idle timeout) and the cause is kept for the report. */
        public class Internal(
            message: String,
            cause: Throwable? = null,
        ) : ConnectionLost(message, cause) {
            /** A copy of this exception, for the coroutines stack-trace recovery. */
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

            /** A copy of this exception, for the coroutines stack-trace recovery. */
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

            /** A copy of this exception, for the coroutines stack-trace recovery. */
            override fun createCopy(): Stopped = Stopped(streamId, code, initiator)
        }

        /**
         * Client: the server rejected 0-RTT, and this stream, opened before the handshake completed, was reset with all the
         * others (RFC 9001 section 4.6.2: the client "MUST reset the state of all streams"). Nothing of it reached the
         * server; the connection lives on, and what is still wanted goes on a new stream.
         *
         * @property streamId The stream that was reset.
         */
        @ExperimentalKuicksilverApi
        public class EarlyDataRejected(
            public val streamId: Long,
        ) : StreamError("stream $streamId reset: the server rejected 0-RTT") {
            /** A copy of this exception, for the coroutines stack-trace recovery. */
            override fun createCopy(): EarlyDataRejected = EarlyDataRejected(streamId)
        }
    }

    /**
     * `sendDatagram` with a payload above [QuicConnection.maxDatagramSize] (RFC 9221).
     *
     * @property size The payload's size in bytes.
     * @property max The largest payload that fits at the call, 0 also when none fits; with [size][QuicException.DatagramTooLarge.size] 0 it means not even an
     *   empty datagram fits (e.g. a peer `max_datagram_frame_size` of 1).
     */
    public class DatagramTooLarge(
        public val size: Int,
        public val max: Int,
    ) : QuicException("datagram of $size bytes exceeds the maximum of $max") {
        /** A copy of this exception, for the coroutines stack-trace recovery. */
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
        /** A copy of this exception, for the coroutines stack-trace recovery. */
        override fun createCopy(): DatagramUnsupported = DatagramUnsupported(reason)
    }

    /**
     * The UDP socket cannot set the Don't Fragment bit (RFC 9000 section 14: "UDP datagrams MUST NOT be fragmented at the IP
     * layer. In IPv4, the Don't Fragment (DF) bit MUST be set if possible"), so QUIC is not used on it: [DatagramIo.open] and
     * [QuicEndpoint.bind] throw it where no traffic of the socket could get DF (the JVM without the `ksl` native library
     * below JDK 19, which has no `IP_DONTFRAGMENT`; Android or a system refusing both DF modes; the Kotlin/Native portable
     * socket). Where only one address family has no DF ([QuicEndpoint.noDontFragmentFamily]), nothing is sent to it: the
     * path closes, or on the active path the connection ends with [ConnectionLost.TransportClosed] (NO_VIABLE_PATH) caused by
     * it, and a server drops that family's Initials. The HTTP/3 client of kuicksilver-ktor-client falls back to TCP.
     *
     * @property family the address family without DF; null when no traffic of the socket can have DF (the whole socket is
     *   refused), never "unknown".
     * @property detail why DF cannot be set.
     */
    @ExperimentalKuicksilverApi
    public class DontFragmentUnavailable(
        public val family: IpFamily?,
        public val detail: String,
    ) : QuicException(
            "QUIC not used: the UDP socket cannot set Don't Fragment (RFC 9000 section 14) " +
                "${if (family == null) "on any traffic" else "for ${family.label} destinations"}: $detail",
        ) {
        /** A copy of this exception, for the coroutines stack-trace recovery. */
        override fun createCopy(): DontFragmentUnavailable = DontFragmentUnavailable(family, detail)
    }

    /** The endpoint is closing: `connect` and `accept` after [QuicEndpoint.close] throw it. */
    public class EndpointClosing : QuicException("endpoint is closing") {
        /** A copy of this exception, for the coroutines stack-trace recovery. */
        override fun createCopy(): EndpointClosing = EndpointClosing()
    }
}

/** An IP address family, as [QuicException.DontFragmentUnavailable] and [QuicEndpoint.noDontFragmentFamily] name it. */
@ExperimentalKuicksilverApi
public enum class IpFamily(
    /** "IPv4" or "IPv6". */
    public val label: String,
) {
    V4("IPv4"),
    V6("IPv6"),
}
