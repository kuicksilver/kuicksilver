// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.SocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.ClosedByteChannelException
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.ReaderJob
import io.ktor.utils.io.WriterJob
import io.ktor.utils.io.reader
import io.ktor.utils.io.writer
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsConnection
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.Volatile
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Wraps a connected ktor-network [Socket] in TLS as a client (module `kuicksilver-ktor-network`, ADR-0005): the
 * handshake completes before this returns; the result is a [Socket] whose channels carry plaintext.
 * Unlike ktor's own `Socket.tls`, this works on every platform and offers TLS 1.3, ALPN and pins.
 */
public suspend fun Socket.tls(
    config: TlsConfig,
    context: CoroutineContext = EmptyCoroutineContext,
): TlsSocket {
    if (config.role !=
        TlsRole.Client
    ) {
        throw TlsException.Config("Socket.tls needs a client configuration; use tlsServer for the server side")
    }
    return TlsSocket.start(this, config, context)
}

/** Accepts TLS on a server-side [Socket] (after `ServerSocket.accept()`). */
public suspend fun Socket.tlsServer(
    config: TlsConfig,
    context: CoroutineContext = EmptyCoroutineContext,
): TlsSocket {
    if (config.role != TlsRole.Server) throw TlsException.Config("Socket.tlsServer needs a server configuration")
    return TlsSocket.start(this, config, context)
}

/**
 * A [Socket] over a [TlsConnection]; closing it sends `close_notify` and closes the underlying socket.
 *
 * @property tls the TLS session underneath, for what [Socket] cannot express: the protocol version, the exporter
 *   (RFC 9846 section 7.5), the `tls-exporter` channel binding (RFC 9266) and key updates. Read and write through the
 *   socket's channels, not through `tls.input`/`tls.output` as well.
 */
public class TlsSocket private constructor(
    private val raw: Socket,
    private val rawOut: ByteWriteChannel,
    public val tls: TlsConnection,
    override val coroutineContext: CoroutineContext,
) : Socket {
    override val socketContext: Job get() = raw.socketContext
    override val localAddress: SocketAddress get() = raw.localAddress
    override val remoteAddress: SocketAddress get() = raw.remoteAddress

    /** The peer's verified certificate chain, leaf first; empty when it sent none (see [TlsConnection.peerCertificates]). */
    public val peerCertificates: List<Certificate> get() = tls.peerCertificates

    /** The application protocol agreed through ALPN (RFC 7301), or null when none was negotiated. */
    public val negotiatedAlpn: String? get() = tls.negotiatedAlpn

    private var attachedWriter: ReaderJob? = null
    private var closing = false

    /**
     * The bound of [close] in all; null: the close waits for the peer to take what is queued (then 3 s at most for its
     * close_notify). 3 s on a client ([Socket.tls]), none on a server ([Socket.tlsServer]): a server's fixed bound cut a slow
     * reader's last response short; whoever accepted the socket bounds it ([setCloseTimeout]).
     */
    @Volatile internal var closeTimeout: Duration? = null

    /**
     * The peer's plaintext goes to the application's channel. A session that failed (a reset, a TLS error) fails that
     * channel, not ends it: ktor's `copyTo` ends its loop on a source closed with a failure as on one closed cleanly and
     * returns normally, so a reset before the application opened its channel, or landing between two of its reads after
     * the last bytes, reached the application as a clean end, and a body delimited by the connection's close passed cut
     * for whole. The channel fails with the session's [TlsException] itself: ktor's channels wrap a failure in
     * `ClosedByteChannelException` where they hand it on, and a second wrapping (ktor's `copyTo` closed the channel with
     * the wrapped failure it caught) hid the [TlsException] two causes deep.
     */
    @OptIn(InternalAPI::class)
    override fun attachForReading(channel: ByteChannel): WriterJob =
        writer(coroutineContext, channel) {
            val source = tls.input
            try {
                while (true) {
                    if (source.readBuffer.exhausted() && !source.awaitContent()) break
                    source.readBuffer.transferTo(channel.writeBuffer)
                    channel.flush()
                }
                source.closedCause?.let { throw it }
            } catch (e: ClosedByteChannelException) {
                throw e.sessionFailure()
            }
        }

    /** The [TlsException] under ktor's wrappers (and, on the JVM in debug mode, their stack-trace-recovery copies), else this. */
    private fun ClosedByteChannelException.sessionFailure(): Throwable {
        var c: Throwable? = cause
        while (c is ClosedByteChannelException) c = c.cause
        return c as? TlsException ?: this
    }

    /**
     * The application's plaintext goes through the TLS session to the raw socket. When the application's channel fails
     * (a handler that threw mid-response), or the pump does, the connection is aborted ([abortTls]: no `close_notify`,
     * the raw socket reset): a `close_notify` and a FIN would end the stream as if complete, and a peer reading a body
     * delimited by the connection's close would take the cut one for the whole. A channel closed normally ends with
     * `close_notify` on [close].
     */
    @OptIn(InternalAPI::class)
    override fun attachForWriting(channel: ByteChannel): ReaderJob =
        reader(coroutineContext, channel) {
            try {
                // ktor's copyTo, without its close of the destination with the failure: closing the TLS output sends
                // close_notify, which would race the abort
                while (true) {
                    if (channel.readBuffer.exhausted() && !channel.awaitContent()) break
                    channel.readBuffer.transferTo(tls.output.writeBuffer)
                    tls.output.flush()
                }
                channel.closedCause?.let { throw it }
            } catch (e: Throwable) {
                if (e !is CancellationException) abortTls()
                throw e
            }
            tls.output.flushAndClose()
        }.also {
            attachedWriter =
                it
        }

    /**
     * Graceful: pending plaintext is encrypted and flushed, `close_notify` is sent, then the raw socket closes. Runs in the
     * socket's scope. On a client ([Socket.tls]) bounded: when the raw socket has not closed after 3 s in all (a peer that
     * stopped reading holds the flush, `close_notify` and the raw socket's last write), what is still queued is dropped, the
     * TLS session is freed and the raw socket is aborted as by [abort], which releases its descriptor. On a server ([Socket.tlsServer]) the close
     * waits for the client to take the last response, however slowly it reads; whoever accepted the socket bounds it.
     */
    override fun close() {
        if (closing) return
        closing = true
        val bound = closeTimeout
        if (bound != null) {
            @OptIn(DelicateCoroutinesApi::class)
            GlobalScope.launch(Dispatchers.Default) {
                // outside the socket's scope: its job completes only after the graceful close below (a child) has ended
                if (withTimeoutOrNull(bound) { raw.socketContext.join() } == null) abortTls()
            }
        }
        launch {
            try {
                attachedWriter?.let { rj ->
                    runCatching { rj.channel.flushAndClose() }
                    rj.job.join()
                }
                tls.shutdown(drainTimeout = bound)
            } finally {
                tls.close()
                runCatching { rawOut.flushAndClose() } // everything handed to the socket's write channel reaches the wire before FIN
                raw.close()
            }
        }
    }

    override fun dispose(): Unit = close()

    /** The socket under the TLS session ([bytesSent]). */
    internal val rawSocket: Socket get() = raw

    /**
     * Ends the connection at once ([abort], and [close] past its bound): the TLS session is released without
     * `close_notify`, which ends the pumps, and the raw socket is aborted. Cancelling the raw socket's job is not enough:
     * its descriptor closes only once `close()` was called and both of its loops have ended, and on the JVM a write loop
     * facing a full send buffer does not see a cancellation (it spins in `SocketChannel.write`).
     */
    internal fun abortTls() {
        closing = true
        // the raw socket first: the session's close ends its output, and a raw writer still draining would send a FIN
        // ahead of the reset
        @OptIn(InternalKuicksilverApi::class)
        raw.abort()
        tls.close()
    }

    /** The factory behind [Socket.tls] and [Socket.tlsServer]; internal, so no empty companion is part of the public ABI. */
    internal companion object {
        /** How long a client's [close] may take in all before it stops waiting for the peer. */
        internal val CLOSE_TIMEOUT: Duration = 3.seconds

        internal suspend fun start(
            raw: Socket,
            config: TlsConfig,
            context: CoroutineContext,
        ): TlsSocket {
            val ctx = raw.coroutineContext + context
            val rawIn = raw.openReadChannel()
            val rawOut = raw.openWriteChannel(autoFlush = true)
            val tls =
                try {
                    if (config.role ==
                        TlsRole.Client
                    ) {
                        TlsConnection.client(rawIn, rawOut, config, ctx)
                    } else {
                        TlsConnection.server(rawIn, rawOut, config, ctx)
                    }
                } catch (t: Throwable) {
                    runCatching { rawOut.flushAndClose() }
                    raw.close()
                    throw t
                }
            return TlsSocket(raw, rawOut, tls, ctx).also { if (config.role == TlsRole.Client) it.closeTimeout = CLOSE_TIMEOUT }
        }
    }
}
