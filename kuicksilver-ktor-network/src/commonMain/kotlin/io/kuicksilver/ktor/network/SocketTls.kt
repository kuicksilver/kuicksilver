// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.SocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.ReaderJob
import io.ktor.utils.io.WriterJob
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.reader
import io.ktor.utils.io.writer
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsConnection
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext

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
 *   (RFC 8446 section 7.5), the `tls-exporter` channel binding (RFC 9266) and key updates. Read and write through the
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

    override fun attachForReading(channel: ByteChannel): WriterJob = writer(coroutineContext, channel) { tls.input.copyTo(channel) }

    override fun attachForWriting(channel: ByteChannel): ReaderJob =
        reader(coroutineContext, channel) {
            channel.copyTo(tls.output)
            tls.output.flushAndClose()
        }.also {
            attachedWriter =
                it
        }

    /** Graceful: pending plaintext is encrypted and flushed, `close_notify` is sent, then the raw socket closes. Runs in the socket's scope. */
    override fun close() {
        if (closing) return
        closing = true
        launch {
            try {
                attachedWriter?.let { rj ->
                    runCatching { rj.channel.flushAndClose() }
                    rj.job.join()
                }
                tls.shutdown()
            } finally {
                tls.close()
                runCatching { rawOut.flushAndClose() } // everything handed to the socket's write channel reaches the wire before FIN
                raw.close()
            }
        }
    }

    override fun dispose(): Unit = close()

    /** The factory behind [Socket.tls] and [Socket.tlsServer]; internal, so no empty companion is part of the public ABI. */
    internal companion object {
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
            return TlsSocket(raw, rawOut, tls, ctx)
        }
    }
}
