// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.SocketAddress
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.ClosedByteChannelException
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.ReaderJob
import io.ktor.utils.io.WriterJob
import io.ktor.utils.io.discard
import io.ktor.utils.io.reader
import io.ktor.utils.io.writer
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.io.ConnectionEndedException
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.SessionCache
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsConnection
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.isHandshakeTimeout
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.Volatile
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
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

/**
 * [tls] with [sessions] as the session cache instead of [io.kuicksilver.tls.SessionCache.Default]: a client engine keeps the
 * tickets of each kind of peer in a cache of its own (the Ktor client's `https://` proxies apart from its origins).
 */
@InternalKuicksilverApi
public suspend fun Socket.tls(
    config: TlsConfig,
    context: CoroutineContext,
    sessions: SessionCache,
): TlsSocket {
    if (config.role != TlsRole.Client) {
        throw TlsException.Config("Socket.tls needs a client configuration; use tlsServer for the server side")
    }
    return TlsSocket.start(this, config, context, sessions = sessions)
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
 * [tlsServer] on a socket whose read channel the caller has opened already ([openDeliveringReadChannel]) and read a prefix
 * from: a PROXY protocol header, which arrives before the ClientHello. The TLS session reads [input] from where the caller
 * stopped, so bytes that came in the same segment as the prefix (the ClientHello, early records) are not lost.
 */
@InternalKuicksilverApi
public suspend fun Socket.tlsServer(
    config: TlsConfig,
    input: ByteReadChannel,
    context: CoroutineContext = EmptyCoroutineContext,
): TlsSocket {
    if (config.role != TlsRole.Server) throw TlsException.Config("Socket.tlsServer needs a server configuration")
    return TlsSocket.start(this, config, context, input)
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
    private val rawIn: ByteReadChannel,
    private val rawOut: ByteWriteChannel,
    public val tls: TlsConnection,
    /** The context of the coroutines of this socket. */
    override val coroutineContext: CoroutineContext,
    /** Accepted with [Socket.tlsServer]: [close] ends the write side right after close_notify. */
    private val server: Boolean = false,
) : Socket {
    /** The job of the underlying TCP socket. */
    override val socketContext: Job get() = raw.socketContext

    /** The local address of the underlying TCP socket. */
    override val localAddress: SocketAddress get() = raw.localAddress

    /** The remote address of the underlying TCP socket. */
    override val remoteAddress: SocketAddress get() = raw.remoteAddress

    /** The peer's verified certificate chain, leaf first; empty when it sent none (see [TlsConnection.peerCertificates]). */
    public val peerCertificates: List<Certificate> get() = tls.peerCertificates

    /** The chain this side presents on the connection, leaf first (see [TlsConnection.localCertificates]). */
    @ExperimentalKuicksilverApi
    public val localCertificates: List<Certificate> get() = tls.localCertificates

    /** See [TlsConnection.sniSelectedFor]. */
    @InternalKuicksilverApi
    public val sniSelectedFor: String? get() = tls.sniSelectedFor

    /** See [TlsConnection.sniSelectedAlpn]. */
    @InternalKuicksilverApi
    public val sniSelectedAlpn: List<String>? get() = tls.sniSelectedAlpn

    /** The application protocol agreed through ALPN (RFC 7301), or null when none was negotiated. */
    public val negotiatedAlpn: String? get() = tls.negotiatedAlpn

    // written by attachForWriting, read by close(), which may run on another thread
    @Volatile private var attachedWriter: ReaderJob? = null

    /** The application's side of [attachedWriter], as given to [attachForWriting] (closeFromSocketClose). */
    @Volatile private var attachedChannel: ByteChannel? = null

    @Volatile private var closing = false

    /** Set once [close] began (not by an abort): [attachForReading], on any thread, then starts no relay. */
    @Volatile private var closeBegun = false

    /**
     * This side ended the socket: [close], [abort], or a failure of the application's own write channel ([failTls]). Only
     * then is a read or write past the end a [ConnectionEndedException.LocalClose]: a reset or a broken pipe the write pump
     * met first is the peer's end, and stays one ([transportFailure]).
     */
    @Volatile private var localEnd = false

    /** The transport's failure that ended the socket ([failTls] for a failure the write pump met, not the application's). */
    @Volatile private var transportFailure: Throwable? = null

    /** The cause [endPump] failed the application's write channel with: the pump's own end, never a failed stream. */
    @Volatile private var pumpEnd: Throwable? = null

    /** Runs in [attachForReading] between its checks and the relay's publication (tests: a close or an abort there). */
    @Volatile internal var beforeReadAttachForTest: (() -> Unit)? = null

    /** Runs in [attachForWriting] between its checks and the pump's publication (tests: a close or an abort there). */
    @Volatile internal var beforeWriteAttachForTest: (() -> Unit)? = null

    /**
     * The bound of [close] in all; null: the close waits for the peer to take what is queued (then 3 s at most for its
     * close_notify). 3 s on a client ([Socket.tls]), none on a server ([Socket.tlsServer]): a server's fixed bound cut a slow
     * reader's last response short; whoever accepted the socket bounds it ([setCloseTimeout]).
     */
    @Volatile internal var closeTimeout: Duration? = null

    /** Ends [close]'s wait for the peer's close_notify when it completes ([stopAwaitingPeerCloseOn]); null: wait up to 3 s. */
    @Volatile internal var stopAwaitingPeer: Job? = null

    /**
     * The peer's plaintext goes to the application's channel. A session that failed (a reset, a TLS error) fails that
     * channel, not ends it: ktor's `copyTo` ends its loop on a source closed with a failure as on one closed cleanly and
     * returns normally, so a reset before the application opened its channel, or landing between two of its reads after
     * the last bytes, reached the application as a clean end, and a body delimited by the connection's close passed cut
     * for whole. The channel fails with the session's [TlsException] itself: ktor's channels wrap a failure in
     * `ClosedByteChannelException` where they hand it on, and a second wrapping (ktor's `copyTo` closed the channel with
     * the wrapped failure it caught) hid the [TlsException] two causes deep. A channel opened with
     * [openDeliveringReadChannel] keeps the plaintext relayed before the failure readable (`ReadDelivery`).
     *
     * A channel opened once this side ended the socket ([close], [abort], a failed stream) gets nothing: it fails at
     * once with a [ConnectionEndedException.LocalClose], and no relay reads the session's input, which the close reads and
     * drops from then on (a second reader would race it and take the peer's bytes past the close). A relay that this
     * side's end stops (a read waiting as the socket closes) fails its channel with the same, never with its own
     * cancellation: a CancellationException reaching a reader that was not cancelled reads as its own cancellation.
     */
    @OptIn(InternalAPI::class)
    override fun attachForReading(channel: ByteChannel): WriterJob {
        ended()?.let { return closedForReading(channel, it) }
        // the relay runs under a job of its own, not under the socket's: a coroutine launched under a job that has ended, or
        // that an abort cancels before the coroutine ran, never runs, and ktor fails its channel with that cancellation
        // ("Parent job is Completed", a JobCancellationException) before this side's end could name itself. The socket's
        // end reaches the relay through [endRelay] (close, abort) or the end of the session's input instead
        if (coroutineContext[Job]?.isActive == false) return closedForReading(channel, ended() ?: readEnd())
        val relayParent = Job()
        beforeReadAttachForTest?.invoke()
        val job = relayTo(channel, relayParent)
        attachedReader = job
        // an end that came meanwhile (a close, an abort, a failed transport) may have looked for the relay before it was
        // set: it ends here then (both sides set their own flag before they read the other's, so one of them sees the
        // other's). It cannot read alongside the close's drop either way: the close cancels the session's input
        // (TlsConnection.cancelInput) once the relay it saw has ended, and a relay that came after reads only that input
        ended()?.let { endRelay(job, it) }
        return job
    }

    /** Why the socket ended, once it did: this side's end ([readEnd]) or the transport's failure; null while it stands. */
    private fun ended(): Throwable? = if (closeBegun || localEnd) readEnd() else transportFailure

    /**
     * The application's channel of a socket that ended: it fails at once with [cause], nothing is read for it. The channel
     * fails here, before any coroutine: one launched under the socket's job, completed by then, would never run. The
     * writer job returned, outside that job, has nothing left to do.
     */
    private fun closedForReading(
        channel: ByteChannel,
        cause: Throwable,
    ): WriterJob {
        channel.cancel(cause)
        @OptIn(DelicateCoroutinesApi::class)
        return GlobalScope.writer(Dispatchers.Unconfined, channel) {}
    }

    /**
     * Stops [relay] for the socket's end: its channel fails with [cause] first, so that the relay's cancellation, which the
     * channel would otherwise take as its cause, finds it closed (ktor's channels keep their first cause). It may be called
     * before the relay ran at all, and more than once.
     */
    private fun endRelay(
        relay: WriterJob,
        cause: Throwable,
    ) {
        relay.channel.cancel(cause)
        relay.job.cancel()
    }

    @OptIn(InternalAPI::class)
    private fun relayTo(
        channel: ByteChannel,
        parent: CompletableJob,
    ): WriterJob {
        val relay =
            writer(coroutineContext + parent, channel) {
                relay(channel)
            }
        relay.job.invokeOnCompletion { parent.complete() }
        return relay
    }

    @OptIn(InternalAPI::class)
    private suspend fun relay(channel: ByteChannel) {
        val source = tls.input
        try {
            while (true) {
                if (source.readBuffer.exhausted() && !source.awaitContent()) break
                source.readBuffer.transferTo(channel.writeBuffer)
                channel.flush()
            }
            source.closedCause?.let { throw it }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            // this side ended the socket ([abortTls] ends the session under the relay, a failed stream of the application's
            // as well): the channel fails with that end, not with what the ended session reports ("connection closed").
            // A failure of the transport is reported as the session saw it
            if (localEnd) {
                readDelivery.fail(channel, readEnd())
                throw CancellationException("the TLS socket is closed", e)
            }
            val failure = if (e is ClosedByteChannelException) e.sessionFailure() else e
            // before the writer's own cancel, which then finds the channel closed: what was relayed stays readable
            readDelivery.fail(channel, failure)
            throw failure
        }
        // the session's input ended cleanly under the socket's end ([abortTls] closes the session; the write pump met the
        // transport's failure first): not the peer's close_notify
        endOfRelay()?.let {
            readDelivery.fail(channel, it)
            throw CancellationException("the TLS socket ended")
        }
    }

    /** What the relay reports once the socket ended under it: this side's end, else the transport's failure; null else. */
    private fun endOfRelay(): Throwable? = if (localEnd) readEnd() else transportFailure

    /** This side ended the socket: what a read gets from then on. */
    private fun readEnd(): ConnectionEndedException.LocalClose =
        ConnectionEndedException.LocalClose("the TLS socket is closed: nothing more is read")

    /** This side ended the socket: what a write gets from then on. */
    private fun writeEnd(): ConnectionEndedException.LocalClose =
        ConnectionEndedException.LocalClose("the TLS socket is closed: nothing more is written")

    /**
     * The relay above, once attached: [close] and [abortTls] end it. It may wait for room in the application's channel:
     * an application that stopped reading would hold it for good otherwise.
     */
    @Volatile private var attachedReader: WriterJob? = null

    /** How the relay above fails the application's channel ([openDeliveringReadChannel]). */
    internal val readDelivery: ReadDelivery = ReadDelivery()

    /** The [TlsException] under ktor's wrappers (and, on the JVM in debug mode, their stack-trace-recovery copies), else this. */
    private fun ClosedByteChannelException.sessionFailure(): Throwable {
        var c: Throwable? = cause
        while (c is ClosedByteChannelException) c = c.cause
        return c as? TlsException ?: this
    }

    /**
     * The application's plaintext goes through the TLS session to the raw socket. When the application's channel fails
     * (a handler that threw mid-response), or the pump does, the connection never ends with `close_notify`: a
     * `close_notify` and a FIN would end the stream as if complete, and a peer reading a body delimited by the
     * connection's close would take the cut one for the whole. It ends with the fatal alert internal_error after what was
     * sent, then a FIN, where OpenSSL can send one (RFC 9846 section 6.1; `failTls`), else with a reset (`abortTls`). A
     * channel closed normally ends with `close_notify` on [close].
     *
     * A channel opened once this side ended the socket ([close], [abort], a failed stream) fails at once with a
     * [ConnectionEndedException.LocalClose] and starts no pump: a pump launched under the socket's completed job never ran
     * (the application's write failed with a JobCancellationException), and one started while the close is under way
     * met the session's closed output and failed the stream, which turns the graceful close into an alert (RFC 9846
     * section 6.1). Only a failure of the application's own channel fails the stream with internal_error: one the pump
     * meets in the session's output while the socket ends (a close under way, an abort) is that end, and a transport
     * failure (a reset, a broken pipe) is the peer's end, reported as such to the reader too.
     */
    @OptIn(InternalAPI::class)
    override fun attachForWriting(channel: ByteChannel): ReaderJob {
        writeEnded()?.let { return closedForWriting(channel, it) }
        // as for the read relay: the pump runs under a job of its own, ended by [endPump] (close, abort), its channel's end
        // or the session's output
        if (coroutineContext[Job]?.isActive == false) return closedForWriting(channel, writeEnded() ?: writeEnd())
        val pumpParent = Job()
        beforeWriteAttachForTest?.invoke()
        val pump =
            reader(coroutineContext + pumpParent, channel) {
                var appFailure = false
                try {
                    // ktor's copyTo, without its close of the destination with the failure: closing the TLS output sends
                    // close_notify, which would race the abort
                    while (true) {
                        val more =
                            try {
                                !channel.readBuffer.exhausted() || channel.awaitContent()
                            } catch (e: CancellationException) {
                                throw e
                            } catch (e: Throwable) {
                                appFailure = true
                                throw e
                            }
                        if (!more) break
                        channel.readBuffer.transferTo(tls.output.writeBuffer)
                        tls.output.flush()
                    }
                    channel.closedCause?.let {
                        appFailure = true
                        throw it
                    }
                } catch (e: Throwable) {
                    val ours = pumpEnd?.let { end -> generateSequence(e) { it.cause }.any { it === end } } ?: false
                    when {
                        e is CancellationException || ours -> {}

                        appFailure -> {
                            failTls(e, applicationFailure = true)
                        }

                        // the session's output ended under this side's end (an abort closes it under the pump): no stream
                        // failed, and the application's channel gets that end, not the closed output's "connection closed"
                        closeBegun || localEnd -> {
                            channel.cancel(pumpEndCause())
                        }

                        // the transport failed under the pump: the peer's end
                        else -> {
                            failTls(e, applicationFailure = false)
                        }
                    }
                    throw e
                }
                tls.output.flushAndClose()
            }
        pump.job.invokeOnCompletion { pumpParent.complete() }
        attachedChannel = channel
        attachedWriter = pump
        // an end that came meanwhile may have looked for the pump before it was set: it ends here then, without a failed
        // stream (the pump writes nothing into the ended session, and a graceful close stays one)
        writeEnded()?.let { endPump(pump, it) }
        return pump
    }

    /** Why a write fails once the socket ended: this side's end ([writeEnd]) or the transport's failure; null while it stands. */
    private fun writeEnded(): Throwable? = if (closeBegun || localEnd) writeEnd() else transportFailure

    /** The application's write channel of a socket that ended: it fails at once with [cause], nothing is sent from it. */
    private fun closedForWriting(
        channel: ByteChannel,
        cause: Throwable,
    ): ReaderJob {
        channel.cancel(cause)
        @OptIn(DelicateCoroutinesApi::class)
        return GlobalScope.reader(Dispatchers.Unconfined, channel) {}
    }

    /**
     * Stops [pump] for the socket's end: the application's channel fails with [cause] (a writer waiting for room gets it,
     * not the pump's cancellation), and the pump, which then finds the channel failed by this side, fails no stream.
     */
    private fun endPump(
        pump: ReaderJob,
        cause: Throwable,
    ) {
        if (pumpEnd == null) pumpEnd = cause
        pump.channel.cancel(pumpEnd)
        pump.job.cancel()
    }

    /** The cause the write channel fails with for the socket's end, [pumpEnd] once one was chosen. */
    private fun pumpEndCause(): Throwable = pumpEnd ?: (writeEnded() ?: writeEnd()).also { pumpEnd = it }

    /**
     * Graceful: pending plaintext is encrypted and flushed, `close_notify` is sent, then the raw socket closes; on a server
     * the raw socket's write side ends right after `close_notify` (its FIN), and the client's `close_notify` or FIN is
     * awaited only after that (at most 3 s), so a client that never answers does not hold the FIN back. Runs in the
     * socket's scope. On a client ([Socket.tls]) bounded: when the raw socket has not closed after 3 s in all (a peer that
     * stopped reading holds the flush, `close_notify` and the raw socket's last write), what is still queued is dropped, the
     * TLS session is freed and the raw socket is aborted as by [abort], which releases its descriptor. On a server ([Socket.tlsServer]) the close
     * waits for the client to take the last response, however slowly it reads; whoever accepted the socket bounds it.
     * The application reads nothing after the close: what the peer still sends is read and dropped from then on, so the
     * wait for its `close_notify` lasts while the peer sends, not while nobody reads (RFC 9846 section 6.1 lets either side
     * close its read side without waiting; reading on avoids resetting the connection under the peer's unread input). On a
     * client the drop stops past 256 KiB (`TlsConnection.INPUT_DROP_LIMIT`) and the close comes under the rest: a response
     * nobody reads is cut, not downloaded until the bound. On a server it goes on until the client's `close_notify`, its FIN
     * or the close's end, which whoever accepted the socket bounds: a reset could erase the last response. To
     * keep reading after the request, close only the write channel ([openWriteChannel]'s `flushAndClose`): `close_notify`
     * is sent and the read channel delivers the rest until the peer's.
     */
    override fun close() {
        closeBegun = true
        localEnd = true
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
                // the application reads no more: its relay ends, and the session's input is cancelled, so that what is still
                // coming is read and dropped (TlsConnection.cancelInput) and the peer's close_notify is not held behind it
                // (and the peer's writes behind that) until the bound (a client's session stops reading past 256 KiB
                // dropped, and the close comes under the rest); a relay attached as the close began fails on the cancelled
                // input, so nothing reads it alongside the drop
                attachedReader?.let {
                    endRelay(it, readEnd())
                    it.job.join()
                }
                tls.cancelInput(CancellationException("the TLS socket is closed: nothing more is read"))
                attachedWriter?.let { rj ->
                    runCatching { attachedChannel?.closeFromSocketClose() ?: rj.channel.flushAndClose() }
                    rj.job.join()
                }
                // a server's FIN follows its close_notify at once, and the client's close_notify (or its FIN) is awaited
                // after it (RFC 6455 section 5.5.1: "The server MUST close the underlying TCP connection immediately"; RFC
                // 9112 section 9.6: the write side first, then reading until the client closes); a client's FIN waits
                // for the server's close_notify, as before
                val finAtOnce: (suspend () -> Unit)? =
                    if (server) {
                        { runCatching { rawOut.flushAndClose() } }
                    } else {
                        null
                    }
                tls.shutdown(drainTimeout = bound, stopAwaitingPeer = stopAwaitingPeer, afterSent = finAtOnce)
            } finally {
                tls.close()
                runCatching { rawOut.flushAndClose() } // everything handed to the socket's write channel reaches the wire before FIN
                raw.close()
            }
        }
    }

    /** Closes the socket, like [close]. */
    override fun dispose(): Unit = close()

    /** The socket under the TLS session ([bytesSent]). */
    internal val rawSocket: Socket get() = raw

    /**
     * Ends the connection at once ([abort], and [close] past its bound): the TLS session is released without
     * `close_notify`, which ends the pumps, and the raw socket is aborted. Cancelling the raw socket's job is not enough:
     * its descriptor closes only once `close()` was called and both of its loops have ended, and on the JVM a write loop
     * facing a full send buffer does not see a cancellation (it spins in `SocketChannel.write`). [local] false: the
     * transport failed ([transportFailure]), and the application's channels get that failure instead of a LocalClose.
     */
    internal fun abortTls(local: Boolean = true) {
        if (local) localEnd = true
        closing = true
        // the application's pumps first, so that their channels take this end before the closed session's own failure
        attachedWriter?.let { endPump(it, writeEnded() ?: writeEnd()) }
        attachedReader?.let { endRelay(it, ended() ?: readEnd()) }
        // the raw socket first: the session's close ends its output, and a raw writer still draining would send a FIN
        // ahead of the reset
        @OptIn(InternalKuicksilverApi::class)
        raw.abort()
        tls.close()
        // and the application's pumps once more (an attach that published meanwhile): the write pump waits for the
        // application's next bytes, the read relay for room in its channel; neither would end otherwise
        attachedWriter?.let { endPump(it, writeEnded() ?: writeEnd()) }
        attachedReader?.let { endRelay(it, ended() ?: readEnd()) }
    }

    /**
     * Ends the connection after the application's stream failed with [cause]: the session sends internal_error after
     * everything sent before ([TlsConnection.abortOutput]; a TLS 1.3 server, a TLS 1.2 client), the raw socket then
     * sends a FIN (the peer fails on the alert, so a FIN cannot pass for a clean end), reads and drops what the peer still
     * sends until it closes ([lingerAfterAlert]: a reset over that input could erase the alert before the peer read it), and
     * closes; it is reset when it has not closed after [ALERT_CLOSE_TIMEOUT] (a peer that stopped reading). Where no alert can be sent, or the transport did
     * not take it, the connection is reset at once (`abortTls`). [applicationFailure] false: the pump met the transport's
     * failure (a reset, a broken pipe), which is the peer's end, not this side's: the reader gets it, not a LocalClose.
     */
    private suspend fun failTls(
        cause: Throwable,
        applicationFailure: Boolean,
    ) {
        if (applicationFailure) {
            localEnd = true
        } else if (transportFailure == null) {
            transportFailure = cause
        }
        val alerted = runCatching { tls.abortOutput(cause, ALERT_CLOSE_TIMEOUT) }.getOrDefault(false)
        if (!alerted) {
            abortTls(local = applicationFailure)
            return
        }
        closing = true
        tls.close()
        @OptIn(DelicateCoroutinesApi::class)
        GlobalScope.launch(Dispatchers.Default) {
            // outside the socket's scope, whose job ends only after this pump: the alert and a FIN, then what the peer still
            // sends is read and dropped until it closes (lingerAfterAlert, once the session's pumps no longer read), bounded
            val closed =
                withTimeoutOrNull(ALERT_CLOSE_TIMEOUT) {
                    runCatching { rawOut.flushAndClose() }
                    tls.closeAndAwaitPumps()
                    rawIn.lingerAfterAlert(ALERT_LINGER)
                    raw.close()
                    raw.socketContext.join()
                }
            if (closed == null) abortTls(local = applicationFailure)
        }
    }

    /** The factory behind [Socket.tls] and [Socket.tlsServer]; internal, so no empty companion is part of the public ABI. */
    internal companion object {
        /** How long a client's [close] may take in all before it stops waiting for the peer. */
        internal val CLOSE_TIMEOUT: Duration = 3.seconds

        /** How long a failed stream's internal_error alert and FIN may take to leave before the connection is reset instead. */
        internal val ALERT_CLOSE_TIMEOUT: Duration = 3.seconds

        /**
         * How long a server's failed handshake, or a failed stream's alert, reads and drops what the peer still sends before
         * the socket closes ([lingerAfterAlert]).
         */
        internal val ALERT_LINGER: Duration = 2.seconds

        /**
         * [ALERT_LINGER] for a client's failed handshake: shorter, since the error reaches the application only after it. A
         * server has sent its whole flight before the client's alert, so little is in flight; the server closes on the alert
         * (RFC 9846 section 6.2), and its FIN usually ends the wait at once.
         */
        internal val CLIENT_ALERT_LINGER: Duration = 250.milliseconds

        /** How much a failed handshake reads and drops at most before the socket closes ([lingerAfterAlert]). */
        internal const val ALERT_LINGER_BYTES: Long = 256L * 1024

        /**
         * After a fatal alert (a failed handshake, a failed stream), whose FIN is on its way: reads and drops what the peer
         * still sends until it closes too, for [bound] and [ALERT_LINGER_BYTES] at most, before the socket closes. Nothing
         * of it reaches TLS: the session has ended, and only the transport is drained. A close over input that
         * is unread, or that arrives after it, makes the kernel answer with a reset, and a reset can erase the alert from the
         * peer's receive buffer before the peer read it (Windows discards what it has not delivered): a client that had sent
         * its request right after its Finished (TLS 1.3, a server that requires a certificate it did not send) saw "connection
         * aborted" instead of certificate_required. The close is staged as RFC 9112 section 9.6 describes for the last
         * response: the write side first, then reading until the peer's close, then the full close.
         */
        private suspend fun ByteReadChannel.lingerAfterAlert(bound: Duration) {
            try {
                withTimeoutOrNull(bound) { discard(ALERT_LINGER_BYTES) }
            } catch (_: CancellationException) {
                currentCoroutineContext().ensureActive() // a cancelled caller; a channel cancelled under it is no reason to stop
            } catch (_: Throwable) {
                // the peer reset the connection, or the socket failed: nothing left to protect the alert from
            }
        }

        internal suspend fun start(
            raw: Socket,
            config: TlsConfig,
            context: CoroutineContext,
            opened: ByteReadChannel? = null,
            sessions: SessionCache? = null,
        ): TlsSocket {
            val ctx = raw.coroutineContext + context
            val rawIn = opened ?: raw.openDeliveringReadChannel()
            val rawOut = raw.openWriteChannel(autoFlush = true)
            val tls =
                try {
                    if (config.role ==
                        TlsRole.Client
                    ) {
                        if (sessions == null) {
                            TlsConnection.client(rawIn, rawOut, config, ctx)
                        } else {
                            TlsConnection.client(rawIn, rawOut, config, ctx, sessions)
                        }
                    } else {
                        TlsConnection.server(rawIn, rawOut, config, ctx)
                    }
                } catch (t: Throwable) {
                    try {
                        runCatching { rawOut.flushAndClose() }
                        // not after the handshake's own deadline (a silent peer has nothing in flight to protect the alert
                        // from) nor when the caller was cancelled (a stop, its own deadline)
                        if (t !is CancellationException && !t.isHandshakeTimeout) {
                            rawIn.lingerAfterAlert(if (config.role == TlsRole.Client) CLIENT_ALERT_LINGER else ALERT_LINGER)
                        }
                    } catch (_: CancellationException) {
                        // cancelled while lingering (a stop, the caller's deadline): the handshake's failure stays the one thrown
                    } finally {
                        raw.close()
                    }
                    throw t
                }
            return TlsSocket(raw, rawIn, rawOut, tls, ctx, server = config.role == TlsRole.Server).also {
                if (config.role == TlsRole.Client) it.closeTimeout = CLOSE_TIMEOUT
            }
        }
    }
}
