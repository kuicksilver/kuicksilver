// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Capsule
import io.kuicksilver.http3.CapsuleConfig
import io.kuicksilver.http3.CapsuleStream
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3Request
import io.kuicksilver.http3.Http3Stream
import io.kuicksilver.http3.WebTransportBidiStream
import io.kuicksilver.http3.WebTransportCloseInfo
import io.kuicksilver.http3.WebTransportException
import io.kuicksilver.http3.WebTransportReceiveStream
import io.kuicksilver.http3.WebTransportSendStream
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.runtime.DatagramDemux
import io.kuicksilver.http3.runtime.H3Session
import io.kuicksilver.http3.runtime.connect
import io.kuicksilver.quic.DatagramSendResult
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * One WebTransport session (draft-ietf-webtrans-http3-16): the Extended CONNECT [stream], spoken as the Capsule Protocol,
 * and the WebTransport streams routed to it.
 *
 * Capsules: WT_CLOSE_SESSION (terminal, at most 4 + 1024 bytes) and WT_DRAIN_SESSION (empty) are read, every other type
 * (flow-control capsules included, section 5.1) is skipped unbuffered by the capsule stream. The peer's streams wait in
 * [bidiIn] and [uniIn] until the application accepts them; how many can be open at once is bounded by the QUIC stream
 * limits we grant (`maxBidiStreams`, `maxUniStreams`), since a stream counts against them until it is finished.
 *
 * State that the router and the stream pumps share ([streams], the channels' contents at close) is touched on the
 * session's dispatcher only.
 */
internal class WtSessionImpl(
    private val h3: H3Session,
    internal val stream: Http3Stream,
    override val headers: Http3Headers,
    override val protocol: String?,
) : WebTransportSession,
    WtSessionSink {
    override val sessionId: Long get() = stream.streamId

    /** The CONNECT stream as capsules; built first, so a peer message that cannot carry capsules fails the accept. */
    internal val capsules: CapsuleStream = stream.useCapsuleProtocol(CAPSULES)
    private val bidiIn = Channel<QuicStream>(Channel.UNLIMITED)
    private val uniIn = Channel<QuicStream>(Channel.UNLIMITED)
    private val streams = HashSet<WtStreamImpl>()
    private val datagramsIn = Channel<ByteArray>(DatagramDemux.QUEUE, BufferOverflow.DROP_OLDEST)
    private val drainFlow = MutableStateFlow(false)
    private val closedInfo = CompletableDeferred<WebTransportCloseInfo>()
    private val watchers = ArrayList<Job>()

    /** The peer's FIN was read (session dispatcher only). */
    private var peerFinished = false
    override val drainRequested: StateFlow<Boolean> get() = drainFlow
    override val closed: Deferred<WebTransportCloseInfo> get() = closedInfo

    /** Starts reading capsules and datagrams; session dispatcher only, right after the router registration. */
    fun start() {
        watchers += h3.scope.launch { readCapsules() }
        watchers +=
            h3.scope.launch {
                try {
                    capsules.datagrams.collect { datagramsIn.trySend(it) }
                } finally {
                    datagramsIn.close()
                }
            }
        // the connection's end cancels the session's coroutines with it: the session is over with the connection's reason
        h3.closed.invokeOnCompletion {
            val cause = if (h3.closed.isCompleted && !h3.closed.isCancelled) h3.closed.getCompleted() else it
            if (closedInfo.complete(WebTransportCloseInfo(0, "", cause ?: sessionClosed()))) {
                bidiIn.close()
                uniIn.close()
                datagramsIn.close()
            }
        }
        // an HTTP/3 GOAWAY asks every session to wind down (section 4.7)
        watchers += h3.scope.launch { h3.goAwayReceived.first { it != null }.let { drainFlow.value = true } }
    }

    override fun onStream(
        stream: QuicStream,
        bidi: Boolean,
    ) {
        if ((if (bidi) bidiIn else uniIn).trySend(stream).isFailure) goneRaw(stream, bidi)
    }

    private suspend fun readCapsules() {
        try {
            capsules.capsules.collect { c ->
                when (c.type) {
                    WtCloseCapsule.TYPE -> {
                        val (code, reason) =
                            WtCloseCapsule.decode(c.value) ?: malformed("WT_CLOSE_SESSION with a malformed code or reason")
                        terminate(WebTransportCloseInfo(code, reason, null), End.ByPeer)
                    }

                    WT_DRAIN_SESSION -> {
                        if (c.value.isNotEmpty()) malformed("WT_DRAIN_SESSION with a value")
                        drainFlow.value = true
                    }
                }
            }
            peerFinished = true // the peer's FIN on a capsule boundary: its side of the CONNECT stream is over
            terminate(WebTransportCloseInfo(0, "", null), End.ByPeer) // without a capsule before it: code 0 (section 6)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            terminate(WebTransportCloseInfo(0, "", e), End.Failed)
        }
    }

    /** A malformed message on the CONNECT stream (section 6): reset and stopped with H3_MESSAGE_ERROR. */
    private fun malformed(reason: String): Nothing {
        stream.reset(Http3ErrorCode.MESSAGE_ERROR)
        stream.stopSending(Http3ErrorCode.MESSAGE_ERROR)
        throw Http3Exception.MessageError(sessionId, reason)
    }

    private enum class End { Locally, ByPeer, Failed }

    /**
     * The session is over: [closed] completes with [info], the session's streams end with WT_SESSION_GONE, and the CONNECT
     * stream is ended in both directions so the connection's session slot frees. The first call wins.
     */
    private suspend fun terminate(
        info: WebTransportCloseInfo,
        end: End,
    ): Boolean {
        if (!closedInfo.complete(info)) return false
        val caller = currentCoroutineContext()[Job] // the capsule reader when the peer ended the session: it reads on to the FIN
        // not cancellable: [closed] is already complete, so a caller cancelled from here on must not leave the rest
        // undone (withContext also throws a caller's cancellation when it returns, so everything is started inside)
        val connectEnd =
            withContext(NonCancellable + h3.dispatcher) {
                bidiIn.close()
                uniIn.close()
                for (ch in listOf(bidiIn to true, uniIn to false)) {
                    while (true) goneRaw(ch.first.tryReceive().getOrNull() ?: break, ch.second)
                }
                for (s in streams.toList()) s.gone()
                streams.clear()
                datagramsIn.close()
                // the capsule reader (the first watcher) goes on to the peer's FIN, which ends the CONNECT stream's other side
                watchers.drop(1).forEach { if (it !== caller) it.cancel() }
                when (end) {
                    // in the connection's scope: cancelling close() stops only its wait, the CONNECT is ended all the same
                    End.Locally -> {
                        h3.scope.launch { endConnect(WtCloseCapsule.encode(info.code, info.reason)) }
                    }

                    // our FIN answers the peer's; its own FIN follows its capsule, and a peer that never sends it is stopped
                    End.ByPeer -> {
                        h3.scope.launch { endConnect(null) }
                    }

                    End.Failed -> {
                        runCatching { stream.reset(Http3ErrorCode.WT_SESSION_GONE) }
                        runCatching { stream.stopSending(Http3ErrorCode.WT_SESSION_GONE) }
                        null
                    }
                }
            }
        if (end == End.Locally) connectEnd?.join()
        return true
    }

    /**
     * Ends the CONNECT stream: [closeCapsule] if any, then FIN, both within [CLOSE_TIMEOUT] (the peer's flow-control
     * credit has no deadline of its own: the stream is reset when it runs out); then waits as long for the peer's FIN,
     * and only when it does not come sends STOP_SENDING WT_SESSION_GONE, so the receive side ends either way. Stopping at
     * once raced the peer's reading of our capsule: Chrome then reported a lost connection instead of the close code.
     */
    private suspend fun endConnect(closeCapsule: ByteArray?) {
        val written =
            withTimeoutOrNull(CLOSE_TIMEOUT) {
                try {
                    closeCapsule?.let { capsules.send(Capsule(WtCloseCapsule.TYPE, it)) }
                    capsules.close()
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Throwable) {
                    // the stream was reset or the connection closed: nothing more to end
                }
                true
            }
        if (written == null) runCatching { stream.reset(Http3ErrorCode.WT_SESSION_GONE) }
        // the peer's FIN answers a close (ours or its own capsule's): once it came there is nothing to stop
        withTimeoutOrNull(CLOSE_TIMEOUT) { watchers.firstOrNull()?.join() }
        if (peerFinished) return
        runCatching { stream.stopSending(Http3ErrorCode.WT_SESSION_GONE) }
    }

    /**
     * The CONNECT stream ended both ways (its exchange is over): the session is over if nothing ended it before, and its
     * id is forgotten by the router, which rejects late streams. Session dispatcher only.
     */
    fun ended() {
        h3.wt.unregister(sessionId)
        if (!closedInfo.isCompleted) {
            h3.scope.launch {
                terminate(WebTransportCloseInfo(0, "", WebTransportException.SessionClosed("the CONNECT stream ended")), End.Failed)
            }
        }
    }

    private fun goneRaw(
        st: QuicStream,
        bidi: Boolean,
    ) {
        runCatching { st.stopSending(Http3ErrorCode.WT_SESSION_GONE) }
        if (bidi) runCatching { st.reset(Http3ErrorCode.WT_SESSION_GONE) }
    }

    private fun sessionClosed() = WebTransportException.SessionClosed("WebTransport session $sessionId is closed")

    /** Wraps [st] and tracks it until both its directions ended; a session that closed meanwhile ends it at once. */
    private suspend fun track(
        st: QuicStream,
        readable: Boolean,
        writable: Boolean,
        headerLength: Int = 0,
    ): WtStreamImpl =
        withContext(NonCancellable + h3.dispatcher) {
            val s = WtStreamImpl(h3.scope, st, readable, writable, headerLength) { done -> h3.scope.launch { streams.remove(done) } }
            if (closedInfo.isCompleted) {
                s.gone()
                throw sessionClosed()
            }
            streams += s
            s
        }

    private suspend fun open(bidi: Boolean): WtStreamImpl {
        if (closedInfo.isCompleted) throw sessionClosed()
        // the wait for stream credit ends when the session does
        val st =
            coroutineScope {
                val opening =
                    async {
                        try {
                            if (bidi) h3.quic.openBidi() else h3.quic.openUni()
                        } catch (e: QuicException) {
                            throw h3.map(e)
                        }
                    }
                select {
                    opening.onAwait { it }
                    closedInfo.onAwait {
                        opening.cancel()
                        // opened just as the session closed: the stream is not handed out, so it is ended here
                        opening.invokeOnCompletion { e ->
                            if (e == null) {
                                @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
                                opening.getCompleted().let { st ->
                                    runCatching { st.reset(Http3ErrorCode.WT_SESSION_GONE) }
                                    if (bidi) runCatching { st.stopSending(Http3ErrorCode.WT_SESSION_GONE) }
                                }
                            }
                        }
                        throw sessionClosed()
                    }
                }
            }
        val header = VarInt.encode(if (bidi) FrameType.WT_STREAM else StreamType.WT_UNI) + VarInt.encode(sessionId)
        try {
            st.output.writeFully(header)
            st.output.flush()
        } catch (e: Throwable) {
            runCatching { st.reset(Http3ErrorCode.WT_SESSION_GONE) }
            throw if (e is CancellationException) e else h3.map(e)
        }
        return track(st, readable = bidi, writable = true, headerLength = header.size)
    }

    override suspend fun openBidi(): WebTransportBidiStream = open(bidi = true)

    override suspend fun openUni(): WebTransportSendStream = open(bidi = false)

    override suspend fun acceptBidi(): WebTransportBidiStream =
        track(bidiIn.receiveCatching().getOrNull() ?: throw sessionClosed(), readable = true, writable = true)

    override suspend fun acceptUni(): WebTransportReceiveStream =
        track(uniIn.receiveCatching().getOrNull() ?: throw sessionClosed(), readable = true, writable = false)

    override fun trySendDatagram(payload: ByteArray): DatagramSendResult =
        if (closedInfo.isCompleted) DatagramSendResult.Closed else capsules.trySendDatagram(payload)

    override suspend fun sendDatagram(payload: ByteArray) {
        if (closedInfo.isCompleted) throw sessionClosed()
        capsules.sendDatagram(payload)
    }

    override suspend fun receiveDatagram(): ByteArray = datagramsIn.receiveCatching().getOrNull() ?: throw sessionClosed()

    override suspend fun drain() {
        if (closedInfo.isCompleted) throw sessionClosed()
        val sent = withTimeoutOrNull(CLOSE_TIMEOUT) { capsules.send(Capsule(WT_DRAIN_SESSION, ByteArray(0))) }
        if (sent == null) {
            val e = WebTransportException.Timeout("WT_DRAIN_SESSION not written within $CLOSE_TIMEOUT: the session was reset")
            terminate(WebTransportCloseInfo(0, "", e), End.Failed)
            throw e
        }
    }

    override suspend fun close(
        code: Long,
        reason: String,
    ) {
        require(code in 0..WtErrorCodes.MAX_APPLICATION_CODE) { "WebTransport error code $code is not in 0..2^32-1" }
        val (c, r) = WtCloseCapsule.decode(WtCloseCapsule.encode(code, reason))!!
        terminate(WebTransportCloseInfo(c, r, null), End.Locally)
    }

    override fun toString(): String = "WebTransportSession($sessionId, protocol=$protocol)"

    companion object {
        /** WebTransport's capsules on the CONNECT stream; HTTP datagrams always go as QUIC datagrams (section 4.5). */
        val CAPSULES: CapsuleConfig =
            CapsuleConfig(
                knownTypes = setOf(WtCloseCapsule.TYPE, WT_DRAIN_SESSION),
                terminalTypes = setOf(WtCloseCapsule.TYPE),
                maxCapsuleLength = 4 + WtCloseCapsule.MAX_REASON,
                datagramFallback = false,
            )

        /** How long ending the CONNECT stream may wait for the peer: its flow-control credit, then its FIN. */
        val CLOSE_TIMEOUT: Duration = 5.seconds
    }
}

/** The client side of `Http3Connection.webTransport` (draft-ietf-webtrans-http3-16 sections 3.2, 3.3, 5.1). */
internal suspend fun H3Session.webTransport(
    r: Http3Request,
    protocols: List<String>,
): WebTransportSession {
    check(settings.webTransport) {
        "Http3Settings.webTransport is off on this connection: the session's streams could not be received"
    }
    for (p in protocols) require(WtProtocols.isValid(p)) { "WebTransport protocol '$p' is not a non-empty printable ASCII string" }
    val ps =
        withinWtDeadline { awaitPeerSettings() }
            ?: throw Http3Exception.Settings("no SETTINGS from the server within $wtDeadline")
    val version =
        peerWtVersion() ?: throw Http3Exception.Settings("the server does not offer WebTransport in its SETTINGS")
    if (!ps.h3Datagram) throw Http3Exception.Settings("the server did not send SETTINGS_H3_DATAGRAM=1, which WebTransport needs")
    withContext(dispatcher) {
        check(!wtClientBusy) {
            "this connection already has a WebTransport session: without WebTransport flow control a client keeps to one"
        }
        wtClientBusy = true
    }
    var made: Http3Stream? = null
    try {
        val fields =
            buildList {
                addAll(r.headers.fields)
                if (version != WtVersion.Draft16) add(WtTokens.DRAFT02_REQUEST_FIELD to "1")
                if (protocols.isNotEmpty()) add(WtProtocols.AVAILABLE_FIELD to WtProtocols.formatList(protocols))
            }
        val ended = CompletableDeferred<Unit>()
        val req = r.toBuilder().apply { headers = Http3Headers(fields) }.build()
        // the answer has a deadline too; a CONNECT still unanswered then is reset by the cancellation (REQUEST_CANCELLED)
        val stream =
            withinWtDeadline { connect(req, version.protocolToken, ended) }
                ?: throw WebTransportException.Timeout("no answer to the WebTransport CONNECT within $wtDeadline")
        made = stream
        // a WT-Protocol that is no valid Structured Field String is ignored, as if absent (section 3.3)
        val selected =
            stream.headers[WtProtocols.SELECTED_FIELD]?.let { WtProtocols.parseItem(it) }?.also { p ->
                if (p !in protocols) {
                    stream.reset(Http3ErrorCode.WT_ALPN_ERROR)
                    stream.stopSending(Http3ErrorCode.WT_ALPN_ERROR)
                    throw WebTransportException.Alpn(protocols, p)
                }
            }
        val s = WtSessionImpl(this, stream, stream.headers, selected)
        withContext(dispatcher) {
            wt.register(stream.streamId, s)
            s.start()
            scope.launch {
                ended.await()
                s.ended()
                wtClientBusy = false
            }
        }
        made = null
        return s
    } catch (e: Throwable) {
        withContext(NonCancellable + dispatcher) {
            wtClientBusy = false
            made?.let {
                if (e is CancellationException) {
                    it.reset(Http3ErrorCode.REQUEST_CANCELLED)
                    it.stopSending(Http3ErrorCode.REQUEST_CANCELLED)
                }
                wt.unregister(it.streamId)
            }
        }
        throw e
    }
}
