// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)

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
import io.kuicksilver.http3.runtime.close
import io.kuicksilver.http3.runtime.connect
import io.kuicksilver.http3.runtime.drains
import io.kuicksilver.quic.DatagramSendResult
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.DisposableHandle
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.Volatile
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * One WebTransport session (draft-ietf-webtrans-http3-16): the Extended CONNECT [stream], spoken as the Capsule Protocol,
 * and the WebTransport streams routed to it.
 *
 * Capsules: WT_CLOSE_SESSION (terminal, at most 4 + 1024 bytes) and WT_DRAIN_SESSION (empty) are read; with flow control
 * ([flow], section 5) its capsules too, and from draft-14 on the WT_MAX_STREAM_DATA and WT_STREAM_DATA_BLOCKED capsules
 * that section 5.4 prohibits; every other type (the flow-control capsules without flow control: "if flow control is not
 * enabled, an endpoint MUST ignore receipt of any flow control capsules", section 5.1) is skipped unbuffered by the
 * capsule stream. The peer's streams wait in [bidiIn] and [uniIn] until the application accepts them; how many can be
 * open at once is bounded by the QUIC stream limits we grant (`maxBidiStreams`, `maxUniStreams`), since a stream counts
 * against them until it is finished, and with flow control by the session's own stream limits.
 *
 * State that the router and the stream pumps share ([streams], the channels' contents at close) is touched on the
 * session's dispatcher only.
 */
internal class WtSessionImpl(
    private val h3: H3Session,
    internal val stream: Http3Stream,
    override val headers: Http3Headers,
    override val protocol: String?,
    /** The draft this session runs ([wtClientVersion], [wtServerVersion]). */
    internal val version: WtVersion,
) : WebTransportSession,
    WtSessionSink {
    override val sessionId: Long get() = stream.streamId

    /** The connection's dispatcher, where [flow] lives (a test hook). */
    internal val dispatcherForTest get() = h3.dispatcher

    /** Flow control is on for this session (section 5.1): both sides declared it, and the draft has it. */
    private val flowEnabled = WtFlow.enabled(h3, version)

    /** The CONNECT stream as capsules; built first, so a peer message that cannot carry capsules fails the accept. */
    internal val capsules: CapsuleStream = stream.useCapsuleProtocol(capsuleConfig(flowEnabled, version))

    /** Capsules flow control sends, written in order by one writer ([start]): a later limit never overtakes an earlier one. */
    private val capsulesOut = Channel<Capsule>(Channel.UNLIMITED)

    /** The session's flow control (section 5), or null when it is not enabled. Session dispatcher only. */
    internal val flow: WtSessionFlow? = if (flowEnabled) WtSessionFlow.of(h3, version) { capsulesOut.trySend(it) } else null

    /** A peer's stream, with the count of its bytes against the session's limit when flow control is on. */
    private class Incoming(
        val stream: QuicStream,
        val count: WtInCount?,
    )

    private val bidiIn = Channel<Incoming>(Channel.UNLIMITED)
    private val uniIn = Channel<Incoming>(Channel.UNLIMITED)
    private val streams = HashSet<WtStreamImpl>()
    private val datagramsIn = Channel<ByteArray>(DatagramDemux.QUEUE, BufferOverflow.DROP_OLDEST)
    private val drainFlow = MutableStateFlow(false)
    private val closedInfo = CompletableDeferred<WebTransportCloseInfo>()
    private val watchers = ArrayList<Job>()

    /**
     * The handler on the connection's end ([start]), disposed when the session ends first: kept, it would hold every session
     * the connection ever carried (with its CONNECT stream and request) until the connection closes.
     */
    @Volatile private var connectionEnd: DisposableHandle? = null

    /** The peer's FIN was read (session dispatcher only). */
    private var peerFinished = false
    override val drainRequested: StateFlow<Boolean> get() = drainFlow
    override val closed: Deferred<WebTransportCloseInfo> get() = closedInfo

    /** Starts reading capsules and datagrams; session dispatcher only, right after the router registration. */
    fun start() {
        // the capsule reader finishes what the peer sent when the connection is lost: a WT_CLOSE_SESSION right before the peer's
        // CONNECTION_CLOSE (Firefox) still ends the session with its code
        watchers += h3.drains(h3.scope.launch { readCapsules() })
        if (flow != null) {
            watchers +=
                h3.scope.launch {
                    for (c in capsulesOut) {
                        try {
                            capsules.send(c)
                        } catch (e: CancellationException) {
                            throw e
                        } catch (_: Throwable) {
                            return@launch // the CONNECT stream is gone: the session ends through its reader
                        }
                    }
                }
        }
        watchers +=
            h3.scope.launch {
                try {
                    capsules.datagrams.collect { datagramsIn.trySend(it) }
                } finally {
                    datagramsIn.close()
                }
            }
        // the connection's end: the session is over with the connection's reason, unless the capsule reader, which reads on to
        // what the peer sent before (H3Session.drains), ends it with a WT_CLOSE_SESSION first
        val reader = watchers.first()
        connectionEnd =
            h3.closed.invokeOnCompletion {
                val cause = if (h3.closed.isCompleted && !h3.closed.isCancelled) h3.closed.getCompleted() else it
                reader.invokeOnCompletion {
                    if (closedInfo.complete(WebTransportCloseInfo(0, "", cause ?: sessionClosed()))) {
                        bidiIn.close()
                        uniIn.close()
                        datagramsIn.close()
                    }
                }
            }
        // an HTTP/3 GOAWAY asks every session to wind down (section 4.7)
        watchers += h3.scope.launch { h3.goAwayReceived.first { it != null }.let { drainFlow.value = true } }
    }

    override fun onStream(
        stream: QuicStream,
        bidi: Boolean,
        headerLength: Int,
    ) {
        val count = flow?.let { WtInCount.start(h3, stream, it, headerLength) { reason -> flowControlError(reason) } }
        if ((if (bidi) bidiIn else uniIn).trySend(Incoming(stream, count)).isFailure) {
            goneRaw(stream, bidi)
            return
        }
        flow?.onPeerStream(bidi)?.let { flowControlError(it) }
    }

    override fun onRejected(
        bidi: Int,
        uni: Int,
        bytes: Long,
    ) {
        flow?.onRejected(bidi, uni, bytes)?.let { flowControlError(it) }
    }

    /**
     * The peer broke flow control: section 5 says it "MUST close the WebTransport session with a WT_FLOW_CONTROL_ERROR
     * error code", which, as an HTTP/3 code and no application code, ends the CONNECT stream with RESET_STREAM and
     * STOP_SENDING. Session dispatcher only.
     */
    internal fun flowControlError(reason: String) {
        if (closedInfo.isCompleted) return
        h3.scope.launch { terminate(WebTransportCloseInfo(0, "", WtSessionFlow.error(reason)), End.FlowControl) }
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

                    in WtFlow.PROHIBITED -> {
                        // section 5.4: "Endpoints MUST treat receipt of a WT_MAX_STREAM_DATA or a WT_STREAM_DATA_BLOCKED capsule as
                        // a session error"
                        flowControlError(
                            "capsule 0x${c.type.toString(16)} (WT_MAX_STREAM_DATA or WT_STREAM_DATA_BLOCKED) is not used over HTTP/3",
                        )
                    }

                    else -> {
                        // a flow-control capsule: known only when flow control is on
                        val v =
                            WtFlow.valueOf(c)
                                ?: malformed("capsule 0x${c.type.toString(16)} whose value is not one variable-length integer")
                        flow?.onCapsule(c.type, v)?.let { flowControlError(it) }
                    }
                }
            }
            peerFinished = true // the peer's FIN on a capsule boundary: its side of the CONNECT stream is over
            terminate(WebTransportCloseInfo(0, "", null), End.ByPeer) // without a capsule before it: code 0 (section 6)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            // the input ended with the lost connection (after the capsules it held): the session ends with the connection's reason
            val cause = if (e !is Http3Exception.MessageError && h3.closed.isCompleted) h3.closed.getCompleted() else e
            terminate(WebTransportCloseInfo(0, "", cause), End.Failed)
        }
    }

    /** A malformed message on the CONNECT stream (section 6): reset and stopped with H3_MESSAGE_ERROR. */
    private fun malformed(reason: String): Nothing {
        stream.reset(Http3ErrorCode.MESSAGE_ERROR)
        stream.stopSending(Http3ErrorCode.MESSAGE_ERROR)
        throw Http3Exception.MessageError(sessionId, reason)
    }

    /**
     * [Over]: the CONNECT stream already ended both ways, so nothing is sent on it. [FlowControl]: ended like [Failed], with
     * WT_FLOW_CONTROL_ERROR.
     */
    private enum class End { Locally, ByPeer, Failed, FlowControl, Over }

    /**
     * The session is over: [closed] completes with [info], the session's streams end with WT_SESSION_GONE, and the CONNECT
     * stream is ended in both directions so the connection's session slot frees. The first call wins.
     */
    private suspend fun terminate(
        info: WebTransportCloseInfo,
        end: End,
    ): Boolean {
        if (!closedInfo.complete(info)) return false
        connectionEnd?.dispose()
        val caller = currentCoroutineContext()[Job] // the capsule reader when the peer ended the session: it reads on to the FIN
        // not cancellable: [closed] is already complete, so a caller cancelled from here on must not leave the rest
        // undone (withContext also throws a caller's cancellation when it returns, so everything is started inside)
        val connectEnd =
            withContext(NonCancellable + h3.dispatcher) {
                bidiIn.close()
                uniIn.close()
                for (ch in listOf(bidiIn to true, uniIn to false)) {
                    while (true) {
                        val q = ch.first.tryReceive().getOrNull() ?: break
                        q.count?.stop()
                        goneRaw(q.stream, ch.second)
                    }
                }
                flow?.end(sessionClosed())
                capsulesOut.close()
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

                    End.FlowControl -> {
                        runCatching { stream.reset(Http3ErrorCode.WT_FLOW_CONTROL_ERROR) }
                        runCatching { stream.stopSending(Http3ErrorCode.WT_FLOW_CONTROL_ERROR) }
                        // the capsule reader ends with the stop: nothing more of the peer is read
                        watchers.firstOrNull()?.let { if (it !== caller) it.cancel() }
                        null
                    }

                    // a RESET_STREAM after our FIN could overtake it and discard what the peer has not read yet (RFC 9000
                    // section 3.1)
                    End.Over -> {
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
     * id is forgotten by the router, which rejects late streams. The exchange's end can come before the capsule reader
     * read to the peer's FIN; the reader's verdict (a FIN without WT_CLOSE_SESSION is code 0, section 6) goes first, and
     * the stream is left alone. Session dispatcher only.
     */
    fun ended() {
        h3.wt.unregister(sessionId)
        if (!closedInfo.isCompleted) {
            val reader = watchers.firstOrNull()
            h3.scope.launch {
                withTimeoutOrNull(CLOSE_TIMEOUT) { reader?.join() }
                terminate(WebTransportCloseInfo(0, "", WebTransportException.SessionClosed("the CONNECT stream ended")), End.Over)
            }
        }
    }

    /**
     * The CONNECT stream's priority changed (the client's PRIORITY_UPDATE): the session's streams follow it. Section 3.4: "it
     * is RECOMMENDED that clients and servers apply the scheduling guidance in both Section 9 of \[RFC9218\] and Section 10 of
     * \[RFC9218\] for all data that they send in the enclosing WebTransport session, including Capsules, WebTransport streams
     * and datagrams". Session dispatcher only.
     */
    fun priorityChanged() {
        val p = stream.priority
        for (s in streams) if (s.writable) s.st.priority = p
    }

    private fun goneRaw(
        st: QuicStream,
        bidi: Boolean,
    ) {
        runCatching { st.stopSending(Http3ErrorCode.WT_SESSION_GONE) }
        // section 4.4: RESET_STREAM_AT; our side of the peer's stream carries no header, so the reliable size is 0, which "is
        // logically equivalent to a RESET_STREAM frame" (draft-ietf-quic-reliable-stream-reset-11 section 4)
        if (bidi) runCatching { st.resetAt(Http3ErrorCode.WT_SESSION_GONE, 0) }
    }

    private fun sessionClosed() = WebTransportException.SessionClosed("WebTransport session $sessionId is closed")

    /**
     * Wraps [st] and tracks it until both its directions ended; a session that closed meanwhile ends it at once. [peer]: a
     * stream the peer opened, whose bytes [peerCount] counts; its end gives its slot back (flow control).
     */
    private suspend fun track(
        st: QuicStream,
        readable: Boolean,
        writable: Boolean,
        headerLength: Int = 0,
        peer: Boolean = false,
        peerCount: WtInCount? = null,
    ): WtStreamImpl =
        withContext(NonCancellable + h3.dispatcher) {
            // section 3.4: sent at the CONNECT stream's priority, set here on the dispatcher so no update is missed
            if (writable) st.priority = stream.priority
            val bidi = readable && writable
            // the peer's half of a bidirectional stream we opened carries no header
            val inCount =
                peerCount ?: flow?.takeIf { readable && !peer }?.let { WtInCount.start(h3, st, it, 0) { r -> flowControlError(r) } }
            val s =
                WtStreamImpl(
                    h3.scope,
                    st,
                    readable,
                    writable,
                    headerLength,
                    { done ->
                        h3.scope.launch {
                            streams.remove(done)
                            if (peer && !closedInfo.isCompleted) flow?.onPeerStreamClosed(bidi)
                        }
                    },
                    flow,
                    inCount,
                )
            if (closedInfo.isCompleted) {
                s.gone()
                throw sessionClosed()
            }
            streams += s
            s
        }

    /**
     * Opens a stream: its stream credit (section 5.6.2: "An endpoint MUST NOT open more streams than permitted by the
     * current stream limit set by its peer"), the QUIC stream, then its whole header, as one unit on the connection's
     * scope that the caller only waits for. Section 5.3 counts the streams both sides agree on, so the unit keeps the
     * count exact: a slot taken for a stream that never existed goes back, and a stream that exists gets its whole header
     * out, then is reset keeping it when nobody wants it any more (the caller gave up, or the session ended).
     */
    private suspend fun open(bidi: Boolean): WtStreamImpl {
        if (closedInfo.isCompleted) throw sessionClosed()
        val header = VarInt.encode(if (bidi) FrameType.WT_STREAM else StreamType.WT_UNI) + VarInt.encode(sessionId)

        fun unwanted(st: QuicStream) {
            // section 4.4: RESET_STREAM_AT keeping the header, so the peer counts the stream as we do
            runCatching { st.resetAt(Http3ErrorCode.WT_SESSION_GONE, header.size.toLong()) }
            if (bidi) runCatching { st.stopSending(Http3ErrorCode.WT_SESSION_GONE) }
        }
        val unit =
            h3.scope.async {
                val f = flow
                f?.takeStream(bidi) // the wait ends with the session (flow.end); nothing is taken before it returns
                val st =
                    try {
                        val quicOpen = suspend { if (bidi) h3.quic.openBidi(stream.priority) else h3.quic.openUni(stream.priority) }
                        quicOpen()
                    } catch (e: Throwable) {
                        // no stream the peer will see: the slot goes back
                        f?.returnStream(bidi)
                        throw if (e is QuicException) h3.map(e) else e
                    }
                withContext(NonCancellable) {
                    try {
                        st.output.writeFully(header)
                        st.output.flush()
                    } catch (e: Throwable) {
                        // only the connection's end gets here (nobody stops a stream it has not seen): the header goes reliably
                        // as far as it was written
                        runCatching { st.resetAt(Http3ErrorCode.WT_SESSION_GONE, header.size.toLong()) }
                        throw h3.map(e)
                    }
                }
                // given up while the header went out: the result would be dropped, so the stream is ended here
                if (!isActive) {
                    unwanted(st)
                    throw CancellationException("the opening of a WebTransport stream was given up")
                }
                // tracked inside the unit too: a caller cancelled now finds the stream handed over below, never lost
                track(st, readable = bidi, writable = true, headerLength = header.size)
            }
        try {
            return select {
                unit.onAwait { it }
                closedInfo.onAwait { throw sessionClosed() }
            }
        } catch (e: Throwable) {
            // the caller gave up, or the session closed: an opening still waiting stops; a stream it opened is ended, keeping
            // its header (section 4.4), with application code 0
            unit.cancel()
            unit.invokeOnCompletion { ex ->
                @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
                if (ex == null) {
                    val s = unit.getCompleted()
                    runCatching { s.reset(0) }
                    if (bidi) runCatching { s.stopSending(0) }
                }
            }
            throw e
        }
    }

    override suspend fun openBidi(): WebTransportBidiStream = open(bidi = true)

    override suspend fun openUni(): WebTransportSendStream = open(bidi = false)

    override suspend fun acceptBidi(): WebTransportBidiStream =
        (bidiIn.receiveCatching().getOrNull() ?: throw sessionClosed()).let {
            track(it.stream, readable = true, writable = true, peer = true, peerCount = it.count)
        }

    override suspend fun acceptUni(): WebTransportReceiveStream =
        (uniIn.receiveCatching().getOrNull() ?: throw sessionClosed()).let {
            track(it.stream, readable = true, writable = false, peer = true, peerCount = it.count)
        }

    override fun trySendDatagram(payload: ByteArray): DatagramSendResult =
        if (closedInfo.isCompleted) DatagramSendResult.Closed else capsules.trySendDatagram(payload)

    override suspend fun sendDatagram(payload: ByteArray) {
        if (closedInfo.isCompleted) throw sessionClosed()
        capsules.sendDatagram(payload)
    }

    override suspend fun receiveDatagram(): ByteArray = datagramsIn.receiveCatching().getOrNull() ?: throw sessionClosed()

    override suspend fun drain() {
        if (closedInfo.isCompleted) throw sessionClosed()
        drainFlow.value = true // this side winds down too
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
        /**
         * WebTransport's capsules on the CONNECT stream; HTTP datagrams always go as QUIC datagrams (section 4.5). The
         * flow-control capsules are read only when flow control is on ([flowEnabled]), the two HTTP/2 ones section 5.4
         * prohibits from draft-14 on (draft-02 predates them).
         */
        fun capsuleConfig(
            flowEnabled: Boolean,
            version: WtVersion,
        ): CapsuleConfig =
            CapsuleConfig(
                knownTypes =
                    buildSet {
                        add(WtCloseCapsule.TYPE)
                        add(WT_DRAIN_SESSION)
                        if (flowEnabled) addAll(WtFlow.CAPSULES)
                        if (version != WtVersion.Draft02) addAll(WtFlow.PROHIBITED)
                    },
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
    ownsConnection: Boolean = false,
): WebTransportSession {
    check(settings.webTransport) {
        "Http3Settings.webTransport is off on this connection: the session's streams could not be received"
    }
    for (p in protocols) require(WtProtocols.isValid(p)) { "WebTransport protocol '$p' is not a non-empty printable ASCII string" }
    val ps =
        withinWtDeadline { awaitPeerSettings() }
            ?: throw Http3Exception.Settings("no SETTINGS from the server within $wtDeadline")
    if (highestCommonWtVersion() == null) {
        throw Http3Exception.Settings("the server does not offer WebTransport in a draft we speak (draft-16 or draft-02) in its SETTINGS")
    }
    if (!ps.h3Datagram) throw Http3Exception.Settings("the server did not send SETTINGS_H3_DATAGRAM=1, which WebTransport needs")
    // section 3.1: "A client MUST NOT establish WebTransport sessions if the server's SETTINGS do not have correct values for
    // every required setting or if the server's transport parameters do not have correct values for every required
    // transport parameter"; a server that also announces draft-02 gets a draft-02 CONNECT ([wtClientVersion])
    val (chosen, refusal) = wtClientVersion(this)
    val version = chosen ?: throw Http3Exception.Settings(refusal!!)
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
        val s = WtSessionImpl(this, stream, stream.headers, selected, version)
        withContext(dispatcher) {
            wt.register(stream.streamId, s)
            s.start()
            scope.launch {
                ended.await()
                s.ended()
                wtClientBusy = false
                // a connection opened for this session alone ends with it, once both directions of the CONNECT did
                if (ownsConnection) close(Http3ErrorCode.NO_ERROR, "")
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
