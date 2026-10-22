// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3Request
import io.kuicksilver.http3.Http3Stream
import io.kuicksilver.http3.WebTransportException
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.http3.runtime.H3Session
import io.kuicksilver.http3.runtime.connect
import io.kuicksilver.quic.QuicStream
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * One WebTransport session: the Extended CONNECT [stream] and the WebTransport streams routed to it. The peer's streams
 * wait in [incoming] until the application takes them; how many can be open at once is bounded by the QUIC stream limits
 * we grant (`maxBidiStreams`, `maxUniStreams`), since a stream counts against them until it is finished.
 */
internal class WtSessionImpl(
    private val h3: H3Session,
    internal val stream: Http3Stream,
    override val headers: Http3Headers,
    override val protocol: String?,
) : WebTransportSession,
    WtSessionSink {
    override val sessionId: Long get() = stream.streamId

    /** The peer's streams routed here, with whether each is bidirectional. */
    internal val incoming = Channel<Pair<QuicStream, Boolean>>(Channel.UNLIMITED)

    override fun onStream(
        stream: QuicStream,
        bidi: Boolean,
    ) {
        if (incoming.trySend(stream to bidi).isFailure) gone(stream, bidi)
    }

    /**
     * The CONNECT stream ended both ways: the session is over (section 6). Streams nobody took are stopped (and reset)
     * with WT_SESSION_GONE; later ones are rejected by the router. Session dispatcher only.
     */
    fun ended() {
        incoming.close()
        while (true) {
            val (st, bidi) = incoming.tryReceive().getOrNull() ?: break
            gone(st, bidi)
        }
        h3.wt.unregister(sessionId)
    }

    private fun gone(
        st: QuicStream,
        bidi: Boolean,
    ) {
        runCatching { st.stopSending(WtCodes.SESSION_GONE) }
        if (bidi) runCatching { st.reset(WtCodes.SESSION_GONE) }
    }

    override fun toString(): String = "WebTransportSession($sessionId, protocol=$protocol)"
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
                    stream.reset(WtCodes.ALPN_ERROR)
                    stream.stopSending(WtCodes.ALPN_ERROR)
                    throw WebTransportException.Alpn(protocols, p)
                }
            }
        val s = WtSessionImpl(this, stream, stream.headers, selected)
        withContext(dispatcher) {
            wt.register(stream.streamId, s)
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
