// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.cancel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.WebTransportBidiStream
import io.kuicksilver.http3.WebTransportException
import io.kuicksilver.http3.runtime.H3Session
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.io.IOException
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.decrementAndFetch

/**
 * A WebTransport stream past its header (signal or type, then Session ID). The application's [input] and [output] are
 * channels of their own, pumped to and from the QUIC stream, so its errors reach the application in WebTransport terms:
 * the peer's RESET_STREAM as [WebTransportException.StreamReset], its STOP_SENDING as
 * [WebTransportException.StreamStopped], with the application code mapped back from the HTTP/3 space (section 4.4).
 * The input holds at most one 16 KiB chunk besides what the application has not read ([WtInput]): the transport's stream
 * window holds the peer back beyond that, and with flow control the credit follows what the application read. The output
 * buffers what ktor-io's `ByteChannel` holds before a writer suspends (1 MiB) plus one chunk. The application cancelling
 * [input] sends STOP_SENDING, and cancelling [output] RESET_STREAM_AT keeping our header (section 4.4), with application
 * code 0.
 */
internal class WtStreamImpl(
    scope: CoroutineScope,
    internal val st: QuicStream,
    private val readable: Boolean,
    internal val writable: Boolean,
    /** Bytes of the stream header we wrote (signal or type, Session ID); 0 for a stream the peer opened. */
    private val headerLength: Int,
    private val onDone: (WtStreamImpl) -> Unit,
    /** The session's flow control (draft-ietf-webtrans-http3-16 section 5) for our bytes, or null when it is not enabled. */
    private val flow: WtSessionFlow? = null,
    /** The count of the peer's bytes on [input] against the session's limit, or null without flow control. */
    private val inCount: WtInCount? = null,
    /** The session's turns at, and its share of, the connection's send buffer (draft-16 section 8), with flow control. */
    private val turns: WtSendTurns? = null,
) : WebTransportBidiStream {
    override val streamId: Long get() = st.id
    private val outCh = ByteChannel()

    /**
     * The application cancelling its input stops the peer at once (code 0), not only when the peer sends more; what it read
     * goes to the session's flow control as consumed, from the session's dispatcher.
     */
    private val inCh: WtInput =
        WtInput(
            onRead = { n -> if (inCount != null) scope.launch { inCount.read(n) } },
            onCancel = {
                if (readable && inPump?.isCompleted == false) {
                    runCatching { st.stopSending(WtErrorCodes.toHttp3(0)) }
                    inPump.cancel()
                }
            },
        )
    override val input: ByteReadChannel get() = inCh
    override val output: ByteWriteChannel get() = outCh
    private val inPump: Job?
    private val outPump: Job?

    /** Body bytes taken from the session's credit (flow control; session dispatcher only). */
    private var outCounted = 0L

    /**
     * This stream's place in the session's data credit, made now, when the session hands the stream to the application:
     * the session serves its streams' credit in that order ([WtSessionFlow.Sender]).
     */
    private val credit = if (writable) flow?.sender() else null

    /** This stream's bytes in the session's share of the send buffer. */
    private val account = if (writable) turns?.follow(scope, st, headerLength) else null

    init {
        inPump = if (readable) scope.launch { pumpIn() } else null.also { inCh.finish() }
        outPump = if (writable) scope.launch { pumpOut() } else null.also { outCh.close() }
        // a pump cancelled before it ran (the connection ended first, or the application stopped the stream as it accepted it)
        // still ends its channel, so the application never hangs on it, and abandons the rest: its bytes count as consumed
        // (section 5.6), as when the running pump is cancelled. Counted on the session's dispatcher; a second call changes nothing
        inPump?.invokeOnCompletion { e ->
            if (e != null) {
                inCh.fail(IOException("the WebTransport stream $streamId stopped reading", e))
                if (inCount != null) scope.launch { inCount.abandon() }
            }
        }
        outPump?.invokeOnCompletion { e ->
            if (e !=
                null
            ) {
                outCh.cancel(IOException("the WebTransport stream $streamId stopped writing", e))
            }
            // the stream's place in the session's credit goes when the writer ends, ran or not (one cancelled before it
            // first ran never reaches its own finally); on the session's dispatcher, and a second close changes nothing
            if (credit != null) scope.launch { credit.close() }
        }
        if (flow != null && writable) {
            // section 5.4: a reset stream counts its final size, so both sides agree on the credit it used. Once the size
            // is fixed (our reset, the one answering the peer's STOP_SENDING, or the FIN) the pump takes no more credit (a
            // wait for it ends at once), so what it took and never sent is given back once and for all
            scope.launch {
                val f = runCatching { st.sentFinalSize?.await() }.getOrNull() ?: return@launch
                credit?.close()
                flow.sentFinal(outCounted, maxOf(0L, f - headerLength))
            }
        }
        val pumps = listOfNotNull(inPump, outPump)
        val left = AtomicInt(pumps.size)
        for (p in pumps) {
            p.invokeOnCompletion {
                if (left.decrementAndFetch() == 0) onDone(this)
            }
        }
    }

    private suspend fun pumpIn() {
        val buf = ByteArray(CHUNK)
        try {
            while (true) {
                val n = st.input.readAvailable(buf, 0, buf.size)
                if (n < 0) break
                inCount?.taken(n)
                inCh.deliver(buf.copyOf(n))
            }
            st.input.closedCause?.let { throw it }
            inCh.finish()
            inCount?.delivered()
        } catch (e: CancellationException) {
            inCount?.abandon() // we stopped reading: the rest counts as consumed once its final size is known
            inCh.fail(IOException("the WebTransport stream $streamId stopped reading", e))
            throw e
        } catch (e: Throwable) {
            inCount?.abandon() // reset by the peer, or stopped: nobody reads the rest
            if (H3Session.transportCause(e) == null) {
                // the application cancelled its input while the pump wrote into it: stop the peer (code 0)
                runCatching { st.stopSending(WtErrorCodes.toHttp3(0)) }
            }
            inCh.fail(map(e))
        }
    }

    private suspend fun pumpOut() {
        val buf = ByteArray(CHUNK)
        try {
            while (true) {
                // everything given was written: the place in the session's credit stays only if more bytes are here at once
                credit?.idle()
                val n = outCh.readAvailable(buf, 0, buf.size)
                if (n < 0) break
                if (credit == null) {
                    st.output.writeFully(buf, 0, n)
                } else {
                    var off = 0
                    while (off < n) {
                        // counted before the write: a reset that cuts the write short is settled by the final size
                        val k = credit.take(n - off)
                        // the sending half is over (reset, or stopped by the peer): its own failure tells why
                        if (k == 0) throw st.output.closedCause ?: IOException("WebTransport stream $streamId: sending ended")
                        outCounted += k
                        val from = off
                        // a chunk at a time, in turn with the connection's other sessions (section 8); flushed before the
                        // next wait for credit, as the peer's WT_MAX_DATA follows what it received
                        val write: suspend () -> Unit = {
                            st.output.writeFully(buf, from, from + k) // start and end index
                            st.output.flush()
                        }
                        if (turns != null && account != null) turns.run(account, k.toLong(), write) else write()
                        off += k
                    }
                }
                st.output.flush()
            }
            if (outCh.closedCause != null) {
                // the application cancelled its output: the stream is abandoned, not ended
                abandon(WtErrorCodes.toHttp3(0))
            } else {
                st.output.flushAndClose()
            }
        } catch (e: CancellationException) {
            outCh.cancel(IOException("the WebTransport stream $streamId stopped writing", e))
            throw e
        } catch (e: Throwable) {
            if (H3Session.transportCause(e) == null) {
                // the application cancelled its output while the pump waited on it: the stream is abandoned (code 0)
                abandon(WtErrorCodes.toHttp3(0))
            }
            outCh.cancel(map(e))
        } finally {
            // nothing more is taken for this stream: its place and what was kept for it go to the streams after it
            credit?.close()
        }
    }

    private fun map(e: Throwable): Throwable =
        when (val q = H3Session.transportCause(e)) {
            is QuicException.StreamError.Reset -> {
                WebTransportException.StreamReset(WtErrorCodes.fromHttp3(q.code))
            }

            is QuicException.StreamError.Stopped -> {
                if (q.initiator == Initiator.Peer) {
                    WebTransportException.StreamStopped(WtErrorCodes.fromHttp3(q.code))
                } else {
                    IOException("WebTransport stream $streamId: we stopped reading it", e)
                }
            }

            else -> {
                e
            }
        }

    override fun reset(code: Long) {
        val h = WtErrorCodes.toHttp3(code)
        check(writable) { "stream $streamId is receive-only" }
        abandon(h)
        outPump?.cancel()
        outCh.cancel(IOException("WebTransport stream $streamId reset locally with $code"))
    }

    override fun stopSending(code: Long) {
        val h = WtErrorCodes.toHttp3(code)
        check(readable) { "stream $streamId is send-only" }
        runCatching { st.stopSending(h) }
        inPump?.cancel()
        inCh.fail(IOException("WebTransport stream $streamId stopped locally with $code"))
    }

    /** The session is over: both directions end with WT_SESSION_GONE (section 6). */
    fun gone() {
        if (writable) abandon(Http3ErrorCode.WT_SESSION_GONE)
        if (readable) runCatching { st.stopSending(Http3ErrorCode.WT_SESSION_GONE) }
        inPump?.cancel()
        outPump?.cancel()
        val e = WebTransportException.SessionClosed("the WebTransport session of stream $streamId is closed")
        inCh.fail(e)
        outCh.cancel(e)
        inCount?.stop()
    }

    /**
     * Resets our sending side with [code] by RESET_STREAM_AT keeping the header we wrote as the reliable size (draft-16
     * section 4.4: "WebTransport implementations MUST use the RESET_STREAM_AT frame [RESET-STREAM-AT] with a Reliable Size
     * set to at least the size of the WebTransport header when resetting a WebTransport data stream"), so the peer can
     * still tell which session the reset belongs to; on a stream the peer opened our side carries no header (size 0). A
     * session of draft-14 or later exists only with `reset_stream_at` on both sides (section 3.1, [wtTransportGap]), so
     * the frame always goes; only a draft-02 session (browsers), whose draft predates the frame, may lack it, and the
     * transport then sends the RESET_STREAM that draft-02 uses.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private fun abandon(code: Long) {
        runCatching { st.resetAt(code, headerLength.toLong()) }
    }

    private companion object {
        const val CHUNK = 16_384
    }
}
