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
import io.kuicksilver.http3.runtime.BodyReadChannel
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
 * Each direction buffers what ktor-io's `ByteChannel` holds before a writer suspends (1 MiB) plus one 16 KiB chunk, on
 * top of the transport's stream window, which holds the peer back once that buffer is full. The application cancelling
 * [input] sends STOP_SENDING, and cancelling [output] RESET_STREAM, with application code 0.
 */
internal class WtStreamImpl(
    scope: CoroutineScope,
    internal val st: QuicStream,
    private val readable: Boolean,
    private val writable: Boolean,
    private val onDone: (WtStreamImpl) -> Unit,
) : WebTransportBidiStream {
    override val streamId: Long get() = st.id
    private val inCh = ByteChannel()
    private val outCh = ByteChannel()

    /** The application cancelling its input stops the peer at once (code 0), not only when the peer sends more. */
    override val input: ByteReadChannel =
        BodyReadChannel(inCh) {
            if (readable && inPump?.isCompleted == false) {
                runCatching { st.stopSending(WtErrorCodes.toHttp3(0)) }
                inPump?.cancel()
            }
        }
    override val output: ByteWriteChannel get() = outCh
    private val inPump: Job?
    private val outPump: Job?

    init {
        inPump = if (readable) scope.launch { pumpIn() } else null.also { inCh.close() }
        outPump = if (writable) scope.launch { pumpOut() } else null.also { outCh.close() }
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
                inCh.writeFully(buf, 0, n)
                inCh.flush()
            }
            st.input.closedCause?.let { throw it }
            inCh.flushAndClose()
        } catch (e: CancellationException) {
            inCh.cancel(IOException("the WebTransport stream $streamId stopped reading", e))
            throw e
        } catch (e: Throwable) {
            if (H3Session.transportCause(e) == null) {
                // the application cancelled its input while the pump wrote into it: stop the peer (code 0)
                runCatching { st.stopSending(WtErrorCodes.toHttp3(0)) }
            }
            inCh.cancel(map(e))
        }
    }

    private suspend fun pumpOut() {
        val buf = ByteArray(CHUNK)
        try {
            while (true) {
                val n = outCh.readAvailable(buf, 0, buf.size)
                if (n < 0) break
                st.output.writeFully(buf, 0, n)
                st.output.flush()
            }
            if (outCh.closedCause != null) {
                // the application cancelled its output: the stream is abandoned, not ended
                runCatching { st.reset(WtErrorCodes.toHttp3(0)) }
            } else {
                st.output.flushAndClose()
            }
        } catch (e: CancellationException) {
            outCh.cancel(IOException("the WebTransport stream $streamId stopped writing", e))
            throw e
        } catch (e: Throwable) {
            if (H3Session.transportCause(e) == null) {
                // the application cancelled its output while the pump waited on it: the stream is abandoned (code 0)
                runCatching { st.reset(WtErrorCodes.toHttp3(0)) }
            }
            outCh.cancel(map(e))
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
        runCatching { st.reset(h) }
        outPump?.cancel()
        outCh.cancel(IOException("WebTransport stream $streamId reset locally with $code"))
    }

    override fun stopSending(code: Long) {
        val h = WtErrorCodes.toHttp3(code)
        check(readable) { "stream $streamId is send-only" }
        runCatching { st.stopSending(h) }
        inPump?.cancel()
        inCh.cancel(IOException("WebTransport stream $streamId stopped locally with $code"))
    }

    /** The session is over: both directions end with WT_SESSION_GONE (section 6). */
    fun gone() {
        if (writable) runCatching { st.reset(Http3ErrorCode.WT_SESSION_GONE) }
        if (readable) runCatching { st.stopSending(Http3ErrorCode.WT_SESSION_GONE) }
        inPump?.cancel()
        outPump?.cancel()
        val e = WebTransportException.SessionClosed("the WebTransport session of stream $streamId is closed")
        inCh.cancel(e)
        outCh.cancel(e)
    }

    private companion object {
        const val CHUNK = 16_384
    }
}
