// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteChannel
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.frame.H3ProtocolError
import io.kuicksilver.http3.message.MalformedMessage
import io.kuicksilver.http3.message.PseudoHeaders
import io.kuicksilver.http3.qpack.DecodeResult
import io.kuicksilver.http3.qpack.QpackError
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.receivedAll
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select

/** A failure confined to one stream (RFC 9114 section 8): abort it with [code] and give the application [error]. */
internal class StreamFailure(
    val code: Long,
    val error: Throwable,
) : Exception(error)

internal const val CHUNK = 16_384

/** Decodes a field section; TooLarge and malformed sections become [StreamFailure]. */
internal suspend fun H3Session.decodeSection(
    st: QuicStream,
    block: ByteArray,
): List<Pair<String, String>> =
    when (
        val r =
            // the peer reset the stream, or the connection is gone with the inserts the section waits for
            qpack.decode(st.id, block) { st.input.closedCause != null || noMoreInserts() }
    ) {
        is DecodeResult.Decoded -> r.fields

        DecodeResult.TooLarge -> throw StreamFailure(
            Http3ErrorCode.EXCESSIVE_LOAD,
            Http3Exception.FieldSectionTooLarge(st.id, settings.maxFieldSectionSize),
        )

        is DecodeResult.Blocked -> error("unreachable")
    }

internal fun malformed(
    streamId: Long,
    e: MalformedMessage,
) = StreamFailure(Http3ErrorCode.MESSAGE_ERROR, Http3Exception.MessageError(streamId, e.reason))

/** Aborts both directions of [st] with [code]; QPACK forgets the stream. */
internal suspend fun H3Session.abort(
    st: QuicStream,
    code: Long,
) {
    runCatching { st.stopSending(code) }
    runCatching { st.reset(code) }
    runCatching { qpack.cancelStream(st.id) }
}

/**
 * Reads the rest of a message after its first HEADERS: DATA into [out], optional trailers into [trailers], nothing after
 * them (RFC 9114 section 4.1). `content-length` must match the DATA total (section 4.1.2). While [tunnel] is true (a
 * CONNECT answered with 2xx) only DATA may come: a HEADERS frame is a connection error H3_FRAME_UNEXPECTED (section 4.4).
 */
internal suspend fun H3Session.pumpBody(
    st: QuicStream,
    frames: RequestFrames,
    out: ByteChannel,
    trailers: CompletableDeferred<Http3Headers?>,
    contentLength: Long?,
    tunnel: () -> Boolean = { false },
    onStreamFailure: suspend (StreamFailure) -> Unit,
) {
    val buf = ByteArray(CHUNK)
    var total = 0L
    var trailerFields: Http3Headers? = null
    try {
        while (true) {
            when (val f = frames.next()) {
                is RequestFrame.Data -> {
                    if (trailerFields != null) throw H3ProtocolError(Http3ErrorCode.FRAME_UNEXPECTED, "DATA after trailers")
                    total += f.length
                    if (contentLength != null &&
                        total > contentLength
                    ) {
                        throw StreamFailure(
                            Http3ErrorCode.MESSAGE_ERROR,
                            Http3Exception.MessageError(st.id, "more DATA than content-length"),
                        )
                    }
                    // waits while the consumer lags by more than the channel's buffer: the body is never buffered without bound
                    // (once the connection is gone with the stream whole, what is left is bounded by its window: no wait)
                    st.input.copyExact(f.length, out, buf) { handOver(out, st) }
                }

                is RequestFrame.Headers -> {
                    if (tunnel()) {
                        throw H3ProtocolError(
                            Http3ErrorCode.FRAME_UNEXPECTED,
                            "HEADERS on the established CONNECT stream ${st.id}",
                        )
                    }
                    if (trailerFields != null) throw H3ProtocolError(Http3ErrorCode.FRAME_UNEXPECTED, "HEADERS after trailers")
                    trailerFields =
                        try {
                            PseudoHeaders.parseTrailers(decodeSection(st, f.block))
                        } catch (
                            e: MalformedMessage,
                        ) {
                            throw malformed(st.id, e)
                        }
                }

                is RequestFrame.HeadersTooLarge -> {
                    if (tunnel()) {
                        throw H3ProtocolError(
                            Http3ErrorCode.FRAME_UNEXPECTED,
                            "HEADERS on the established CONNECT stream ${st.id}",
                        )
                    }
                    throw StreamFailure(
                        Http3ErrorCode.EXCESSIVE_LOAD,
                        Http3Exception.FieldSectionTooLarge(st.id, settings.maxFieldSectionSize),
                    )
                }

                RequestFrame.End -> {
                    if (contentLength != null &&
                        total != contentLength
                    ) {
                        throw StreamFailure(
                            Http3ErrorCode.MESSAGE_ERROR,
                            Http3Exception.MessageError(st.id, "DATA total $total differs from content-length $contentLength"),
                        )
                    }
                    // as flushAndClose: a consumer that already gave up the body changes nothing here
                    try {
                        handOver(out, st)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Throwable) {
                    }
                    out.close()
                    trailers.complete(trailerFields)
                    return
                }
            }
        }
    } catch (
        e: CancellationException,
    ) {
        // the session's scope goes with the connection, and may cancel the pump before it read the transport's failure: the
        // body then fails with the connection's reason, which is what the reader needs, not the pump's own cancellation
        if (closed.isCompleted) {
            val reason = closed.getCompleted()
            out.cancel(reason)
            trailers.completeExceptionally(reason)
        } else {
            out.cancel(e)
            trailers.cancel(e)
        }
        throw e
    } catch (
        e: StreamFailure,
    ) {
        onStreamFailure(e)
        out.cancel(e.error)
        trailers.completeExceptionally(e.error)
    } catch (
        e: IncompleteFrame,
    ) {
        truncated(st, out, trailers)
    } catch (
        e: H3ProtocolError,
    ) {
        out.cancel(Http3Exception.Protocol(e.code, Initiator.Local, null, e.message))
        trailers.completeExceptionally(e)
        fail(
            e.code,
            e.message ?: "",
        )
    } catch (
        e: QpackError,
    ) {
        out.cancel(Http3Exception.Qpack(e.code, e.message))
        trailers.completeExceptionally(e)
        fail(
            e.code,
            e.message ?: "",
        )
    } catch (
        e: StreamAbandoned,
    ) {
        // the peer reset the stream while its trailers waited for the encoder stream: the body fails with that reset, and
        // the Stream Cancellation was already sent (RFC 9204 section 4.4.2)
        val mapped = map(st.input.closedCause ?: if (noMoreInserts()) connectionError() else e)
        out.cancel(mapped)
        trailers.completeExceptionally(mapped)
    } catch (e: Throwable) {
        // the consumer cancelled the body (its own reason), or the transport failed (a reset, a lost connection)
        val mapped = map(e)
        if (out.isClosedForWrite &&
            out.closedCause != null
        ) {
            runCatching { st.stopSending(if (isServer) Http3ErrorCode.NO_ERROR else Http3ErrorCode.REQUEST_CANCELLED) }
        } else {
            out.cancel(mapped)
        }
        trailers.completeExceptionally(mapped)
        // trailers may still have been on the way: the peer's encoder must not wait for their acknowledgment (RFC 9204 section 2.2.2.2)
        runCatching { qpack.cancelStream(st.id) }
    }
}

/**
 * Hands what was written to [out] to its reader, waiting while the reader lags by more than the channel's buffer. Once the
 * connection is gone and [st] came whole (RFC 9000 section 3.2, "Data Recvd") it never waits: the rest of the message is
 * moved into [out] at once, bounded by the stream's flow-control window, so the reader finishes and the session can end
 * whether or not the application ever reads. The bytes then live as long as the application keeps the body, and no longer
 * through the session or the transport.
 */
@OptIn(io.ktor.utils.io.InternalAPI::class) // flushWriteBuffer and hasFreeSpace: hand over without waiting
internal suspend fun H3Session.handOver(
    out: ByteChannel,
    st: QuicStream,
) {
    out.flushWriteBuffer()
    if (out.hasFreeSpace || detached(st)) return
    coroutineScope {
        val waiting = launch { out.flush() }
        select {
            waiting.onJoin {}
            closed.onAwait { if (detached(st)) waiting.cancel() else waiting.join() }
        }
    }
}

@OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
private fun H3Session.detached(st: QuicStream): Boolean = closed.isCompleted && st.receivedAll

/** A clean end of stream inside a frame: a connection error H3_FRAME_ERROR (RFC 9114 section 7.1). */
internal suspend fun H3Session.truncated(
    st: QuicStream,
    out: ByteChannel?,
    trailers: CompletableDeferred<Http3Headers?>?,
) {
    val reason = "stream ${st.id} ended inside a frame"
    val x = Http3Exception.Protocol(Http3ErrorCode.FRAME_ERROR, Initiator.Local, null, reason)
    out?.cancel(x)
    trailers?.completeExceptionally(x)
    fail(Http3ErrorCode.FRAME_ERROR, reason)
}

internal fun contentLength(h: Http3Headers): Long? = h["content-length"]?.trim()?.toLongOrNull()
