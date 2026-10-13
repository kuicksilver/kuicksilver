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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred

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
            qpack.decode(st.id, block) {
                st.input.closedCause !=
                    null
            }
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
                    st.input.copyExact(f.length, out, buf)
                    // suspends while the consumer lags by more than the channel's buffer: the body is never buffered without bound
                    out.flush()
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
                    out.flushAndClose()
                    trailers.complete(trailerFields)
                    return
                }
            }
        }
    } catch (
        e: CancellationException,
    ) {
        out.cancel(e)
        trailers.cancel(e)
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
