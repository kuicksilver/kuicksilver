// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteChannel
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.frame.FrameType
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

/** A decoded field section that also knows its never-indexed field lines (RFC 9204 section 4.5.4). */
internal class DecodedFields(
    fields: List<Pair<String, String>>,
    val neverIndexed: List<Pair<String, String>>,
) : List<Pair<String, String>> by fields

/** [this] with the regular never-indexed field lines of [decoded] (a [DecodedFields]) as received. */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
internal fun Http3Headers.receivedNeverIndexed(decoded: List<Pair<String, String>>): Http3Headers {
    val never = (decoded as? DecodedFields)?.neverIndexed?.filterNot { it.first.startsWith(':') }.orEmpty()
    return if (never.isEmpty()) this else withReceivedNeverIndexed(never)
}

/** The names [Http3Headers.neverIndexed] and [Http3Headers.neverIndexNames] give for sending. */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
internal fun Http3Headers.neverIndexNames(): Set<String> =
    if (neverIndexed.isEmpty()) neverIndexNames else neverIndexNames + neverIndexed.map { it.first }

/**
 * Encodes [fields] and writes them as a HEADERS frame on [st] (RFC 9114 section 7.2.2). Its `http:frame_created` follows
 * the write, as every frame's does: logged once the frame's write call returned; a write that throws logs nothing (a
 * later flush failure does not retract it).
 */
internal suspend fun H3Session.writeHeadersFrame(
    st: QuicStream,
    fields: List<Pair<String, String>>,
    neverIndexed: Set<String> = emptySet(),
) {
    val block = qpack.encode(st.id, fields, neverIndexed)
    st.output.writeFrame(FrameType.HEADERS, block)
    qlog { it.frameCreated(st.id, FrameType.HEADERS, block.size.toLong(), it.headers(fields)) }
}

/** Decodes a field section; TooLarge and malformed sections become [StreamFailure]. */
internal suspend fun H3Session.decodeSection(
    st: QuicStream,
    block: ByteArray,
): List<Pair<String, String>> {
    val r =
        try {
            // the peer reset the stream, or the connection is gone with the inserts the section waits for
            qpack.decode(st.id, block) { insertsWatch(st) }
        } catch (e: QpackError) {
            // a section that does not decode (a connection error follows) is in the trace without its fields
            qlog { it.frameParsed(st.id, FrameType.HEADERS, block.size.toLong(), it.headers(emptyList())) }
            throw e
        }
    qlog { it.frameParsed(st.id, FrameType.HEADERS, block.size.toLong(), it.headers((r as? DecodeResult.Decoded)?.fields.orEmpty())) }
    return when (r) {
        is DecodeResult.Decoded -> if (r.neverIndexed.isEmpty()) r.fields else DecodedFields(r.fields, r.neverIndexed)

        // a value longer than we decode is the stream error QPACK_DECOMPRESSION_FAILED (RFC 9204 section 7.4), fields that
        // only add up past the limit EXCESSIVE_LOAD; a server answers 431 for either (RFC 9114 section 4.2.2)
        is DecodeResult.TooLarge -> throw StreamFailure(
            if (r.valueTooLong) Http3ErrorCode.QPACK_DECOMPRESSION_FAILED else Http3ErrorCode.EXCESSIVE_LOAD,
            Http3Exception.FieldSectionTooLarge(st.id, settings.maxFieldSectionSize),
        )

        is DecodeResult.Blocked -> error("unreachable")
    }
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
    runCatching { cancelSections(st) }
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
    /** Whether our response on [st] was already complete: an H3_NO_ERROR reset then costs nothing ([H3Session.countClientReset]). */
    responseComplete: () -> Boolean = { false },
    /** Server: the request handed to the application, abandoned (and counted) at most once ([H3Session.countClientStop]). */
    abandoned: ServerRequestImpl? = null,
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
                            decodeSection(st, f.block).let { PseudoHeaders.parseTrailers(it).receivedNeverIndexed(it) }
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
                    // section 4.1: any HEADERS after the trailers is an invalid sequence, whatever its size
                    if (trailerFields != null) throw H3ProtocolError(Http3ErrorCode.FRAME_UNEXPECTED, "HEADERS after trailers")
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
        // server: a request handed to the application that the client made us reset (content-length broken, trailers too
        // large) is a glitch, as a malformed head is (RFC 9114 section 10.5; MadeYouReset, CVE-2025-8671); last: an empty
        // budget ends the connection
        if (abandoned != null) glitch("a malformed request (${e.code})")
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
        countClientReset(st.input.closedCause, responseComplete(), abandoned) // last: an empty budget ends the connection
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
        runCatching { cancelSections(st) }
        countClientReset(e, responseComplete(), abandoned) // last: an empty budget ends the connection
    }
}

/**
 * Hands what was written to [out] to its reader, waiting while the reader lags by more than the channel's buffer. Once the
 * connection is gone and [st] came whole (RFC 9000 section 3.2, "Data Recvd") it never waits: the rest of the message is
 * moved into [out] at once, bounded by the stream's flow-control window, so the reader finishes and the session can end
 * whether or not the application ever reads. The bytes then live as long as the application keeps the body, and no longer
 * through the session or the transport.
 *
 * "Gone" is the transport's end (`quic.closed`), not the session's: a local close completes the session's `closed` first,
 * and packets that were already in flight may still complete the stream before the transport acts on the close. Only the
 * transport's end settles `receivedAll`, the same verdict [H3Session.drains] readers get, so the two always agree.
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
            quic.closed.onAwait { if (detached(st)) waiting.cancel() else waiting.join() }
        }
    }
}

/** The transport is gone and [st] came whole: its verdict is final ([H3Session.drains]). */
@OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
private fun H3Session.detached(st: QuicStream): Boolean = quic.closed.isCompleted && st.receivedAll

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
