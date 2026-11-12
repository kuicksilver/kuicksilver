// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, InternalAPI::class)

package io.kuicksilver.ktor.network

import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.writeFully
import io.ktor.websocket.ProtocolViolationException
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.ktor.network.websocket.DeflateDataException
import io.kuicksilver.ktor.network.websocket.INFLATE_CHUNK
import io.kuicksilver.ktor.network.websocket.MessageInflater
import io.kuicksilver.tls.KslCrypto
import kotlinx.io.Buffer
import kotlinx.io.Sink
import kotlinx.io.readTo

/**
 * The channel Ktor's WebSocket session writes its frames to, which hands them on to [output] as RFC 6455 wants them on
 * the wire, whatever Ktor's writer did:
 *
 * - with [masking] (a client), every frame is masked with a new key from OpenSSL's CSPRNG (section 5.3: "the masking key
 *   MUST be derived from a strong source of entropy"; Ktor draws it from `kotlin.random.Random`); without (a server),
 *   none is (section 5.1: "A server MUST NOT mask any frames that it sends to the client", whatever Ktor's server
 *   `masking` setting says). Give Ktor's session `masking = false`: a key it sets is removed here anyway.
 * - the frames after the first of a fragmented message go out with opcode 0 (section 5.4); Ktor's common (Kotlin/Native)
 *   writer gives every fragment the message's opcode.
 * - a Close frame whose code an endpoint may not send ([isValidCloseCode]: 1005, 1006 and 1015 "MUST NOT be set as a
 *   status code in a Close control frame", section 7.4.1) goes out without a body, which means no status code; a reason
 *   that is not UTF-8 (section 5.5.1) is dropped and the code kept.
 * - compressed messages (RFC 7692) go out as RFC 7692 messages: RSV1 on the first frame only, one DEFLATE stream per
 *   message. How the sending extension frames them is [compression]: see [SentCompression]. A continuation with RSV1
 *   that cannot be made right is refused (section 6.1: an endpoint "MUST NOT set the "Per-Message Compressed" bit of
 *   control frames and non-first fragments of a data message").
 * - with [checkText] (`webSocketTextCheckable`: no extension but permessage-deflate), a text message must be UTF-8 as a
 *   whole (section 5.6: "the whole message MUST contain valid UTF-8"): Ktor's `Frame.Text(String)` always is, but
 *   `Frame.Text(fin, ByteArray)` carries the application's bytes. An uncompressed message is checked as it passes; a
 *   compressed one is inflated on the side and its text checked (RFC 7692 section 6: after decompression the payload is
 *   "subject to the constraints for the original data type again"), unless this library's `PerMessageDeflate`
 *   compressed it, which checks before it compresses.
 * - a message that breaks these rules is refused and nothing more is sent; the write fails with Ktor's
 *   `ProtocolViolationException`. At a frame boundary (a continuation that cannot be sent as RFC 7692 wants, refused
 *   before its header; a text message whose last frame ends inside a character) the connection is failed as RFC 6455
 *   section 7.1.7 asks: a Close with 1011, then the end of [output]. A byte that cannot be UTF-8 inside a frame whose
 *   header is already out leaves no frame boundary to put a Close at: [output] is cancelled (the connection is reset, as
 *   when the transport fails), so the peer never receives the message whole.
 *
 * The frames are rewritten as they pass, in the writer's own coroutine: what Ktor's writer flushed is on [output] when
 * its flush returns, so closing or resetting [output] after the session ended loses nothing. Only a frame header (at
 * most 14 bytes) and a Close frame (at most 139) wait for their last byte here. The side inflater's zlib state is freed
 * when the writer closes the channel ([ByteWriteChannel.flushAndClose], which Ktor's writers always call last).
 */
@InternalKuicksilverApi
public fun guardWebSocketOutput(
    output: ByteWriteChannel,
    masking: Boolean,
    checkText: Boolean = true,
    compression: SentCompression = SentCompression.Checked,
): ByteWriteChannel = OutputGuard(output, masking, checkText, compression)

/** How the extension that compresses what this side sends (permessage-deflate) frames a compressed message. */
@InternalKuicksilverApi
public enum class SentCompression {
    /**
     * Nothing is compressed, or this library's `PerMessageDeflate` compresses: its messages are RFC 7692 messages and it
     * checks text before it compresses, so compressed messages pass as they are.
     */
    Checked,

    /**
     * An RFC 7692 sender (an application's own extension): RSV1 on the first frame, one DEFLATE stream for the whole
     * message, the trailing 0x00 0x00 0xff 0xff removed at its end. Its text is inflated on the side and checked; RSV1 on
     * a continuation is refused.
     */
    PerMessage,

    /**
     * Ktor's `WebSocketDeflateExtension`: each frame compressed with a sync flush of its own, its 0x00 0x00 0xff 0xff
     * removed, and RSV1 on every frame. A fragmented message is made an RFC 7692 one here: a non-final frame gets its
     * 0x00 0x00 0xff 0xff back (the blocks of the next frame continue the same stream), and the continuations lose RSV1. A
     * fragment Ktor left uncompressed inside a compressed message (its `compressCondition` said no to that frame), or a
     * compressed fragment after an uncompressed first one, cannot be made right without compressing again: such a
     * message is refused. This follows Ktor 3.6.x's extension (the engines check the Ktor version they run with);
     * `ClientDeflateKtorTest` is the canary for a change in it.
     */
    PerFrame,
}

private class OutputGuard(
    private val output: ByteWriteChannel,
    private val masking: Boolean,
    private val checkText: Boolean,
    private val compression: SentCompression,
) : ByteWriteChannel {
    private val staged = Buffer()
    private val chunk = ByteArray(CHUNK)
    private val header = ByteArray(MAX_HEADER)
    private val wireHeader = ByteArray(MAX_HEADER)
    private var headerLength = 0
    private val closeBuffer = ByteArray(MAX_CONTROL.toInt())
    private var closeSize = -1 // -1: no Close being collected
    private var closeLength = 0

    // the frame being handed on
    private var payloadLeft = -1L // -1: reading a header
    private var position = 0L
    private val ktorMask = ByteArray(4)
    private var ktorMasked = false
    private val wireMask = ByteArray(4)
    private var dataFrame = false
    private var fin = false
    private var inflating = false // this frame is compressed and inflated on the side
    private var appendTail = false // this frame gets its 0x00 0x00 0xff 0xff back (SentCompression.PerFrame)
    private var messageCompressed = false

    // the message being handed on
    private var inMessage = false
    private val text = Utf8Validator()
    private var checkingText = false

    // side inflation of compressed text: a window kept across messages reads a sender that keeps it or not
    private val sideInflater: MessageInflater? =
        if (compression != SentCompression.Checked) MessageInflater(noContextTakeover = false, Long.MAX_VALUE) else null
    private var inflated: ByteArray? = null

    private var failure: Throwable? = null
    private var keys = ByteArray(0)
    private var keyAt = 0

    override val isClosedForWrite: Boolean get() = output.isClosedForWrite

    override val closedCause: Throwable? get() = output.closedCause

    override val writeBuffer: Sink get() = staged

    override suspend fun flush() {
        failure?.let { throw it }
        process()
        output.flush()
    }

    override suspend fun flushAndClose() {
        try {
            if (failure != null) return // the output was cancelled
            process()
            output.flushAndClose()
        } finally {
            sideInflater?.close()
        }
    }

    override fun cancel(cause: Throwable?) {
        output.cancel(cause)
    }

    private suspend fun process() {
        try {
            while (!staged.exhausted()) {
                when {
                    closeSize >= 0 -> closeBody()
                    payloadLeft < 0 -> headerByte()
                    else -> payload()
                }
            }
        } catch (r: Refusal) {
            throw fail(r)
        }
    }

    /** The next byte of a header; once the header is whole, it goes out rewritten (or a Close is collected). */
    private suspend fun headerByte() {
        header[headerLength++] = staged.readByte()
        if (headerLength < 2) return
        val b1 = header[1].toInt() and 0xff
        val lengthBytes =
            when (b1 and 0x7f) {
                126 -> 2
                127 -> 8
                else -> 0
            }
        val maskBytes = if (b1 and 0x80 != 0) 4 else 0
        if (headerLength < 2 + lengthBytes + maskBytes) return
        var length = (b1 and 0x7f).toLong()
        if (lengthBytes > 0) {
            length = 0
            for (i in 2 until 2 + lengthBytes) length = (length shl 8) or (header[i].toLong() and 0xff)
        }
        ktorMasked = maskBytes > 0
        if (ktorMasked) header.copyInto(ktorMask, 0, 2 + lengthBytes, 2 + lengthBytes + 4)
        headerLength = 0
        val b0 = header[0].toInt() and 0xff
        val opcode = b0 and 0x0f
        if (opcode == OPCODE_CLOSE && length <= MAX_CONTROL) { // Ktor's Frame.Close holds at most 125 bytes
            closeSize = length.toInt()
            closeLength = 0
            if (length == 0L) closeBody()
            return
        }
        var first = b0
        if (opcode < OPCODE_CLOSE) {
            val rsv1 = b0 and WS_RSV1 != 0
            val perFrame = compression == SentCompression.PerFrame
            if (inMessage) {
                // RFC 6455 section 5.4: inside a fragmented message every frame after the first is a continuation
                first = first and 0x0f.inv()
                // RFC 7692 section 6.1: no RSV1 on a continuation
                if (rsv1) {
                    if (!(perFrame && messageCompressed)) throw Refusal("RSV1 on a continuation frame (RFC 7692 section 6.1)")
                    first = first and WS_RSV1.inv()
                } else if (perFrame && messageCompressed) {
                    throw Refusal("an uncompressed fragment inside a compressed message (RFC 7692 section 6.1)")
                }
            } else {
                messageCompressed = rsv1
                // an RSV bit other than permessage-deflate's: an extension's payload, not text to check
                checkingText = checkText && opcode == OPCODE_TEXT && b0 and (WS_RSV2 or WS_RSV3) == 0 &&
                    (!rsv1 || sideInflater != null)
                text.reset()
            }
            inMessage = b0 and 0x80 == 0
            fin = !inMessage
            dataFrame = true
            inflating = checkingText && messageCompressed
            appendTail = perFrame && messageCompressed && !fin
        } else {
            dataFrame = false
            inflating = false
            appendTail = false
        }
        start(first, length + if (appendTail) TAIL.size else 0, length)
        if (payloadLeft < 0) endOfPayload()
    }

    /**
     * Sends the header of a frame of [length] payload bytes on the wire whose first byte is [b0], with a fresh key when
     * masking; [payload] of them follow from Ktor's writer.
     */
    private suspend fun start(
        b0: Int,
        length: Long,
        payload: Long = length,
    ) {
        val h = wireHeader
        var n = 0
        h[n++] = b0.toByte()
        val m = if (masking) 0x80 else 0
        when {
            length < 126 -> {
                h[n++] = (m or length.toInt()).toByte()
            }

            length <= 0xffff -> {
                h[n++] = (m or 126).toByte()
                h[n++] = (length shr 8).toByte()
                h[n++] = length.toByte()
            }

            else -> {
                h[n++] = (m or 127).toByte()
                for (shift in 56 downTo 0 step 8) h[n++] = (length shr shift).toByte()
            }
        }
        if (masking) {
            nextKey(wireMask)
            wireMask.copyInto(h, n)
            n += 4
        }
        output.writeFully(h, 0, n)
        payloadLeft = payload
        position = 0
        if (payload == 0L) payloadLeft = -1
    }

    /** Payload bytes of the current frame: Ktor's mask removed, the text checked, ours applied. */
    private suspend fun payload() {
        val n = minOf(payloadLeft, staged.size, chunk.size.toLong()).toInt()
        staged.readTo(chunk, 0, n)
        if (ktorMasked) unmask(chunk, n, ktorMask, position)
        if (dataFrame && checkingText) {
            try {
                if (inflating) {
                    inflateSide(chunk, n)
                } else if (!text.feed(chunk, 0, n)) {
                    throw notUtf8()
                }
            } catch (r: Refusal) {
                throw Refusal(r.what, atBoundary = false) // the frame's header is out: only a reset ends it
            }
        }
        if (masking) unmask(chunk, n, wireMask, position)
        output.writeFully(chunk, 0, n)
        position += n
        payloadLeft -= n
        if (payloadLeft == 0L) {
            payloadLeft = -1
            endOfPayload()
        }
    }

    /**
     * The end of a frame's payload: the side inflation ends the piece (each frame with [SentCompression.PerFrame], the
     * message otherwise), a non-final frame gets its 0x00 0x00 0xff 0xff back, a text message must end between
     * characters.
     */
    private suspend fun endOfPayload() {
        // the frame is whole on the wire first: a refusal below comes at a frame boundary
        if (appendTail) {
            val tail = TAIL.copyOf()
            if (masking) unmask(tail, tail.size, wireMask, position)
            output.writeFully(tail)
        }
        if (inflating && (fin || compression == SentCompression.PerFrame)) {
            val i = sideInflater!!
            guardSide {
                i.endOfMessage()
                drainSide(i)
                i.messageDone()
            }
        }
        if (dataFrame && fin && checkingText && !text.complete) throw notUtf8()
    }

    /** [length] compressed bytes of the frame: inflated on the side and their text checked; nothing of it is kept. */
    private fun inflateSide(
        bytes: ByteArray,
        length: Int,
    ) {
        val i = sideInflater!!
        guardSide {
            i.input(bytes, 0, length)
            drainSide(i)
        }
    }

    private fun drainSide(i: MessageInflater) {
        val o = inflated ?: ByteArray(INFLATE_CHUNK).also { inflated = it }
        while (true) {
            val n = i.read(o, 0, o.size)
            if (n == 0) return
            if (!text.feed(o, 0, n)) throw notUtf8()
        }
    }

    /** Data the extension compressed that does not inflate is the extension's matter: such a message is not checked. */
    private inline fun guardSide(block: () -> Unit) {
        try {
            block()
        } catch (_: DeflateDataException) {
            checkingText = false
            inflating = false
        }
    }

    private fun notUtf8(): Refusal = Refusal("a text message that is not UTF-8 (RFC 6455 section 5.6)")

    /**
     * Nothing more is sent, and the write fails with Ktor's `ProtocolViolationException`. At a frame boundary the
     * connection is failed as RFC 6455 section 7.1.7 asks: a Close with 1011 (masked on the client), then the end of the
     * output (FIN), and nothing after it (section 5.5.1). Inside a frame whose header is out, a Close cannot follow: the
     * output is cancelled (a reset).
     */
    private suspend fun fail(r: Refusal): Throwable {
        val e = ProtocolViolationException("${r.what} was not sent")
        failure = e
        staged.clear()
        if (r.atBoundary) {
            try {
                output.writeFully(closeFrame())
                output.flushAndClose()
            } catch (c: Throwable) {
                output.cancel(e)
                if (c is kotlinx.coroutines.CancellationException) throw c
            }
        } else {
            output.cancel(e)
        }
        return e
    }

    /** A Close frame with 1011 (RFC 6455 section 7.4.1: an unexpected condition), masked with a new key on the client. */
    private fun closeFrame(): ByteArray {
        val body = byteArrayOf(0x03, 0xF3.toByte())
        if (!masking) return byteArrayOf(0x88.toByte(), 0x02) + body
        nextKey(wireMask)
        unmask(body, body.size, wireMask, 0)
        return byteArrayOf(0x88.toByte(), 0x82.toByte()) + wireMask + body
    }

    /** Why the message cannot go out; [atBoundary] when no frame is half sent. */
    private class Refusal(
        val what: String,
        val atBoundary: Boolean = true,
    ) : Exception(what)

    /** Collects a Close frame's body; once whole, sends the Close with what of it an endpoint may send. */
    private suspend fun closeBody() {
        val body = closeBuffer
        val n = minOf((closeSize - closeLength).toLong(), staged.size).toInt()
        staged.readTo(body, closeLength, closeLength + n)
        closeLength += n
        if (closeLength < closeSize) return
        val size = closeSize
        closeSize = -1
        if (ktorMasked) unmask(body, size, ktorMask, 0)
        val sent =
            when {
                size < 2 -> 0
                !isValidCloseCode(((body[0].toInt() and 0xff) shl 8) or (body[1].toInt() and 0xff)) -> 0
                !isUtf8(body, 2, size) -> 2
                else -> size
            }
        start(0x80 or OPCODE_CLOSE, sent.toLong())
        if (masking) unmask(body, sent, wireMask, 0)
        if (sent > 0) output.writeFully(body, 0, sent)
        payloadLeft = -1
    }

    /** Four bytes of OpenSSL's CSPRNG (`RAND_bytes`), drawn [KEY_BATCH] keys at a time. */
    private fun nextKey(into: ByteArray) {
        if (keyAt == keys.size) {
            keys = KslCrypto.randomBytes(4 * KEY_BATCH)
            keyAt = 0
        }
        keys.copyInto(into, 0, keyAt, keyAt + 4)
        keys.fill(0, keyAt, keyAt + 4)
        keyAt += 4
    }

    private companion object {
        const val CHUNK = 8 * 1024
        const val MAX_HEADER = 14
        const val MAX_CONTROL = 125L
        const val KEY_BATCH = 64

        /** The empty stored block a sync flush ends with (RFC 7692 section 7.2.1). */
        val TAIL = byteArrayOf(0x00, 0x00, 0xff.toByte(), 0xff.toByte())
    }
}
