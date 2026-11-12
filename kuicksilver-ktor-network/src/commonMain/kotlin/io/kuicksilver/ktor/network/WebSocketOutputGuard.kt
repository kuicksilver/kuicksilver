// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, InternalAPI::class)

package io.kuicksilver.ktor.network

import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.writeFully
import io.ktor.websocket.ProtocolViolationException
import io.kuicksilver.annotations.InternalKuicksilverApi
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
 * - a text message that no extension transformed (no RSV bit on its first frame) must be UTF-8 as a whole (section
 *   5.6: "the whole message MUST contain valid UTF-8"): Ktor's `Frame.Text(String)` always is, but `Frame.Text(fin,
 *   ByteArray)` carries the application's bytes. At the first byte that cannot be UTF-8, or a message that ends inside a
 *   character, nothing more is sent: [output] is cancelled (the connection is reset, as when the transport fails) and
 *   the write fails with Ktor's `ProtocolViolationException`, so the peer never receives the message whole.
 *
 * The frames are rewritten as they pass, in the writer's own coroutine: what Ktor's writer flushed is on [output] when
 * its flush returns, so closing or resetting [output] after the session ended loses nothing. Only a frame header (at
 * most 14 bytes) and a Close frame (at most 139) wait for their last byte here.
 */
@InternalKuicksilverApi
public fun guardWebSocketOutput(
    output: ByteWriteChannel,
    masking: Boolean,
): ByteWriteChannel = OutputGuard(output, masking)

private class OutputGuard(
    private val output: ByteWriteChannel,
    private val masking: Boolean,
) : ByteWriteChannel {
    private val staged = Buffer()
    private val chunk = ByteArray(CHUNK)
    private val header = ByteArray(MAX_HEADER)
    private var headerLength = 0
    private var close: ByteArray? = null
    private var closeLength = 0

    // the frame being handed on
    private var payloadLeft = -1L // -1: reading a header
    private var position = 0L
    private var ktorMask: ByteArray? = null
    private val wireMask = ByteArray(4)
    private var inMessage = false
    private val text = Utf8Validator()
    private var checkingText = false
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
        if (failure != null) return // the output was cancelled
        process()
        output.flushAndClose()
    }

    override fun cancel(cause: Throwable?) {
        output.cancel(cause)
    }

    private suspend fun process() {
        while (!staged.exhausted()) {
            when {
                close != null -> closeBody()
                payloadLeft < 0 -> headerByte()
                else -> payload()
            }
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
        ktorMask = if (maskBytes > 0) header.copyOfRange(2 + lengthBytes, 2 + lengthBytes + 4) else null
        headerLength = 0
        val b0 = header[0].toInt() and 0xff
        val opcode = b0 and 0x0f
        if (opcode == OPCODE_CLOSE && length <= MAX_CONTROL) { // Ktor's Frame.Close holds at most 125 bytes
            close = ByteArray(length.toInt())
            closeLength = 0
            if (length == 0L) closeBody()
            return
        }
        var first = b0
        if (opcode < OPCODE_CLOSE) {
            // RFC 6455 section 5.4: inside a fragmented message every frame after the first is a continuation
            if (inMessage) {
                first = first and 0x0f.inv()
            } else {
                checkingText = opcode == OPCODE_TEXT && b0 and WS_RSV_ALL == 0
                text.reset()
            }
            inMessage = b0 and 0x80 == 0
            fin = !inMessage
            dataFrame = true
        } else {
            dataFrame = false
        }
        start(first, length)
        if (payloadLeft < 0) endOfPayload()
    }

    // the frame being handed on is a data frame, and the last of its message
    private var dataFrame = false
    private var fin = false

    /** The end of a frame's payload: a text message must end between characters (RFC 6455 section 5.6). */
    private fun endOfPayload() {
        if (dataFrame && fin && checkingText && !text.complete) throw notUtf8()
    }

    private fun notUtf8(): Throwable {
        val e = ProtocolViolationException("a text message that is not UTF-8 (RFC 6455 section 5.6) was not sent")
        failure = e
        staged.clear()
        output.cancel(e)
        return e
    }

    /** Sends the header of a frame of [length] payload bytes whose first byte is [b0], with a fresh key when masking. */
    private suspend fun start(
        b0: Int,
        length: Long,
    ) {
        val h = ByteArray(MAX_HEADER)
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
        payloadLeft = length
        position = 0
        if (length == 0L) payloadLeft = -1
    }

    /** Payload bytes of the current frame: Ktor's mask removed, ours applied. */
    private suspend fun payload() {
        val n = minOf(payloadLeft, staged.size, chunk.size.toLong()).toInt()
        staged.readTo(chunk, 0, n)
        ktorMask?.let { unmask(chunk, n, it, position) }
        if (dataFrame && checkingText && !text.feed(chunk, 0, n)) throw notUtf8()
        if (masking) unmask(chunk, n, wireMask, position)
        output.writeFully(chunk, 0, n)
        position += n
        payloadLeft -= n
        if (payloadLeft == 0L) {
            payloadLeft = -1
            endOfPayload()
        }
    }

    /** Collects a Close frame's body; once whole, sends the Close with what of it an endpoint may send. */
    private suspend fun closeBody() {
        val body = close!!
        val n = minOf((body.size - closeLength).toLong(), staged.size).toInt()
        staged.readTo(body, closeLength, closeLength + n)
        closeLength += n
        if (closeLength < body.size) return
        close = null
        ktorMask?.let { unmask(body, body.size, it, 0) }
        val sent =
            when {
                body.size < 2 -> ByteArray(0)
                !isValidCloseCode(((body[0].toInt() and 0xff) shl 8) or (body[1].toInt() and 0xff)) -> ByteArray(0)
                !isUtf8(body, 2, body.size) -> body.copyOf(2)
                else -> body
            }
        start(0x80 or OPCODE_CLOSE, sent.size.toLong())
        if (masking) unmask(sent, sent.size, wireMask, 0)
        if (sent.isNotEmpty()) output.writeFully(sent)
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
    }
}
