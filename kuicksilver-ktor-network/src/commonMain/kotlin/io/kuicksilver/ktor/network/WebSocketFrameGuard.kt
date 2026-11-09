// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readFully
import io.ktor.utils.io.writeByte
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.ktor.network.websocket.DeflateDataException
import io.kuicksilver.ktor.network.websocket.INFLATE_CHUNK
import io.kuicksilver.ktor.network.websocket.MessageInflater
import io.kuicksilver.ktor.network.websocket.MessageTooBigException
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.ktor.network.websocket.WebSocketInflate
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.io.EOFException
import kotlin.coroutines.CoroutineContext

/*
 * The engines' check of the WebSocket frames a peer sends, against what the handshake negotiated (RFC 6455 sections 5.2
 * and 9.1, RFC 7692 section 6.1): Ktor's frame readers accept any RSV bit whether or not an extension gave it a meaning.
 */

/** RSV1 in the first byte of a WebSocket frame (RFC 6455 section 5.2); permessage-deflate's "compressed" bit. */
@InternalKuicksilverApi
public const val WS_RSV1: Int = 0x40

/** RSV2 in the first byte of a WebSocket frame. */
@InternalKuicksilverApi
public const val WS_RSV2: Int = 0x20

/** RSV3 in the first byte of a WebSocket frame. */
@InternalKuicksilverApi
public const val WS_RSV3: Int = 0x10

/** All three RSV bits. */
@InternalKuicksilverApi
public const val WS_RSV_ALL: Int = WS_RSV1 or WS_RSV2 or WS_RSV3

/**
 * The extension names of `Sec-WebSocket-Extensions` field values (RFC 6455 section 9.1: a comma-separated list of
 * `name; param; param=value`), lower-cased, in order; a comma inside a quoted parameter value does not split the list.
 */
@InternalKuicksilverApi
public fun webSocketExtensionNames(values: List<String>): List<String> {
    val names = ArrayList<String>()
    for (value in values) {
        var quoted = false
        var escaped = false
        var inName = true
        val name = StringBuilder()

        fun end() {
            val n = name.toString().trim().lowercase()
            if (n.isNotEmpty()) names += n
            name.clear()
            inName = true
        }
        for (c in value) {
            when {
                escaped -> {
                    escaped = false
                }

                quoted && c == '\\' -> {
                    escaped = true
                }

                c == '"' -> {
                    quoted = !quoted
                }

                quoted -> {}

                c == ',' -> {
                    end()
                }

                c == ';' -> {
                    inName = false
                }

                inName -> {
                    name.append(c)
                }
            }
        }
        end()
    }
    return names
}

/**
 * The RSV bits a peer's frames may set after a handshake in which [offered] extensions were requested and [accepted]
 * ones answered ([webSocketExtensionNames]); an extension counts only when it is in both. `permessage-deflate` (RFC 7692)
 * gives RSV1; any other extension both sides agreed on is the application's own, whose bits the engine does not know, so
 * then every bit is allowed ([WS_RSV_ALL]). No extension: 0.
 */
@InternalKuicksilverApi
public fun negotiatedWebSocketRsv(
    offered: List<String>,
    accepted: List<String>,
): Int {
    var rsv = 0
    for (name in accepted) {
        if (name !in offered) continue
        rsv = rsv or if (name == PERMESSAGE_DEFLATE) WS_RSV1 else WS_RSV_ALL
    }
    return rsv
}

/** The name of the WebSocket per-message compression extension (RFC 7692 section 7). */
private const val PERMESSAGE_DEFLATE = "permessage-deflate"

/**
 * The WebSocket frames of [input], passed through unchanged frame by frame after their first byte was checked (RFC 6455
 * section 5.2): an opcode that is not defined (3-7, 11-15), an RSV bit outside [allowedRsv], or, when [allowedRsv] is
 * exactly [WS_RSV1] (permessage-deflate), RSV1 on a continuation or control frame (RFC 7692 section 6.1), a mask bit
 * that does not match [peerMasks] (RFC 6455 section 5.1: a client masks every frame, a server none), or a 64-bit payload
 * length whose most significant bit is set (section 5.2: it MUST be 0) fails the
 * connection (RFC 6455 section 7.1.7) with code 1002 (protocol error): in place of that frame the returned channel
 * carries a Close frame with 1002 and the reason, then ends. Ktor's session answers it with the same Close through its
 * own writer (the only writer of the connection), so 1002 is what goes on the wire and is the session's `closeReason`;
 * its `incoming` then ends without the bad frame or anything after it, and every frame before it was delivered. A raw
 * session (`webSocketRaw`) sees that Close frame in `incoming` and answers it itself, as any Close.
 *
 * The violation is not raised as Ktor's `ProtocolViolationException` in the reader: on its common (Kotlin/Native) reader
 * the session's `incoming` closes before its 1002 is queued, so an application closing at that moment sends 1000 first,
 * and ktor-io's `readAvailable` (its JVM reader) reports a cancelled channel as an ordinary end of stream.
 *
 * With [untilClose], the channel ends after the peer's Close frame: the session is over once Close frames were exchanged
 * (RFC 6455 section 7.1.1), and the peer sends no frame after its Close (section 5.5.1). Ktor's JVM WebSocket reader stops
 * at the Close frame; its common (Native) reader reads to the end of the stream, so without this a Native session would
 * wait for the peer's FIN, which may trail the Close frame or not come at all.
 *
 * With [inflate] (Kuicksilver's engines with [PerMessageDeflate] negotiated, RFC 7692 section 7.2.2), each message whose
 * first frame has RSV1 is decompressed as its frames arrive and handed on as plain frames (no RSV1) of at most 64 KiB
 * each, the first with the message's opcode and the rest continuations, so Ktor's session and the extension see it
 * uncompressed; uncompressed messages and control frames between the fragments pass as they are. A message that inflates
 * to more than [WebSocketInflate.maxMessageSize] bytes is cut off there with a Close frame with 1009 (RFC 6455 section
 * 7.4.1, message too big) after at most 64 KiB more than the limit was handed on; malformed compressed data, a
 * continuation frame outside a message or a new message inside a fragmented one ends it with 1002, as above.
 *
 * A failed [input] fails the returned channel with its cause, and the end of [input] ends it. The copy runs in [context]
 * but outside its job, so it never holds a call open (a reader that gave up, e.g. on a frame over its limit, leaves it
 * waiting for room); the end of [context]'s job stops it.
 */
@InternalKuicksilverApi
public fun guardWebSocketInput(
    input: ByteReadChannel,
    allowedRsv: Int,
    untilClose: Boolean,
    peerMasks: Boolean,
    context: CoroutineContext,
    inflate: WebSocketInflate? = null,
): ByteReadChannel {
    val out = ByteChannel()
    val job = Job()
    context[Job]?.invokeOnCompletion { job.cancel() }
    CoroutineScope(context + job).launch(CoroutineName("ws-frame-guard")) {
        val inflater = inflate?.let { GuardInflater(it) }
        val header = ByteArray(MAX_HEADER)
        try {
            while (true) {
                val b0 = input.readByte()
                val b1 = input.readByte()
                violation(b0.toInt() and 0xff, b1.toInt() and 0xff, allowedRsv, peerMasks)?.let {
                    out.failWith(CLOSE_PROTOCOL_ERROR, "Received illegal frame: $it")
                    return@launch
                }
                header[0] = b0
                header[1] = b1
                var n = 2
                var length = (b1.toInt() and 0x7f).toLong()
                val extended =
                    when (length) {
                        126L -> 2
                        127L -> 8
                        else -> 0
                    }
                if (extended > 0) {
                    length = 0
                    repeat(extended) {
                        val b = input.readByte()
                        header[n++] = b
                        length = (length shl 8) or (b.toLong() and 0xff)
                    }
                }
                val maskAt = n
                if (b1.toInt() and 0x80 != 0) repeat(4) { header[n++] = input.readByte() } // masking key
                if (length < 0) {
                    out.failWith(CLOSE_PROTOCOL_ERROR, "Received illegal frame: a 64-bit length with its most significant bit set")
                    return@launch
                }
                val opcode = b0.toInt() and 0x0f
                if (inflater != null && opcode < OPCODE_CLOSE) {
                    inflater.sequenceViolation(opcode)?.let {
                        out.failWith(CLOSE_PROTOCOL_ERROR, "Received illegal frame: $it")
                        return@launch
                    }
                    val fin = b0.toInt() and 0x80 != 0
                    if (inflater.dataFrame(opcode, fin, compressed = b0.toInt() and WS_RSV1 != 0)) {
                        val mask = if (n > maskAt) header.copyOfRange(maskAt, n) else null
                        try {
                            inflater.inflateFrame(input, out, length, mask, fin)
                        } catch (e: MessageTooBigException) {
                            val reason =
                                if (e.compressedBytes) {
                                    "Message is too big: more than ${e.limit} compressed bytes"
                                } else {
                                    "Message is too big: more than ${e.limit} bytes inflated"
                                }
                            out.failWith(CLOSE_MESSAGE_TOO_BIG, reason)
                            return@launch
                        } catch (_: DeflateDataException) {
                            // zlib's own message stays here: it says nothing the peer needs
                            out.failWith(CLOSE_PROTOCOL_ERROR, "Invalid compressed data")
                            return@launch
                        }
                        continue
                    }
                }
                out.writeFully(header, 0, n)
                if (length > 0 && input.copyTo(out, length) < length) {
                    // ktor-io's copyTo stops on an input failed with a cause as at its end, without the cause
                    input.closedCause?.let { throw it }
                    break
                }
                out.flush()
                if (untilClose && opcode == OPCODE_CLOSE) break
            }
            out.flushAndClose()
        } catch (_: EOFException) {
            // the stream ended (between or inside frames): so does the session's input. ktor-io's readFully answers an input
            // failed with a cause with an EOFException too: that one fails the session's input with the cause
            val cause = input.closedCause
            if (cause == null) out.flushAndClose() else out.cancel(cause)
        } catch (cause: Throwable) {
            out.cancel(cause)
        } finally {
            inflater?.close()
        }
    }
    return out
}

/** Writes a Close frame with [code] and [reason] in place of the frame that broke the rules, and ends the channel. */
private suspend fun ByteChannel.failWith(
    code: Int,
    reason: String,
) {
    writeFully(closeFrame(code, reason))
    flushAndClose()
}

/** The longest frame header: 2 bytes, an 8-byte length and a 4-byte masking key. */
private const val MAX_HEADER = 14

/**
 * The guard's half of permessage-deflate (RFC 7692 section 7.2.2): which message the frames belong to and whether it is
 * compressed, and the decompression of a compressed one into frames of at most [INFLATE_CHUNK] bytes.
 */
private class GuardInflater(
    spec: WebSocketInflate,
) {
    private val inflater = MessageInflater(spec.noContextTakeover, spec.maxMessageSize)
    private var inMessage = false
    private var compressed = false
    private var messageOpcode = 0
    private var emitted = false
    private var output: ByteArray? = null
    private var outputLength = 0
    private var buffer: ByteArray? = null

    /** Why a data frame with [opcode] cannot come now (RFC 6455 section 5.4), or null. */
    fun sequenceViolation(opcode: Int): String? =
        when {
            opcode == OPCODE_CONTINUATION && !inMessage -> "a continuation frame outside a fragmented message"
            opcode != OPCODE_CONTINUATION && inMessage -> "a new message before the fragmented one ended"
            else -> null
        }

    /** Follows a data frame; true when its payload is compressed data for [inflateFrame]. */
    fun dataFrame(
        opcode: Int,
        fin: Boolean,
        compressed: Boolean,
    ): Boolean {
        if (opcode != OPCODE_CONTINUATION) {
            this.compressed = compressed
            messageOpcode = opcode
            emitted = false
        }
        inMessage = !fin
        return this.compressed
    }

    /** Reads the [length] bytes of compressed payload (unmasked with [mask]) and writes what they inflate to. */
    suspend fun inflateFrame(
        input: ByteReadChannel,
        out: ByteChannel,
        length: Long,
        mask: ByteArray?,
        fin: Boolean,
    ) {
        val buf = buffer ?: ByteArray(INPUT_CHUNK).also { buffer = it }
        var left = length
        var position = 0L
        while (left > 0) {
            val n = minOf(left, buf.size.toLong()).toInt()
            input.readFully(buf, 0, n)
            if (mask != null) for (i in 0 until n) buf[i] = (buf[i].toInt() xor mask[((position + i) and 3).toInt()].toInt()).toByte()
            position += n
            left -= n
            inflater.input(buf, 0, n)
            drain(out)
        }
        if (fin) {
            inflater.endOfMessage()
            drain(out)
            emit(out, fin = true)
            inflater.messageDone()
        } else if (outputLength > 0) {
            emit(out, fin = false) // what this frame gave goes on now: the next frame may be a while
        }
        out.flush()
    }

    private suspend fun drain(out: ByteChannel) {
        val o = output ?: ByteArray(INFLATE_CHUNK).also { output = it }
        while (true) {
            val n = inflater.read(o, outputLength, o.size - outputLength)
            if (n == 0) return
            outputLength += n
            if (outputLength == o.size) emit(out, fin = false)
        }
    }

    private suspend fun emit(
        out: ByteChannel,
        fin: Boolean,
    ) {
        val opcode = if (emitted) OPCODE_CONTINUATION else messageOpcode
        out.writeByte(((if (fin) 0x80 else 0) or opcode).toByte())
        when {
            outputLength < 126 -> {
                out.writeByte(outputLength.toByte())
            }

            outputLength <= 0xffff -> {
                out.writeByte(126.toByte())
                out.writeByte((outputLength shr 8).toByte())
                out.writeByte(outputLength.toByte())
            }

            else -> { // a whole piece, 64 KiB: the 64-bit length
                out.writeByte(127.toByte())
                for (shift in 56 downTo 0 step 8) out.writeByte((outputLength.toLong() shr shift).toByte())
            }
        }
        if (outputLength > 0) out.writeFully(output!!, 0, outputLength)
        emitted = true
        outputLength = 0
    }

    fun close() {
        inflater.close()
    }
}

/** The compressed payload is read in pieces of this size. */
private const val INPUT_CHUNK = 16 * 1024

/** RFC 6455 section 7.4.1: 1009, an endpoint received a message too big for it to process. */
private const val CLOSE_MESSAGE_TOO_BIG = 1009

/** RFC 6455 section 7.4.1: 1002, an endpoint is terminating the connection due to a protocol error. */
private const val CLOSE_PROTOCOL_ERROR = 1002

/** An unmasked Close frame with [code] and [reason] (cut to the 123 bytes a control frame leaves it). */
private fun closeFrame(
    code: Int,
    reason: String,
): ByteArray {
    val text = reason.encodeToByteArray().let { if (it.size > 123) it.copyOf(123) else it }
    return byteArrayOf((0x80 or OPCODE_CLOSE).toByte(), (2 + text.size).toByte(), (code shr 8).toByte(), code.toByte()) + text
}

/** Why a frame whose first two bytes are [b0] and [b1] breaks the protocol, or null when it does not. */
private fun violation(
    b0: Int,
    b1: Int,
    allowedRsv: Int,
    peerMasks: Boolean,
): String? {
    val opcode = b0 and 0x0f
    val rsv = b0 and WS_RSV_ALL
    val masked = b1 and 0x80 != 0
    return when {
        masked != peerMasks -> {
            if (peerMasks) "unmasked frame from a client" else "masked frame from a server"
        }

        opcode in 3..7 || opcode > OPCODE_PONG -> {
            "reserved opcode $opcode"
        }

        rsv and allowedRsv.inv() != 0 -> {
            "RSV bits 0x${rsv.toString(16)} set without an extension that defines them"
        }

        allowedRsv == WS_RSV1 && rsv != 0 && (opcode == OPCODE_CONTINUATION || opcode >= OPCODE_CLOSE) -> {
            "RSV1 on a ${if (opcode == OPCODE_CONTINUATION) "continuation" else "control"} frame (RFC 7692 section 6.1)"
        }

        else -> {
            null
        }
    }
}

private const val OPCODE_CONTINUATION = 0x0
private const val OPCODE_CLOSE = 0x8
private const val OPCODE_PONG = 0xA
