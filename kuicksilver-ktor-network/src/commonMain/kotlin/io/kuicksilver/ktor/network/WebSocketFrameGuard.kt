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
import io.ktor.websocket.WebSocketExtension
import io.ktor.websocket.WebSocketExtensionFactory
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
 * The engines' check of the WebSocket frames a peer sends (RFC 6455 sections 5 to 8 and 10.4, RFC 7692 section 6.1), in
 * front of Ktor's session: its frame readers accept any RSV bit whether or not an extension gave it a meaning, check no
 * UTF-8 and no Close code, and its JVM reader allocates whatever length a frame claims.
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
 * gives RSV1. Another extension gives the bits its factory declares when one of the [installed] Ktor extensions answers
 * to its name, and every bit ([WS_RSV_ALL]) when none does: then it is the application's own, whose bits the engine does
 * not know. No extension: 0.
 */
@InternalKuicksilverApi
public fun negotiatedWebSocketRsv(
    offered: List<String>,
    accepted: List<String>,
    installed: List<WebSocketExtension<*>> = emptyList(),
): Int {
    var rsv = 0
    for (name in accepted) {
        if (name !in offered) continue
        rsv = rsv or
            if (name == PERMESSAGE_DEFLATE) {
                WS_RSV1
            } else {
                installed.firstOrNull { e -> e.protocols.any { it.name.trim().lowercase() == name } }?.factory?.rsvBits() ?: WS_RSV_ALL
            }
    }
    return rsv
}

/** Whether `permessage-deflate` was agreed ([negotiatedWebSocketRsv]): RFC 7692 section 6.1 then governs RSV1. */
@InternalKuicksilverApi
public fun negotiatedPerMessageDeflate(
    offered: List<String>,
    accepted: List<String>,
): Boolean = PERMESSAGE_DEFLATE in offered && PERMESSAGE_DEFLATE in accepted

/**
 * Whether the payload of text messages, once the engines have decompressed a `permessage-deflate` message themselves
 * (`negotiatedWebSocketInflate`), is the text an application sent, which the guards check is UTF-8 (RFC 6455 sections
 * 5.6 and 8.1): no extension was agreed, or only `permessage-deflate`, whichever implementation. Another extension is
 * the application's own: its specification, not RFC 6455, defines what its payload is, and a payload it transforms
 * without an RSV bit is not touched.
 */
@InternalKuicksilverApi
public fun webSocketTextCheckable(
    offered: List<String>,
    accepted: List<String>,
): Boolean = accepted.filter { it in offered }.all { it == PERMESSAGE_DEFLATE }

private fun WebSocketExtensionFactory<*, *>.rsvBits(): Int =
    (if (rsv1) WS_RSV1 else 0) or (if (rsv2) WS_RSV2 else 0) or (if (rsv3) WS_RSV3 else 0)

/** The name of the WebSocket per-message compression extension (RFC 7692 section 7). */
private const val PERMESSAGE_DEFLATE = "permessage-deflate"

/**
 * The default of the engines' `webSocketMaxMessageSize`: 16 MiB, as `PerMessageDeflate`'s `maxInflatedMessageSize`. The
 * largest frame, and message once reassembled, a peer may send (RFC 6455 section 10.4).
 */
@InternalKuicksilverApi
public const val DEFAULT_WEBSOCKET_MAX_MESSAGE_SIZE: Long = 16L shl 20

/**
 * The WebSocket frames of [input], checked frame by frame before Ktor's session reads them; a frame that breaks a rule
 * fails the connection (RFC 6455 section 7.1.7): in place of that frame the returned channel carries a Close frame with
 * the code below and a reason, then ends. Ktor's session answers it with the same Close through its own writer (the only
 * writer of the connection), so that code is what goes on the wire and is the session's `closeReason`; its `incoming`
 * ends without the bad frame or anything after it, and every frame before it was delivered. A raw session
 * (`webSocketRaw`) sees that Close frame in `incoming` and answers it itself, as any Close.
 *
 * 1002 (protocol error): an opcode that is not defined (3-7, 11-15); an RSV bit outside [allowedRsv]; with
 * [perMessageDeflate], RSV1 on a continuation or control frame (RFC 7692 section 6.1); a mask bit that does not match
 * [peerMasks] (section 5.1: a client masks every frame, a server none); a 64-bit payload length whose most significant
 * bit is set, or a length not in its minimal encoding (section 5.2: "the minimal number of bytes MUST be used to encode
 * the length", section 10.7); a control frame with FIN clear or a payload over 125 bytes (section 5.5); a continuation
 * frame outside a fragmented message or a new message inside one (section 5.4); a Close frame whose body is 1 byte or
 * whose code an endpoint may not send ([isValidCloseCode], sections 5.5.1 and 7.4).
 *
 * 1009 (message too big, section 10.4): an uncompressed frame whose header claims more payload than [maxMessageSize], or
 * one that takes its message past it, is refused from its header, before any of its payload is read: Ktor's JVM reader
 * allocates a frame's whole claimed length at once. A compressed message is held to the smaller of [maxMessageSize] and
 * [WebSocketInflate.maxMessageSize], counted as it inflates, and its compressed frames to 8 times that limit plus 64 KiB
 * in all, from their headers.
 *
 * 1007 (invalid data, sections 5.6 and 8.1): with [checkText] ([webSocketTextCheckable]), a text message that is not
 * UTF-8 as a whole, a sequence split across fragments included; and always a Close reason that is not UTF-8. A text
 * message is checked as it streams: it is handed on unmasked, in frames of at most 64 KiB (the first with its opcode,
 * the rest continuations), and none of the bytes that broke it.
 *
 * The violations are not raised as Ktor's `ProtocolViolationException` in the reader: on its common (Kotlin/Native)
 * reader the session's `incoming` closes before its Close is queued, so an application closing at that moment sends
 * 1000 first, and ktor-io's `readAvailable` (its JVM reader) reports a cancelled channel as an ordinary end of stream.
 *
 * With [untilClose], the channel ends after the peer's Close frame: the session is over once Close frames were exchanged
 * (RFC 6455 section 7.1.1), and the peer sends no frame after its Close (section 5.5.1). Ktor's JVM WebSocket reader stops
 * at the Close frame; its common (Native) reader reads to the end of the stream, so without this a Native session would
 * wait for the peer's FIN, which may trail the Close frame or not come at all.
 *
 * With [inflate] (Kuicksilver's engines with permessage-deflate negotiated, by [PerMessageDeflate] or by Ktor's own
 * extension, RFC 7692 section 7.2.2), each message whose
 * first frame has RSV1 is decompressed as its frames arrive and handed on as plain frames (no RSV1) of at most 64 KiB
 * each, the first with the message's opcode and the rest continuations, so Ktor's session and the extension see it
 * uncompressed; uncompressed messages and control frames between the fragments pass as they are. A message that inflates
 * past its limit is cut off there with 1009 after at most 64 KiB more than the limit was handed on; malformed compressed
 * data ends it with 1002.
 *
 * A failed [input] fails the returned channel with its cause, and the end of [input] ends it. [onEnd] runs once the
 * returned channel has ended or failed for any of these reasons (with [untilClose], right after the peer's Close frame was
 * handed on), or the copy was stopped. The copy runs in [context]
 * but outside its job, so it never holds a call open (a reader that gave up leaves it waiting for room); the end of
 * [context]'s job stops it.
 *
 * @throws IllegalArgumentException when [maxMessageSize] is less than 1.
 */
@InternalKuicksilverApi
public fun guardWebSocketInput(
    input: ByteReadChannel,
    allowedRsv: Int,
    untilClose: Boolean,
    peerMasks: Boolean,
    context: CoroutineContext,
    inflate: WebSocketInflate? = null,
    perMessageDeflate: Boolean = inflate != null,
    maxMessageSize: Long = DEFAULT_WEBSOCKET_MAX_MESSAGE_SIZE,
    checkText: Boolean = true,
    onEnd: () -> Unit = {},
): ByteReadChannel {
    require(maxMessageSize >= 1) { "maxMessageSize $maxMessageSize is less than 1" }
    val out = ByteChannel()
    val job = Job()
    context[Job]?.invokeOnCompletion { job.cancel() }
    val rules = InputRules(allowedRsv, untilClose, peerMasks, perMessageDeflate, maxMessageSize, checkText)
    CoroutineScope(context + job).launch(CoroutineName("ws-frame-guard")) {
        val guard = InputGuard(input, out, rules, inflate)
        try {
            guard.run()
        } catch (_: EOFException) {
            // the stream ended (between or inside frames): so does the session's input. ktor-io's readFully answers an input
            // failed with a cause with an EOFException too: that one fails the session's input with the cause
            val cause = input.closedCause
            if (cause == null) out.flushAndClose() else out.cancel(cause)
        } catch (cause: Throwable) {
            out.cancel(cause)
        } finally {
            guard.close()
            onEnd()
        }
    }
    return out
}

/** What the handshake decided for the peer's frames ([guardWebSocketInput]'s parameters). */
private class InputRules(
    val allowedRsv: Int,
    val untilClose: Boolean,
    val peerMasks: Boolean,
    val perMessageDeflate: Boolean,
    val maxMessageSize: Long,
    val checkText: Boolean,
)

/** A frame that fails the connection with Close [code] and [reason] (RFC 6455 section 7.1.7). */
private class FrameRuleException(
    val code: Int,
    val reason: String,
) : Exception(reason)

private fun protocolError(what: String) = FrameRuleException(CLOSE_PROTOCOL_ERROR, "Received illegal frame: $what")

private fun invalidText() = FrameRuleException(CLOSE_INVALID_DATA, "Invalid UTF-8 in a text message")

/**
 * The guard of one connection's input: which message the frames belong to, whether it is compressed or checked as text,
 * and the re-framing of the data it hands on itself (inflated, or checked text) in frames of at most [INFLATE_CHUNK].
 */
private class InputGuard(
    private val input: ByteReadChannel,
    private val out: ByteChannel,
    private val rules: InputRules,
    inflate: WebSocketInflate?,
) {
    private val inflater =
        inflate?.let { MessageInflater(it.noContextTakeover, minOf(it.maxMessageSize, rules.maxMessageSize)) }
    private val header = ByteArray(MAX_HEADER)
    private val mask = ByteArray(4)
    private val control = ByteArray(MAX_CONTROL_PAYLOAD.toInt())
    private val closeBody = ByteArray(MAX_CONTROL_PAYLOAD.toInt())
    private val utf8 = Utf8Validator()
    private var inMessage = false
    private var messageOpcode = 0
    private var compressed = false
    private var text = false
    private var messageBytes = 0L
    private var emitted = false
    private var output: ByteArray? = null
    private var outputLength = 0
    private var buffer: ByteArray? = null

    /** Copies frames until the input ends, the peer's Close with [InputRules.untilClose], or a violation. */
    suspend fun run() {
        try {
            while (frame()) continue
            out.flushAndClose()
        } catch (e: FrameRuleException) {
            out.writeFully(closeFrame(e.code, e.reason))
            out.flushAndClose()
        }
    }

    fun close() {
        inflater?.close()
    }

    /** One frame; false once the peer's Close went on and the channel ends there. */
    private suspend fun frame(): Boolean {
        val b0 = input.readByte().toInt() and 0xff
        val b1 = input.readByte().toInt() and 0xff
        violation(b0, b1, rules)?.let { throw protocolError(it) }
        header[0] = b0.toByte()
        header[1] = b1.toByte()
        var n = 2
        var length = (b1 and 0x7f).toLong()
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
        val masked = b1 and 0x80 != 0
        if (masked) {
            repeat(4) {
                val b = input.readByte()
                mask[it] = b
                header[n++] = b
            }
        }
        if (length < 0) throw protocolError("a 64-bit length with its most significant bit set")
        // RFC 6455 section 5.2: "the minimal number of bytes MUST be used to encode the length"
        if ((extended == 2 && length < 126) || (extended == 8 && length <= 0xffff)) {
            throw protocolError("a payload length of $length not in its minimal encoding")
        }
        val frameMask = if (masked) mask else null
        val opcode = b0 and 0x0f
        val fin = b0 and 0x80 != 0
        if (opcode >= OPCODE_CLOSE) return control(opcode, fin, length, n, frameMask)
        data(opcode, fin, b0 and WS_RSV1 != 0, length, n, frameMask)
        return true
    }

    /** RFC 6455 section 5.5: a control frame is not fragmented and has at most 125 bytes; a Close body is checked. */
    private suspend fun control(
        opcode: Int,
        fin: Boolean,
        length: Long,
        headerLength: Int,
        mask: ByteArray?,
    ): Boolean {
        if (!fin) throw protocolError("a fragmented control frame")
        if (length > MAX_CONTROL_PAYLOAD) throw protocolError("a control frame of $length bytes")
        val size = length.toInt()
        input.readFully(control, 0, size)
        if (opcode == OPCODE_CLOSE) {
            control.copyInto(closeBody, 0, 0, size)
            if (mask != null) unmask(closeBody, size, mask, 0)
            checkCloseBody(closeBody, size)
        }
        out.writeFully(header, 0, headerLength)
        out.writeFully(control, 0, size)
        out.flush()
        return !(rules.untilClose && opcode == OPCODE_CLOSE)
    }

    /** RFC 6455 sections 5.5.1, 7.4 and 8.1: no body, or a code an endpoint may send and an optional UTF-8 reason. */
    private fun checkCloseBody(
        body: ByteArray,
        size: Int,
    ) {
        if (size == 0) return
        if (size == 1) throw protocolError("a Close frame with a 1-byte body")
        val code = ((body[0].toInt() and 0xff) shl 8) or (body[1].toInt() and 0xff)
        if (!isValidCloseCode(code)) throw protocolError("Close code $code, which an endpoint may not send")
        if (!isUtf8(body, 2, size)) throw FrameRuleException(CLOSE_INVALID_DATA, "Invalid UTF-8 in a Close reason")
    }

    private suspend fun data(
        opcode: Int,
        fin: Boolean,
        rsv1: Boolean,
        length: Long,
        headerLength: Int,
        mask: ByteArray?,
    ) {
        // RFC 6455 section 5.4: continuations follow a first fragment, and messages do not interleave
        if (opcode == OPCODE_CONTINUATION && !inMessage) throw protocolError("a continuation frame outside a fragmented message")
        if (opcode != OPCODE_CONTINUATION && inMessage) throw protocolError("a new message before the fragmented one ended")
        if (opcode != OPCODE_CONTINUATION) {
            messageOpcode = opcode
            compressed = rsv1 && inflater != null
            text = rules.checkText && opcode == OPCODE_TEXT
            messageBytes = 0
            emitted = false
            utf8.reset()
        }
        inMessage = !fin
        if (compressed) {
            // the compressed bytes of a message are bounded too (MessageInflater): a frame past that is refused from its header
            val room = inflater!!.compressedRoom
            if (length > room) {
                throw FrameRuleException(CLOSE_MESSAGE_TOO_BIG, "Message is too big: more than ${inflater.maxCompressed} compressed bytes")
            }
            return inflateFrame(length, mask, fin)
        }
        // RFC 6455 section 10.4, from the header alone: nothing of the payload is read or handed on
        if (length > rules.maxMessageSize - messageBytes) {
            throw FrameRuleException(CLOSE_MESSAGE_TOO_BIG, "Message is too big: more than ${rules.maxMessageSize} bytes")
        }
        messageBytes += length
        if (text) return textFrame(length, mask, fin)
        out.writeFully(header, 0, headerLength)
        if (length > 0 && input.copyTo(out, length) < length) {
            // ktor-io's copyTo stops on an input failed with a cause as at its end, without the cause
            input.closedCause?.let { throw it }
            throw EOFException("the stream ended inside a frame")
        }
        out.flush()
    }

    /** An uncompressed text frame: its payload checked as UTF-8 piece by piece and handed on re-framed. */
    private suspend fun textFrame(
        length: Long,
        mask: ByteArray?,
        fin: Boolean,
    ) {
        val buf = buffer()
        var left = length
        var position = 0L
        while (left > 0) {
            val n = minOf(left, buf.size.toLong()).toInt()
            input.readFully(buf, 0, n)
            if (mask != null) unmask(buf, n, mask, position)
            position += n
            left -= n
            if (!utf8.feed(buf, 0, n)) throw invalidText()
            append(buf, n)
        }
        endOfFrame(fin)
    }

    private suspend fun append(
        src: ByteArray,
        length: Int,
    ) {
        val o = output()
        var at = 0
        while (at < length) {
            val k = minOf(length - at, o.size - outputLength)
            src.copyInto(o, outputLength, at, at + k)
            outputLength += k
            at += k
            if (outputLength == o.size) emit(fin = false)
        }
    }

    /** A compressed frame: its payload (unmasked) inflated and handed on re-framed (RFC 7692 section 7.2.2). */
    private suspend fun inflateFrame(
        length: Long,
        mask: ByteArray?,
        fin: Boolean,
    ) {
        val inflater = inflater!!
        val buf = buffer()
        var left = length
        var position = 0L
        try {
            while (left > 0) {
                val n = minOf(left, buf.size.toLong()).toInt()
                input.readFully(buf, 0, n)
                if (mask != null) unmask(buf, n, mask, position)
                position += n
                left -= n
                inflater.input(buf, 0, n)
                drain(inflater)
            }
            if (fin) {
                inflater.endOfMessage()
                drain(inflater)
            }
        } catch (e: MessageTooBigException) {
            val reason =
                if (e.compressedBytes) {
                    "Message is too big: more than ${e.limit} compressed bytes"
                } else {
                    "Message is too big: more than ${e.limit} bytes inflated"
                }
            throw FrameRuleException(CLOSE_MESSAGE_TOO_BIG, reason)
        } catch (_: DeflateDataException) {
            // zlib's own message stays here: it says nothing the peer needs
            throw FrameRuleException(CLOSE_PROTOCOL_ERROR, "Invalid compressed data")
        }
        endOfFrame(fin)
        if (fin) inflater.messageDone()
    }

    private suspend fun drain(inflater: MessageInflater) {
        val o = output()
        while (true) {
            val n = inflater.read(o, outputLength, o.size - outputLength)
            if (n == 0) return
            if (text && !utf8.feed(o, outputLength, n)) throw invalidText()
            outputLength += n
            if (outputLength == o.size) emit(fin = false)
        }
    }

    /** The end of a re-framed frame: the message's last frame, or what this frame gave (the next one may be a while). */
    private suspend fun endOfFrame(fin: Boolean) {
        if (fin) {
            if (text && !utf8.complete) throw invalidText()
            emit(fin = true)
        } else if (outputLength > 0) {
            emit(fin = false)
        }
        out.flush()
    }

    private suspend fun emit(fin: Boolean) {
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

    private fun buffer(): ByteArray = buffer ?: ByteArray(INPUT_CHUNK).also { buffer = it }

    private fun output(): ByteArray = output ?: ByteArray(INFLATE_CHUNK).also { output = it }
}

/**
 * Unmasks (or masks) the first [length] bytes of [bytes], which start at [position] of the payload, with [mask]: four
 * bytes per step with the key turned to [position].
 */
internal fun unmask(
    bytes: ByteArray,
    length: Int,
    mask: ByteArray,
    position: Long,
) {
    val at = (position and 3).toInt()
    val m0 = mask[at].toInt()
    val m1 = mask[(at + 1) and 3].toInt()
    val m2 = mask[(at + 2) and 3].toInt()
    val m3 = mask[(at + 3) and 3].toInt()
    var i = 0
    val words = length and 3.inv()
    while (i < words) {
        bytes[i] = (bytes[i].toInt() xor m0).toByte()
        bytes[i + 1] = (bytes[i + 1].toInt() xor m1).toByte()
        bytes[i + 2] = (bytes[i + 2].toInt() xor m2).toByte()
        bytes[i + 3] = (bytes[i + 3].toInt() xor m3).toByte()
        i += 4
    }
    if (i < length) bytes[i] = (bytes[i].toInt() xor m0).toByte()
    if (i + 1 < length) bytes[i + 1] = (bytes[i + 1].toInt() xor m1).toByte()
    if (i + 2 < length) bytes[i + 2] = (bytes[i + 2].toInt() xor m2).toByte()
}

/**
 * Whether an endpoint may send [code] in a Close frame, and so whether one received is valid: 1000-1003 and 1007-1011
 * (RFC 6455 section 7.4.1), 1012-1014 (registered since, in the IANA WebSocket Close Code Number registry), and
 * 3000-4999 (section 7.4.2: libraries, frameworks and applications). Not 0-999 (not used), 1004 (reserved), 1005, 1006
 * and 1015 (MUST NOT be set in a Close frame), nor the rest of 1000-2999, which no specification defines.
 */
@InternalKuicksilverApi
public fun isValidCloseCode(code: Int): Boolean = code in 1000..1003 || code in 1007..1014 || code in 3000..4999

/** The longest frame header: 2 bytes, an 8-byte length and a 4-byte masking key. */
private const val MAX_HEADER = 14

/** RFC 6455 section 5.5: all control frames MUST have a payload length of 125 bytes or less. */
private const val MAX_CONTROL_PAYLOAD = 125L

/** The payload of a compressed or checked frame is read in pieces of this size. */
private const val INPUT_CHUNK = 16 * 1024

/** RFC 6455 section 7.4.1: 1009, an endpoint received a message too big for it to process. */
private const val CLOSE_MESSAGE_TOO_BIG = 1009

/** RFC 6455 section 7.4.1: 1007, data within a message that was not consistent with its type (non-UTF-8 text). */
private const val CLOSE_INVALID_DATA = 1007

/** RFC 6455 section 7.4.1: 1002, an endpoint is terminating the connection due to a protocol error. */
private const val CLOSE_PROTOCOL_ERROR = 1002

/** An unmasked Close frame with [code] and [reason] (cut to the 123 bytes a control frame leaves it, at a character). */
private fun closeFrame(
    code: Int,
    reason: String,
): ByteArray {
    var text = reason.encodeToByteArray()
    if (text.size > 123) {
        var end = 123
        while (end > 0 && text[end].toInt() and 0xC0 == 0x80) end-- // not inside a character: the reason stays UTF-8
        text = text.copyOf(end)
    }
    return byteArrayOf((0x80 or OPCODE_CLOSE).toByte(), (2 + text.size).toByte(), (code shr 8).toByte(), code.toByte()) + text
}

/** Why a frame whose first two bytes are [b0] and [b1] breaks the protocol, or null when it does not. */
private fun violation(
    b0: Int,
    b1: Int,
    rules: InputRules,
): String? {
    val opcode = b0 and 0x0f
    val rsv = b0 and WS_RSV_ALL
    val masked = b1 and 0x80 != 0
    return when {
        masked != rules.peerMasks -> {
            if (rules.peerMasks) "unmasked frame from a client" else "masked frame from a server"
        }

        opcode in 3..7 || opcode > OPCODE_PONG -> {
            "reserved opcode $opcode"
        }

        rsv and rules.allowedRsv.inv() != 0 -> {
            "RSV bits 0x${rsv.toString(16)} set without an extension that defines them"
        }

        rules.perMessageDeflate && rsv and WS_RSV1 != 0 && (opcode == OPCODE_CONTINUATION || opcode >= OPCODE_CLOSE) -> {
            "RSV1 on a ${if (opcode == OPCODE_CONTINUATION) "continuation" else "control"} frame (RFC 7692 section 6.1)"
        }

        else -> {
            null
        }
    }
}

internal const val OPCODE_CONTINUATION = 0x0
internal const val OPCODE_TEXT = 0x1
internal const val OPCODE_CLOSE = 0x8
private const val OPCODE_PONG = 0xA
