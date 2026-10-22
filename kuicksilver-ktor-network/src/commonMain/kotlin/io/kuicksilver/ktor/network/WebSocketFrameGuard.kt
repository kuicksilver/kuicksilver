// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.readByte
import io.ktor.utils.io.writeByte
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.InternalKuicksilverApi
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
 * exactly [WS_RSV1] (permessage-deflate), RSV1 on a continuation or control frame (RFC 7692 section 6.1), or a mask bit
 * that does not match [peerMasks] (RFC 6455 section 5.1: a client masks every frame, a server none) fails the
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
): ByteReadChannel {
    val out = ByteChannel()
    val job = Job()
    context[Job]?.invokeOnCompletion { job.cancel() }
    CoroutineScope(context + job).launch(CoroutineName("ws-frame-guard")) {
        try {
            while (true) {
                val b0 = input.readByte()
                val b1 = input.readByte()
                violation(b0.toInt() and 0xff, b1.toInt() and 0xff, allowedRsv, peerMasks)?.let {
                    out.writeFully(closeFrame(CLOSE_PROTOCOL_ERROR, "Received illegal frame: $it"))
                    out.flushAndClose()
                    return@launch
                }
                out.writeByte(b0)
                out.writeByte(b1)
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
                        out.writeByte(b)
                        length = (length shl 8) or (b.toLong() and 0xff)
                    }
                }
                if (b1.toInt() and 0x80 != 0) repeat(4) { out.writeByte(input.readByte()) } // masking key
                if (length < 0) break // out of range: the reader rejects the header
                if (length > 0 && input.copyTo(out, length) < length) break
                out.flush()
                if (untilClose && b0.toInt() and 0x0f == OPCODE_CLOSE) break
            }
            out.flushAndClose()
        } catch (_: EOFException) {
            out.flushAndClose() // the stream ended (between or inside frames): so does the session's input, as before
        } catch (cause: Throwable) {
            out.cancel(cause)
        }
    }
    return out
}

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
