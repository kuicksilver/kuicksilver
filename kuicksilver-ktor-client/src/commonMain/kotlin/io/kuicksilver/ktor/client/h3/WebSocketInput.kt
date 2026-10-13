// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h3

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.readByte
import io.ktor.utils.io.writeByte
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.io.EOFException
import kotlin.coroutines.CoroutineContext

/**
 * The WebSocket frames of [stream] up to and including the peer's Close frame, then the end of the channel: the session is
 * over once Close frames were exchanged (RFC 6455 section 7.1.1 lets the client close after sending and receiving one), and
 * the peer sends no frame after its Close (section 5.5.1). Ktor's JVM WebSocket reader stops at the Close frame; its common
 * (Native) reader reads to the end of the stream, so without this a Native session would wait for the peer's FIN, which may
 * trail the Close frame or not come at all. Bytes are passed through unchanged, frame by frame; a failed [stream] fails the
 * returned channel with its cause, and the end of [stream] ends it. The copy runs in [callContext] but outside its job, so
 * it never holds the call open (a reader that gave up, e.g. on a frame over its limit, leaves it waiting for room); the
 * call's end stops it.
 */
internal fun webSocketInputUntilClose(
    stream: ByteReadChannel,
    callContext: CoroutineContext,
): ByteReadChannel {
    val out = ByteChannel()
    val job = Job()
    callContext[Job]?.invokeOnCompletion { job.cancel() }
    CoroutineScope(callContext + job).launch(CoroutineName("h3-ws-input")) {
        try {
            while (true) {
                val b0 = stream.readByte()
                val b1 = stream.readByte()
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
                        val b = stream.readByte()
                        out.writeByte(b)
                        length = (length shl 8) or (b.toLong() and 0xff)
                    }
                }
                if (b1.toInt() and 0x80 != 0) repeat(4) { out.writeByte(stream.readByte()) } // masking key
                if (length < 0) break // out of range: the reader rejects the header
                if (length > 0 && stream.copyTo(out, length) < length) break
                out.flush()
                if (b0.toInt() and 0x0f == OPCODE_CLOSE) break
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

private const val OPCODE_CLOSE = 0x8
