// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The Pongs of one WebSocket connection, sent by the engine itself, between the frame guards of its input
 * ([guardWebSocketInput]) and its output ([guardWebSocketOutput]): one instance given to both.
 *
 * RFC 6455 section 5.5.2: "Upon receipt of a Ping frame, an endpoint MUST send a Pong frame in response, unless it already
 * received a Close frame. It SHOULD respond with Pong frame as soon as is practical." Ktor's `DefaultWebSocketSession`
 * answers a Ping from a coroutine of its own (its "ponger"), which runs whenever its dispatcher gets to it: the
 * application's next frames, an echo of the message the Ping came in the middle of included (section 5.4: control frames
 * "MAY be injected in the middle of a fragmented message"), could go out before it. Here the input guard hands each
 * Ping's Application data to [answer] as soon as it has read the Ping, before it hands the Ping on; the Pong, with
 * "identical Application data" (section 5.5.3), goes out at the output's next frame boundary: at once when the output is
 * idle (a coroutine of its own writes it), or right after the frame the session is writing. The Pong the session then
 * writes for the same Ping is dropped by the output guard (one dropped per Ping answered here, matched by its data), so
 * the peer gets one Pong per Ping, as before. A Pong the application sends unsolicited (section 5.5.3) passes, unless its
 * data equals that of a Ping answered here whose session Pong has not come yet.
 *
 * Bounds: at most [MAX_WAITING] Pings wait to be answered; an older one is dropped for a newer (section 5.5.3: an endpoint
 * that "has not yet sent Pong frame(s) in response to previous Ping frame(s) ... MAY elect to send a Pong frame for only
 * the most recently processed Ping frame"); the session's Pong for a dropped one is not dropped, so it is still answered.
 * At most [MAX_OWED] answered Pings wait for the session's Pong (a raw session may never send one); past that the oldest
 * is forgotten, and a late session Pong for it goes out as an unsolicited one. No Pong goes out after this side's Close
 * (section 5.5.1) or after a refusal ended the output; the input guard answers no Ping that follows the peer's Close.
 */
@InternalKuicksilverApi
public class WebSocketPongs {
    /** Taken by the output guard around everything it writes, and by the writer of Pongs. */
    internal val lock = Mutex()

    /** The data of the Pings read and not yet taken under [lock]; never suspends the input guard. */
    private val requests = Channel<ByteArray>(MAX_WAITING, BufferOverflow.DROP_OLDEST)
    private val wake = Channel<Unit>(Channel.CONFLATED)

    // under [lock]
    private val waiting = ArrayDeque<ByteArray>()
    private val owed = ArrayDeque<ByteArray>()

    @kotlin.concurrent.Volatile private var output: OutputPongs? = null

    /** The output guard of the connection, once it exists (a server makes it after the input guard). */
    internal fun attach(guard: OutputPongs) {
        output = guard
        wake.trySend(Unit)
    }

    /** The input guard read a Ping with [data] (unmasked): it is answered at the output's next frame boundary. */
    internal fun answer(data: ByteArray) {
        requests.trySend(data)
        wake.trySend(Unit)
    }

    /** Writes the waiting Pongs while the output is idle, until [stop]; runs in [scope] (the input guard's). */
    internal fun start(scope: CoroutineScope) {
        scope.launch {
            for (w in wake) lock.withLock { output?.sendWaiting(this@WebSocketPongs, flush = true) }
        }
    }

    internal fun stop() {
        wake.close()
    }

    /** Under [lock]: the Pings read since the last call, now waiting and owed. */
    internal fun takeRequests() {
        while (true) {
            val data = requests.tryReceive().getOrNull() ?: return
            if (waiting.size == MAX_WAITING) waiting.removeFirst()
            waiting.addLast(data)
            if (owed.size == MAX_OWED) owed.removeFirst()
            owed.addLast(data)
        }
    }

    /** Under [lock]: the next Pong to send, or null. */
    internal fun nextWaiting(): ByteArray? = waiting.removeFirstOrNull()

    /** Under [lock]: no Pong is sent any more (this side's Close went out, or the output failed). */
    internal fun dropWaiting() {
        waiting.clear()
    }

    /** Under [lock]: whether a Pong of the session with [data] answers a Ping already answered here (and is dropped). */
    internal fun owedTo(
        data: ByteArray,
        size: Int,
    ): Boolean {
        val i = owed.indexOfFirst { it.size == size && (0 until size).all { k -> it[k] == data[k] } }
        if (i < 0) return false
        owed.removeAt(i)
        return true
    }

    internal companion object {
        const val MAX_WAITING = 16
        const val MAX_OWED = 64
    }
}

/** The output guard's side of [WebSocketPongs]. */
internal interface OutputPongs {
    /** Under the lock: sends the waiting Pongs if no frame is part-way on the output, and flushes them with [flush]. */
    suspend fun sendWaiting(
        pongs: WebSocketPongs,
        flush: Boolean,
    )
}
