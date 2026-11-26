// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * The Pongs of one WebSocket connection, sent by the engine itself, between the frame guards of its input
 * ([guardWebSocketInput]) and its output ([guardWebSocketOutput]): one instance given to both.
 *
 * RFC 6455 section 5.5.2: "Upon receipt of a Ping frame, an endpoint MUST send a Pong frame in response, unless it already
 * received a Close frame. It SHOULD respond with Pong frame as soon as is practical." Ktor's `DefaultWebSocketSession`
 * answers a Ping from a coroutine of its own (its "ponger"), which runs whenever its dispatcher gets to it: the
 * application's next frames, an echo of the message the Ping came in the middle of included (section 5.4: control frames
 * "MAY be injected in the middle of a fragmented message"), could go out before it; a raw session answers none. Here the
 * input guard hands each Ping's Application data to [answer] as soon as it has read the Ping, before it hands the Ping on;
 * the Pong, with "identical Application data" (section 5.5.3), goes out at the output's next frame boundary: at once when
 * the output is idle (a coroutine of its own writes it), or right after the frame the session is writing. Pings are
 * answered after this side's Close too, until the peer's (section 5.5.1 forbids only data frames after a Close): when the
 * session's writer ends its channel right after its Close, as Ktor's does, the transport end is held open for Pongs
 * ([holdEnd]) until the peer's Close is read, the input ends or [closeWait] passes; see [guardWebSocketOutput].
 *
 * The Pong the session then writes for the same Ping is dropped by the output guard (one dropped per Ping answered here,
 * matched by its data), so the peer gets one Pong per Ping, as before. The engine cannot tell Ktor's default session from
 * a raw one (both write to the same channel), so under a raw session too a Pong whose data equals that of a Ping answered
 * here, and not yet matched, is taken for the application's answer to that Ping and dropped: the peer has its Pong
 * already. An unsolicited Pong with other data (section 5.5.3: "A Pong frame MAY be sent unsolicited") passes; one with
 * the same data as such a Ping (a heartbeat with the empty data of an empty Ping, say) is dropped once per such Ping.
 *
 * Bounds. At most [MAX_WAITING] Pings wait to be answered: when one more comes, only the newest is kept (section 5.5.3:
 * an endpoint that "has not yet sent Pong frame(s) in response to previous Ping frame(s) ... MAY elect to send a Pong
 * frame for only the most recently processed Ping frame"), and the older ones are no longer owed, so the session's Pongs
 * for them pass. At most [MAX_OWED] answered Pings wait for the session's Pong (a raw session may never send one); past
 * that the oldest is forgotten, and a late session Pong for it goes out as an unsolicited one. No Pong goes out after a
 * failure of the output; the input guard answers no Ping that follows the peer's Close. A write of a Pong that fails
 * (the transport reset while it waited for room) ends the writing of Pongs quietly: the output's own writer reports the
 * failure, and an exception from here would reach the uncaught-exception handler, which ends the process on Android and
 * Kotlin/Native.
 */
@InternalKuicksilverApi
public class WebSocketPongs(
    private val closeWait: Duration = DEFAULT_CLOSE_WAIT,
) {
    /** Taken by the output guard around everything it writes, and by the writer of Pongs. */
    internal val lock = Mutex()

    /**
     * The data of the Pings read and not yet taken under [lock]; never suspends the input guard. One more than
     * [MAX_WAITING], so that a burst past the bound is seen as one; a Ping dropped here was never owed (the session answers it).
     */
    private val requests = Channel<ByteArray>(MAX_WAITING + 1, BufferOverflow.DROP_OLDEST)
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

    /** The peer's Close was read, or the input ended: no Ping is answered any more, and a held transport end may go. */
    private val peerDone = CompletableDeferred<Unit>()

    /** Whether the peer's Close was read or the input ended. */
    internal val peerFinished: Boolean get() = peerDone.isCompleted

    @kotlin.concurrent.Volatile private var scope: CoroutineScope? = null

    /**
     * The peer's Close was read, or its input ended in order (its FIN, END_STREAM or FIN of the stream): the peer is done,
     * and a held end goes in order. Never set by a cancellation or a failure of the input ([stop] alone).
     */
    @kotlin.concurrent.Volatile private var peerEndedInOrder = false

    /** The input guard read the peer's Close: from here the transport end the output guard holds may go, in order. */
    internal fun peerClosed() {
        peerEndedInOrder = true
        peerDone.complete(Unit)
    }

    /** The input ended in order (no cause): as [peerClosed] for the held end. */
    internal fun inputEnded() {
        peerEndedInOrder = true
        peerDone.complete(Unit)
    }

    /**
     * The writer ended the output guard's channel after this side's Close, before the peer's Close: the transport stays
     * open for Pongs until the peer's Close is read, the input ends, or [closeWait] passes (RFC 6455 section 5.5.2: Pongs
     * are owed "unless it already received a Close frame"; section 5.5.1: the transport is closed "after both sending and
     * receiving a Close message"), then [OutputPongs.endHeld] ends it in order. An input that stopped otherwise (it
     * failed, or the engine stopped the input guard) and the engine's own end of the session (the guard's job cancelled)
     * end the wait too, and then the held end is ended in order only when the peer's Close was read or its input ended in
     * order before (`peerEndedInOrder`, never set by a cancellation): the engine ends the transport cleanly next and looks
     * at that end. Otherwise the end is only marked ended and the engine ends or resets the transport itself. Whatever
     * happens, also when a bound fires while the end waits for the lock, the held end is marked ended
     * ([OutputPongs.markEnded]) once this coroutine is over, so a wait for it ([awaitWebSocketOutputEnd]) always ends.
     * False when there is no scope to wait in (the input guard never started): the caller ends the transport at once.
     */
    @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class) // ATOMIC: the held end is ended also when the job was cancelled first
    internal fun holdEnd(guard: OutputPongs): Boolean {
        val s = scope ?: return false
        s.launch(CoroutineName("ws-held-end"), start = CoroutineStart.ATOMIC) {
            var ended = false
            try {
                // the peer's Close, its end in order, or the close wait passing end the hold in order; an input stopped
                // otherwise ends it too, and then in order only if the peer had ended in order before
                val waited = withTimeoutOrNull(closeWait) { peerDone.await() }
                val inOrder = waited == null || peerEndedInOrder
                // bounded too, its wait for the lock included (a writer stuck on a full output holds it): the end path waits
                // two close waits at most; markEnded below covers an end the bound cut
                withTimeoutOrNull(closeWait) { lock.withLock { guard.endHeld(this@WebSocketPongs, close = inOrder) } }
                ended = true
            } finally {
                try {
                    if (!ended) {
                        // cancelled (the engine ended the session): in order only after the peer's Close or its end in order,
                        // within one close wait (a peer that reads nothing more cannot keep it); a cancellation alone never is
                        val inOrder = peerEndedInOrder
                        withContext(NonCancellable) {
                            withTimeoutOrNull(closeWait) { lock.withLock { guard.endHeld(this@WebSocketPongs, close = inOrder) } }
                        }
                    }
                } finally {
                    guard.markEnded() // whatever happened above, a bound that fired while waiting for the lock included
                }
            }
        }
        return true
    }

    /** Writes the waiting Pongs while the output is idle, until [stop]; runs in [scope] (the input guard's). */
    internal fun start(scope: CoroutineScope) {
        this.scope = scope
        scope.launch {
            for (w in wake) {
                try {
                    lock.withLock { output?.sendWaiting(this@WebSocketPongs, flush = true) }
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Throwable) {
                    // the output failed (a reset transport): its writer sees the failure; nothing more is sent from here
                    lock.withLock { dropWaiting() }
                    wake.close()
                    return@launch
                }
            }
        }
    }

    internal fun stop() {
        peerDone.complete(Unit)
        wake.close()
    }

    /**
     * Under [lock]: the Pings read since the last call, now waiting and owed. When [MAX_WAITING] are waiting already, only
     * the newest is kept and the others are no longer owed (section 5.5.3), so the session's Pongs answer them.
     */
    internal fun takeRequests() {
        while (true) {
            val data = requests.tryReceive().getOrNull() ?: return
            if (waiting.size == MAX_WAITING) {
                for (old in waiting) owed.removeAt(owed.indexOfFirst { it === old }.takeIf { it >= 0 } ?: continue)
                waiting.clear()
            }
            waiting.addLast(data)
            if (owed.size == MAX_OWED) owed.removeFirst()
            owed.addLast(data)
        }
    }

    /** Under [lock]: the next Pong to send, or null. */
    internal fun nextWaiting(): ByteArray? = waiting.removeFirstOrNull()

    /** Under [lock]: the waiting Pongs are not sent (the output failed, or its writer ended it). */
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

        /**
         * How long a transport end held for Pongs waits for the peer's Close: the engines' own close wait (the client's
         * `webSocketCloseWaitMillis`, 5 s by default; the server's wait for the client's end, 5 s).
         */
        val DEFAULT_CLOSE_WAIT: Duration = 5.seconds
    }
}

/** The output guard's side of [WebSocketPongs]. */
internal interface OutputPongs {
    /** Under the lock: sends the waiting Pongs if no frame is part-way on the output, and flushes them with [flush]. */
    suspend fun sendWaiting(
        pongs: WebSocketPongs,
        flush: Boolean,
    )

    /**
     * Under the lock: ends the transport end held for Pongs ([WebSocketPongs.holdEnd]): with [close], the waiting Pongs go
     * out and the transport is ended in order; without, it is only marked ended (the engine ends it). Once only.
     */
    suspend fun endHeld(
        pongs: WebSocketPongs,
        close: Boolean,
    )

    /**
     * Without the lock: the held end is over, whether [endHeld] ran or not (a bound fired while it waited for the lock): no
     * Pong is sent any more, and a wait for the end ([awaitWebSocketOutputEnd]) is over.
     */
    fun markEnded()
}
