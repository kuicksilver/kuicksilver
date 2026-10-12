// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.StreamPriority
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlin.concurrent.Volatile

/**
 * One stream of the core as two ktor-io channels. The input pulls from the core only when the application
 * awaits content, so flow-control credit returns at the application's pace; the output hands bytes to the core on every
 * flush and suspends while the core's send buffer is full. No pump coroutines: every core access hops onto the loop.
 */
// ByteReadChannel/ByteWriteChannel implementations need ktor's opt-in (readBuffer/writeBuffer)
@OptIn(ExperimentalKuicksilverApi::class, io.ktor.utils.io.InternalAPI::class)
internal class StreamRuntime(
    internal val conn: ConnectionRuntime,
    internal val loop: EndpointLoop,
    override val id: Long,
    recv: Boolean,
    send: Boolean,
    initialPriority: StreamPriority = StreamPriority.Default,
) : QuicStream {
    @Volatile
    override var receivedEarly: Boolean = false
        internal set

    private val inChannel: StreamInput? = if (recv) StreamInput(this) else null
    private val outChannel: StreamOutput? = if (send) StreamOutput(this) else null
    override val input: ByteReadChannel get() = inChannel ?: throw IllegalStateException("stream $id is send-only")
    override val output: ByteWriteChannel get() = outChannel ?: throw IllegalStateException("stream $id is receive-only")
    internal val readable = Channel<Unit>(Channel.CONFLATED)
    internal val ticker = conn.newTicker()
    override var priority: StreamPriority = initialPriority
        set(v) {
            field = v
            loop.scope.launch { conn.core.setPriority(id, v) }
        }

    internal fun signalReadable() {
        readable.trySend(Unit)
    }

    internal fun finished() {
        readable.trySend(Unit)
        conn.removeTicker(ticker)
    }

    internal fun peerReset(code: Long) {
        inChannel?.closeWith(QuicException.StreamError.Reset(id, code, Initiator.Peer))
    }

    internal fun peerStopped(code: Long) {
        outChannel?.closeWith(QuicException.StreamError.Stopped(id, code, Initiator.Peer))
    }

    internal fun connectionLost(reason: QuicException.ConnectionLost) {
        inChannel?.closeWith(reason)
        outChannel?.closeWith(reason)
    }

    override fun reset(code: Long) {
        outChannel?.closeWith(QuicException.StreamError.Reset(id, code, Initiator.Local))
        loop.scope.launch {
            conn.core.resetStream(id, code)
            loop.flush(conn.core)
        }
    }

    override fun stopSending(code: Long) {
        inChannel?.closeWith(QuicException.StreamError.Stopped(id, code, Initiator.Local))
        loop.scope.launch {
            conn.core.stopSending(id, code)
            loop.flush(conn.core)
        }
    }
}
