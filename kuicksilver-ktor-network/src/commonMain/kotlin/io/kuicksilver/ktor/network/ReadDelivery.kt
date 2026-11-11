// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openReadChannel
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.ClosedByteChannelException
import io.ktor.utils.io.InternalAPI
import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * Opens this socket's read channel so that a failure of the connection reaches the reader only after every byte received
 * before it: the bytes stay readable, and the read past them fails with the failure, never ends cleanly.
 *
 * ktor-io's `ByteChannel` drops what it holds when it is cancelled (`readBuffer` throws as soon as a cause is set), and
 * ktor's `openReadChannel` hands out such a channel: a response the peer sent completely before resetting the connection
 * (a 413 or 401 to an upload the server stopped reading, which its close over unread data answers with a reset, RFC 9112
 * section 9.6) was lost when the reader had not taken it yet. The engines read through this. On sockets of this module
 * (TCP on every platform, [TlsSocket]); on any other socket it is `openReadChannel`.
 */
@InternalKuicksilverApi
public fun Socket.openDeliveringReadChannel(): ByteReadChannel {
    val delivery = readDelivery() ?: return openReadChannel()
    val inner = ByteChannel(false)
    val view = DeliveringReadChannel(inner)
    // registered before the attach, so the read loop never fails the channel past it; one view a socket, and none left
    // behind by an attach that failed (a second read channel, a closed socket)
    check(delivery.register(view)) { "reading channel has already been set" }
    try {
        attachForReading(inner)
    } catch (e: Throwable) {
        delivery.unregister(view)
        throw e
    }
    return view
}

/** The [ReadDelivery] of a socket of this module, or null. */
internal fun Socket.readDelivery(): ReadDelivery? = if (this is TlsSocket) readDelivery else tcpReadDelivery()

/** The [ReadDelivery] of a platform TCP socket of this module, or null for any other socket. */
internal expect fun Socket.tcpReadDelivery(): ReadDelivery?

/**
 * How a socket's read loop fails its read channel: through the [DeliveringReadChannel] that [openDeliveringReadChannel]
 * put in front of it, after its buffered bytes; any other channel is cancelled, as ktor's sockets do. Called by the loop
 * that writes into the channel, on its own coroutine (the channel's writer is single).
 */
@OptIn(ExperimentalAtomicApi::class)
internal class ReadDelivery {
    private val registered = AtomicReference<DeliveringReadChannel?>(null)

    private val view: DeliveringReadChannel? get() = registered.load()

    /** Registers [view]; false when one is registered already (a socket has one read channel). */
    fun register(view: DeliveringReadChannel): Boolean = registered.compareAndSet(null, view)

    /** Takes back [view], whose channel was not attached. */
    fun unregister(view: DeliveringReadChannel) {
        registered.compareAndSet(view, null)
    }

    /** Whether [channel] is the inner channel of a [DeliveringReadChannel]: its failure goes through [fail] alone. */
    fun delivers(channel: Any): Boolean = view?.inner === channel

    /** Fails [channel] with [cause]: after its buffered bytes when it [delivers], else at once. Never suspends. */
    fun fail(
        channel: ByteWriteChannel,
        cause: Throwable,
    ) {
        val v = view
        if (v != null && v.inner === channel) v.failAfterBuffered(cause) else channel.cancel(cause)
    }
}

/**
 * [inner] as the socket's read loop fills it, failing with a recorded failure only once what [inner] already holds was
 * read (as `TlsConnection`'s input does). A failure is never a clean end: `isClosedForRead` stays false and every read
 * past the delivered bytes throws it, as a cancelled channel's reads do (ClosedByteChannelException with the failure as
 * its cause).
 */
@OptIn(InternalAPI::class)
internal class DeliveringReadChannel(
    internal val inner: ByteChannel,
) : ByteReadChannel {
    @Volatile private var failure: Throwable? = null

    /**
     * Records [cause] and closes [inner] cleanly without waiting (its writer's own coroutine calls this): its bytes stay
     * readable, then reads fail with [cause]. An [inner] the reader cancelled already keeps its own cause.
     */
    fun failAfterBuffered(cause: Throwable) {
        if (failure == null) failure = cause as? ClosedByteChannelException ?: ClosedByteChannelException(cause)
        inner.close()
    }

    override val closedCause: Throwable? get() = failure ?: inner.closedCause

    // in this order: the failure is recorded before inner closes, so a failure between the two reads is never a clean end
    override val isClosedForRead: Boolean get() = inner.isClosedForRead && failure == null

    override val readBuffer: kotlinx.io.Source get() {
        val f = failure
        if (f != null && inner.isClosedForRead) throw f
        return inner.readBuffer
    }

    override suspend fun awaitContent(min: Int): Boolean {
        val enough = inner.awaitContent(min)
        if (!enough) failure?.let { throw it }
        return enough
    }

    override fun cancel(cause: Throwable?) {
        inner.cancel(cause)
    }
}
