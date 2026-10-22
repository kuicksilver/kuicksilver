// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.SocketAddress
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ReaderJob
import io.ktor.utils.io.WriterJob
import io.kuicksilver.ktor.client.EngineEvents
import io.kuicksilver.ktor.client.KuicksilverEngineConfig
import io.kuicksilver.quic.KuicksilverLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.test.TestScope
import kotlin.coroutines.CoroutineContext

/** What an in-memory HTTP/1.1 connection sends ([toServer]) and receives ([fromServer]); the test plays the server. */
internal class Wire(
    val toServer: ByteChannel = ByteChannel(),
    val fromServer: ByteChannel = ByteChannel(),
)

/** The socket under a connection whose channels the test drives; closing it ends them, as a real socket's close does. */
private class NoSocket(
    private val wire: Wire,
) : Socket {
    override val socketContext: Job = Job()
    override val coroutineContext: CoroutineContext get() = socketContext
    override val localAddress: SocketAddress = InetSocketAddress("127.0.0.1", 1)
    override val remoteAddress: SocketAddress = InetSocketAddress("127.0.0.1", 2)

    override fun attachForReading(channel: ByteChannel): WriterJob = error("not a real socket")

    override fun attachForWriting(channel: ByteChannel): ReaderJob = error("not a real socket")

    override fun close() {
        wire.toServer.cancel(null)
        wire.fromServer.cancel(null)
        socketContext.cancel()
    }
}

/**
 * One exchange of [data] through [H1Pool.execute] on [wire] (cleartext allowed), as a pooled connection when [reused];
 * the call ends when it returns.
 */
internal suspend fun TestScope.exchange(
    wire: Wire,
    data: HttpRequestData,
    reused: Boolean = false,
): HttpResponseData = exchange(wire, data, reused) { it }

/** [exchange], with the call kept open while [block] uses the response (reads its body). */
internal suspend fun <T> TestScope.exchange(
    wire: Wire,
    data: HttpRequestData,
    reused: Boolean = false,
    events: EngineEvents = EngineEvents(null, KuicksilverLogger.None),
    block: suspend (HttpResponseData) -> T,
): T {
    val selector = SelectorManager(Dispatchers.Default)
    val pool = H1Pool(KuicksilverEngineConfig(), selector, events)
    pool.cleartextPermitted = { true }
    val call = Job()
    try {
        val conn = H1Connection(NoSocket(wire), null, wire.fromServer, wire.toServer, "test")
        return block(pool.execute(data, coroutineContext + call, H1Pool.Opened(conn, reused)))
    } finally {
        call.cancel()
        selector.close()
    }
}
