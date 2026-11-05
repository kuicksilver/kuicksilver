// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.discard
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The Native TCP socket's close keeps its order: the write loop drains what the application wrote, and only then is the
 * read loop cancelled (its end shuts the read side down, TCP_SHUT_RD on POSIX) and the descriptor closed. Cancelling the
 * read loop while the write loop still drains lets the kernel drop the response's tail: on Linux a close with unread
 * received data (a pipelined request after `Connection: close`) sends a reset instead of the rest.
 */
class NativeCloseOrderTest {
    @Test fun closeEndsTheReadLoopOnlyAfterTheWriteLoopDrained() =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            val server = bindTcp(selector, "127.0.0.1", 0)
            try {
                val accepted = async { server.accept() }
                val socket = connectTcp(selector, InetSocketAddress("127.0.0.1", (server.localAddress as InetSocketAddress).port))
                val native = socket as NativeTcpSocket
                val input = socket.openReadChannel() // the read loop runs; nothing here reads it
                val peer = withTimeout(10.seconds) { accepted.await() }
                val peerOut = peer.openWriteChannel(autoFlush = true)
                peerOut.writeFully("pipelined, never read".encodeToByteArray()) // unread received data
                val out = socket.openWriteChannel(autoFlush = true)
                // more than the kernel's buffers on both ends can hold (Linux tcp_wmem up to 4 MiB, plus the receive side)
                val size = 32 shl 20
                // UNDISPATCHED: the write hands over all its bytes before it waits for room (the peer does not read yet)
                launch(start = CoroutineStart.UNDISPATCHED) { runCatching { out.writeFully(ByteArray(size)) } }
                socket.close()
                withTimeout(10.seconds) { while (!out.isClosedForWrite) yield() }
                repeat(200) { yield() }
                assertTrue(!native.writeLoopEnded, "the write loop still drains: the peer has read nothing")
                assertTrue(!native.readLoopEnded, "so the read loop is still running")
                val read = withTimeout(60.seconds) { peer.openReadChannel().discard() }
                assertEquals(size.toLong(), read, "every byte the application wrote, then the end of the stream")
                withTimeout(10.seconds) { socket.socketContext.join() }
                assertTrue(native.writeLoopEnded && native.readLoopEnded)
                input.cancel(null)
                peer.close()
            } finally {
                server.close()
                selector.close()
            }
        }
}
