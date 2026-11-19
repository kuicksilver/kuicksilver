// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.discard
import io.ktor.utils.io.readFully
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.seconds

/**
 * A socket closed or aborted while its selector has nothing to wait for is really closed: the peer sees the reset of an
 * abort or the end of a close, and a write to a closed socket is refused. Each
 * socket under test is on a selector of its own that has no other socket, so that selector waits idle when the socket
 * closes. Before, on the JVM, the JDK kept the descriptor of a channel still registered with that selector until it
 * selected again, which an idle ktor selector never did: the aborted connection sent no reset, the closed one kept its
 * descriptor.
 */
class IdleSelectorCloseTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A socket that never read nor wrote: its selector never had an interest. */
    @Test fun negative_abortOfAnIdleSocketResetsThePeer() = abortResetsThePeer(Writer.None)

    /**
     * A socket whose writer sent what it had and waits for more, aborted: its selector waits for nothing, and the abort
     * goes through the writer's cancellation ([KslNioSocket]'s closeDescriptor), not the plain close of the case above.
     * The peer reads what was sent first, so the writer is idle when the abort comes.
     */
    @Test fun negative_abortOfASocketWithAnIdleWriterResetsThePeer() = abortResetsThePeer(Writer.Idle)

    /**
     * A writer held by a peer that does not read, aborted 2 s after it got stuck. Whether its selector still selects
     * then depends on timing: without the release it hung 1 of 4 times here (the client's socket stayed ESTABLISHED), so
     * this case guards rather than shows the bug.
     */
    @Test fun negative_abortOfABlockedWriterResetsThePeer() = abortResetsThePeer(Writer.Blocked)

    private enum class Writer { None, Idle, Blocked }

    private fun abortResetsThePeer(writer: Writer) =
        idleSelectorTest { server, clientSelector ->
            val client = connectTcp(clientSelector, InetSocketAddress("127.0.0.1", server.port()))
            val peer = server.accept()
            val input = peer.openReadChannel()
            if (writer == Writer.Idle) {
                val out = client.openWriteChannel()
                out.writeFully(ByteArray(1000))
                out.flush()
                val got = ByteArray(1000)
                withTimeout(10.seconds) { input.readFully(got) } // the writer sent it all: it waits on its channel
                client.abort()
            } else if (writer == Writer.Blocked) {
                val out = client.openWriteChannel()
                // until the writer is stuck on a full connection (the peer reads nothing)
                val writing = fillUntilStuck(out) { kernelBufferBytes(client, peer) }
                kotlinx.coroutines.delay(2.seconds) // the scenario, not a synchronization: the selector goes idle
                client.abort()
                writing.await()
            } else {
                client.abort()
            }
            // the peer reads what reached it, then the reset: never a clean end, never a wait for ever. It writes a byte
            // every 100 ms meanwhile: macOS ignores a reset that reaches a socket whose receive window is 0 (a capture on
            // lo0 shows the client's reset on the wire and the peer staying ESTABLISHED; the same reset sent again in
            // answer to the peer's next segment is taken), and a segment to a connection that is gone is always answered
            // with one. To a descriptor still open the bytes are only taken: the client has no read interest, so they do
            // not wake its selector either
            val probeOut = peer.openWriteChannel()
            val probe =
                launch {
                    runCatching {
                        while (true) {
                            probeOut.writeFully(byteArrayOf(0))
                            probeOut.flush()
                            kotlinx.coroutines.delay(100)
                        }
                    }
                }
            val ended = withTimeoutOrNull(10.seconds) { runCatching { input.discard() } }
            probe.cancel()
            assertNotNull(ended, "no reset and no end 10 s after the abort: the descriptor was not closed")
            assertNotNull(input.closedCause, "the stream ended cleanly: an abort resets the connection")
            peer.close()
        }

    /**
     * A socket closed in order on an idle selector: the peer reads the end, and its writes after that are refused (the
     * client's descriptor is gone, its kernel answers them with a reset), instead of being taken by a socket nobody holds.
     */
    @Test fun negative_closeOfAnIdleSocketReleasesTheDescriptor() =
        idleSelectorTest { server, clientSelector ->
            val client = connectTcp(clientSelector, InetSocketAddress("127.0.0.1", server.port()))
            val peer = server.accept()
            val input = peer.openReadChannel()
            client.close()
            assertEquals(0L, withTimeout(10.seconds) { input.discard() }, "the peer reads the end")
            val out = peer.openWriteChannel()
            val refused =
                withTimeoutOrNull(10.seconds) {
                    runCatching {
                        while (true) {
                            out.writeFully(ByteArray(1024))
                            out.flush()
                        }
                    }.exceptionOrNull()
                }
            assertNotNull(refused, "writes to the closed socket were still taken 10 s later: its descriptor stayed open")
            peer.close()
        }

    private fun io.ktor.network.sockets.ServerSocket.port() = (localAddress as InetSocketAddress).port

    private fun idleSelectorTest(
        block: suspend kotlinx.coroutines.CoroutineScope.(
            server: io.ktor.network.sockets.ServerSocket,
            clientSelector: SelectorManager,
        ) -> Unit,
    ) = runBlocking {
        val selector = SelectorManager(Dispatchers.IO)
        val clientSelector = SelectorManager(Dispatchers.IO) // the client's alone: idle once it waits for nothing
        try {
            withTimeout(60.seconds) {
                val server = bindTcp(selector, "127.0.0.1", 0)
                try {
                    block(server, clientSelector)
                } finally {
                    server.close()
                }
            }
        } finally {
            selector.close()
            clientSelector.close()
        }
    }
}
