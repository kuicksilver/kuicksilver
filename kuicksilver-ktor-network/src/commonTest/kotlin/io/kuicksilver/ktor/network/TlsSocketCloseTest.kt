// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.availableForRead
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import kotlinx.io.readString
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.seconds

/**
 * What a TLS socket's close waits for. A close of the whole socket still waits for the peer's `close_notify`, as a client
 * of a WebSocket or an HTTP server should, but no longer behind data the application will never read: the session reads
 * and drops it, so the peer's end gets through. Closing only the write side (a half-close) still delivers what the peer
 * sends after it.
 */
class TlsSocketCloseTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * The client closes while a response it never read is still coming (more than every buffer on the way holds), and the
     * server closes once it wrote the response. Before, the session waited for room in the application's channel, the
     * server's write waited for the client to read, and the close waited for the server's `close_notify` until its bound.
     */
    @Test fun negative_aCloseDoesNotWaitBehindAResponseTheApplicationNeverReads(): Unit =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            try {
                withTimeout(60.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    val client = async { connectTcp(selector, InetSocketAddress("127.0.0.1", port)).tls(clientConfig()) }
                    val accepted = server.accept().tlsServer(serverConfig())
                    val sock = client.await()
                    sock.closeTimeout = 50.seconds // the bound of the old wait, far beyond the assertion's
                    val input = sock.openReadChannel()
                    val response =
                        async {
                            runCatching {
                                val out = accepted.openWriteChannel(autoFlush = true)
                                out.writeFully(ByteArray(16 shl 20)) // more than both ends' buffers
                                out.flushAndClose()
                            }
                            accepted.close() // its close_notify, once the client took the response
                        }
                    while (input.availableForRead == 0) yield() // the response is under way; the application stops reading
                    sock.close()
                    assertNotNull(
                        withTimeoutOrNull(20.seconds) { sock.rawSocket.socketContext.join() },
                        "the close still waits behind the response the application never read",
                    )
                    response.await()
                    withTimeoutOrNull(10.seconds) { accepted.socketContext.join() }
                    server.close()
                }
            } finally {
                selector.close()
            }
        }

    /** A half-close: the client ends its request (its write side, `close_notify`) and still reads the whole response. */
    @Test fun aHalfCloseStillDeliversWhatThePeerSendsAfterIt(): Unit =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            try {
                withTimeout(30.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    val client = async { connectTcp(selector, InetSocketAddress("127.0.0.1", port)).tls(clientConfig()) }
                    val accepted = server.accept().tlsServer(serverConfig())
                    val sock = client.await()
                    val served =
                        async {
                            val request = accepted.openReadChannel().readBuffer().readString() // to the client's end
                            val out = accepted.openWriteChannel(autoFlush = true)
                            out.writeStringUtf8("answer to $request")
                            out.flushAndClose()
                            accepted.close()
                        }
                    val out = sock.openWriteChannel(autoFlush = true)
                    out.writeStringUtf8("question")
                    out.flushAndClose() // the write side only
                    assertEquals("answer to question", sock.openReadChannel().readBuffer().readString())
                    served.await()
                    sock.close()
                    withTimeoutOrNull(10.seconds) { sock.rawSocket.socketContext.join() }
                    withTimeoutOrNull(10.seconds) { accepted.socketContext.join() }
                    server.close()
                }
            } finally {
                selector.close()
            }
        }
}
