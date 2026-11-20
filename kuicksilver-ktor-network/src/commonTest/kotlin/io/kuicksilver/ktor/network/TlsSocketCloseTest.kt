// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.availableForRead
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import kotlinx.io.readString
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
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

    /**
     * A read channel opened once the close has begun, and never read, does not bring back the wait behind input nobody
     * reads: no second reader takes the session's input, which the close reads and drops, and the channel ends at once
     * with nothing in it. Before, a relay started then took the input from the close's drop and held it behind the unread
     * channel, and the close waited for the peer's `close_notify` until its bound.
     */
    @Test fun negative_aReadChannelOpenedAfterCloseGetsNothing(): Unit =
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
                    sock.close()
                    val late = sock.openReadChannel() // never read until the close is over
                    val response =
                        async {
                            runCatching {
                                val out = accepted.openWriteChannel(autoFlush = true)
                                out.writeFully(ByteArray(16 shl 20)) // more than both ends' buffers
                                out.flushAndClose()
                            }
                            accepted.close()
                        }
                    assertNotNull(
                        withTimeoutOrNull(20.seconds) { sock.rawSocket.socketContext.join() },
                        "the close waits behind a read channel opened after it",
                    )
                    var got = 0L
                    val buf = ByteArray(64 * 1024)
                    runCatching {
                        while (true) {
                            val n = late.readAvailable(buf, 0, buf.size)
                            if (n < 0) break
                            got += n
                        }
                    }
                    assertEquals(0L, got, "a read channel opened after the close got the peer's bytes")
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

    /**
     * A client that closes while a response far beyond its drop bound (64 MiB, `TlsConnection.INPUT_DROP_LIMIT` is 256 KiB)
     * is still coming does not read it to its end: past the bound the session stops reading and the close comes under the
     * rest, so the server's write fails instead of running to the end. Before the bound, the client read and dropped the
     * whole response for as long as its close waited.
     */
    @Test fun negative_aClientCloseCutsAResponseFarBeyondItsDropBound(): Unit =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            try {
                withTimeout(60.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    val client = async { connectTcp(selector, InetSocketAddress("127.0.0.1", port)).tls(clientConfig()) }
                    val accepted = server.accept().tlsServer(serverConfig())
                    val sock = client.await()
                    sock.closeTimeout = 50.seconds // far beyond the assertions: only the bound ends the drop early
                    val input = sock.openReadChannel()
                    val response =
                        async {
                            val written =
                                runCatching {
                                    val out = accepted.openWriteChannel(autoFlush = true)
                                    val piece = ByteArray(64 * 1024)
                                    repeat(1024) { out.writeFully(piece) } // 64 MiB
                                    out.flushAndClose()
                                }.isSuccess
                            accepted.close()
                            written
                        }
                    while (input.availableForRead == 0) yield() // the response is under way; the application stops reading
                    sock.close()
                    assertNotNull(
                        withTimeoutOrNull(20.seconds) { sock.rawSocket.socketContext.join() },
                        "the close still waits behind the response the application never read",
                    )
                    assertFalse(withTimeout(30.seconds) { response.await() }, "the server wrote all 64 MiB: the client read it out")
                    withTimeoutOrNull(10.seconds) { accepted.socketContext.join() }
                    server.close()
                }
            } finally {
                selector.close()
            }
        }

    /**
     * A server's close has no drop bound: a client still uploading what the server will never read (8 MiB, far beyond the
     * client's bound) while it reads the last response slowly gets that response whole and its clean end. Cutting the
     * server's reading there would close under the client's upload, and the kernel's reset would discard what of the
     * response had not reached the client (RFC 9112 section 9.6 stages a server's close for that reason); whoever accepted
     * the socket bounds its close.
     */
    @Test fun aServerCloseStillDeliversTheLastResponseToASlowUploadingClient(): Unit =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            try {
                withTimeout(60.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    val client = async { connectTcp(selector, InetSocketAddress("127.0.0.1", port)).tls(clientConfig()) }
                    val accepted = server.accept().tlsServer(serverConfig())
                    val sock = client.await()
                    val size = 4 shl 20
                    val upload =
                        launch(Dispatchers.IO) {
                            runCatching {
                                val out = sock.openWriteChannel(autoFlush = true)
                                val piece = ByteArray(64 * 1024)
                                repeat(128) { out.writeFully(piece) } // 8 MiB the server never reads
                            }
                        }
                    launch(Dispatchers.IO) {
                        runCatching {
                            val out = accepted.openWriteChannel(autoFlush = true)
                            val piece = ByteArray(64 * 1024)
                            repeat(size / piece.size) { out.writeFully(piece) }
                            out.flushAndClose() // its close_notify
                        }
                        accepted.close() // the whole socket: what the client still uploads is dropped
                    }
                    val input = sock.openReadChannel()
                    val buf = ByteArray(64 * 1024)
                    var got = 0L
                    val end =
                        runCatching {
                            while (true) {
                                val n = input.readAvailable(buf, 0, buf.size)
                                if (n < 0) break
                                got += n
                                delay(2.milliseconds) // a slow reader
                            }
                        }
                    assertTrue(end.isSuccess, "the response ended with ${end.exceptionOrNull()} after $got bytes, not cleanly")
                    assertEquals(size.toLong(), got, "the client got the whole last response")
                    upload.cancel()
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
