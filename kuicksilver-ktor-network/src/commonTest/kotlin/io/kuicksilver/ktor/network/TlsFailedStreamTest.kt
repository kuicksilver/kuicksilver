// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.close
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.io.IOException
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.seconds

/**
 * A TLS server socket whose application stream fails mid-response (a handler that threw) ends the connection with a
 * reset and no `close_notify`, so a client reading to the end gets an error. Before, the TLS socket's close sent
 * `close_notify` and a FIN, and the client saw a clean end of a cut stream: for a body delimited by the connection's
 * close, the cut one passed for the whole. A stream that ends normally still closes with `close_notify` and a FIN.
 */
class TlsFailedStreamTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun negative_aFailedTlsStreamResetsTheConnection() {
        val seen = exchange(fail = true)
        assertNull(seen, "the client of a failed TLS stream saw $seen, not an error")
    }

    @Test fun aCompleteTlsStreamEndsCleanly() {
        assertEquals("a clean end after ${64 shl 10} bytes", exchange(fail = false))
    }

    /** What the client saw reading to the end: "a clean end after N bytes", or null when the read failed. */
    private fun exchange(fail: Boolean): String? =
        runBlocking {
            val selector = SelectorManager(Dispatchers.Default)
            try {
                withTimeout(30.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    val client =
                        async {
                            // the engines' own socket: a write to a reset connection fails instead of raising SIGPIPE
                            val sock = connectTcp(selector, InetSocketAddress("127.0.0.1", port)).tls(clientConfig())
                            val input = sock.openReadChannel()
                            val buf = ByteArray(8192)
                            var got = 0L
                            try {
                                while (true) {
                                    val n = input.readAvailable(buf, 0, buf.size)
                                    if (n < 0) break
                                    got += n
                                }
                                "a clean end after $got bytes"
                            } catch (e: Exception) {
                                if (e is CancellationException) throw e
                                null
                            } finally {
                                sock.close()
                            }
                        }
                    val sock = server.accept().tlsServer(serverConfig())
                    val out = sock.openWriteChannel()
                    out.writeFully(ByteArray(64 shl 10))
                    out.flush()
                    if (fail) out.close(IOException("the handler failed")) else out.flushAndClose()
                    sock.close()
                    val seen = client.await()
                    server.close()
                    seen
                }
            } finally {
                selector.close()
            }
        }
}
