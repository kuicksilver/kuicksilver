// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.availableForRead
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.seconds

/**
 * A TLS socket that ends, closed or aborted, ends its job too, whatever the application does with its channels.
 *
 * An aborted TLS socket ends, its job included, also while the application keeps its write channel open without writing
 * (a server handler aborting a peer that does not read). The application's write pump is a child of the raw socket's job
 * and waited for the application's next bytes: the descriptor was closed, but the socket's job stayed for good, with the
 * pump, one per aborted connection (found by the leak sentinel, docs/process.md).
 */
class TlsSocketReleaseTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun negative_anAbortedTlsSocketEndsItsJobWhileTheApplicationsWriteChannelIsOpen(): Unit =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            try {
                withTimeout(30.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    val client = async { connectTcp(selector, InetSocketAddress("127.0.0.1", port)).tls(clientConfig()) }
                    val accepted = server.accept().tlsServer(serverConfig())
                    val sock = client.await()
                    val input = sock.openDeliveringReadChannel()
                    val out = accepted.openWriteChannel() // kept open: the application neither writes nor closes it again
                    out.writeFully("hello".encodeToByteArray())
                    out.flush()
                    while (input.availableForRead < 5) yield() // the pumps on both sides are running
                    val raw = accepted.rawSocket as KslNioSocket
                    accepted.abort()
                    // an event, not a wait: the job completes once the abort ended everything under it; the bound only turns a
                    // hang into a failure
                    assertNotNull(withTimeoutOrNull(10.seconds) { raw.socketContext.join() }, "the aborted socket's job never completed")
                    assertFalse(raw.isOpen, "and its descriptor is closed")
                    sock.close()
                    server.close()
                    withTimeoutOrNull(10.seconds) { sock.socketContext.join() }
                }
            } finally {
                selector.close()
            }
        }

    /**
     * The application stopped reading (a client that got what it wanted, a server whose peer sends a flood) and closes: the
     * pump relaying the session's plaintext into the application's channel waited for room there, as a child of the raw
     * socket's job, so the socket's job never completed, however the close ended (found by the leak sentinel).
     */
    @Test fun negative_aClosedTlsSocketEndsItsJobWhileTheApplicationDoesNotRead(): Unit =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            try {
                withTimeout(30.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    val client = async { connectTcp(selector, InetSocketAddress("127.0.0.1", port)).tls(clientConfig()) }
                    val accepted = server.accept().tlsServer(serverConfig())
                    val sock = client.await()
                    val input = sock.openReadChannel() // never read again after the first bytes
                    val out = accepted.openWriteChannel()
                    val flood = async { runCatching { while (true) out.writeFully(ByteArray(64 shl 10)) } }
                    while (input.availableForRead == 0) yield() // the relay has delivered: it now waits for room
                    val raw = sock.rawSocket
                    sock.close()
                    assertNotNull(withTimeoutOrNull(10.seconds) { raw.socketContext.join() }, "the closed socket's job never completed")
                    accepted.abort()
                    flood.await()
                    server.close()
                    withTimeoutOrNull(10.seconds) { accepted.socketContext.join() }
                }
            } finally {
                selector.close()
            }
        }
}
