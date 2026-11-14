// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * A connected socket's addresses, and a listener's, stay readable after it is closed: they do not change, and readers such
 * as the client's HTTP/2 setup ask for the peer's address after the connection may have ended (a server's GOAWAY right
 * after the preface). Ktor's JVM socket asks the channel on every read, which then throws ClosedChannelException; a
 * native socket's local address asked of a closed descriptor fails, or answers for another socket that reuses its number.
 */
class SocketAddressAfterCloseTest {
    private fun tcpTest(block: suspend (SelectorManager) -> Unit) =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            try {
                withTimeout(30.seconds) { block(selector) }
            } finally {
                selector.close()
            }
        }

    private val io.ktor.network.sockets.SocketAddress.port: Int get() = (this as InetSocketAddress).port

    @Test fun addressesStayReadableAfterClose() =
        tcpTest { selector ->
            val server = bindTcp(selector, "127.0.0.1", 0)
            val serverPort = server.localAddress.port
            val (client, accepted) =
                coroutineScope {
                    val accepting = async { server.accept() }
                    connectTcp(selector, InetSocketAddress("127.0.0.1", serverPort)) to accepting.await()
                }
            // the peer's view gives the expected values: neither of the client's own is read before its close
            val clientPort = accepted.remoteAddress.port
            // both loops attached, as on a connection in use: the descriptor closes once they have ended
            client.openReadChannel()
            client.openWriteChannel()

            client.close()
            accepted.close()
            server.close()
            // the descriptors are closed in the system before anything is asked: an address read from one still open would
            // pass without the fix
            awaitDescriptorClosed(client)
            awaitDescriptorClosed(accepted)
            awaitDescriptorClosed(server)

            assertEquals(clientPort, client.localAddress.port)
            assertEquals(serverPort, client.remoteAddress.port)
            assertEquals(serverPort, accepted.localAddress.port)
            assertEquals(clientPort, accepted.remoteAddress.port)
            // a regression guard on Native, whose listener has always taken its address at bind; on the JVM, ktor's asks the
            // closed channel
            assertEquals(serverPort, server.localAddress.port)
        }
}
