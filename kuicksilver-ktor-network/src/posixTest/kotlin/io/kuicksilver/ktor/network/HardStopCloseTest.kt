// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import platform.posix.F_GETFD
import platform.posix.fcntl
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.seconds

/**
 * A hard stop cancels the listening socket's job, and with it every accepted socket's: their loops end before anyone
 * closes them. The close that follows (the engine's) still releases the descriptor. Before, it launched its work in the
 * cancelled job, where nothing starts, and the descriptor stayed open for the rest of the process.
 */
class HardStopCloseTest {
    @Test fun aSocketWhoseJobWasCancelledStillClosesItsDescriptor() =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            val server = bindTcp(selector, "127.0.0.1", 0)
            try {
                val accepted = async { server.accept() }
                val client = connectTcp(selector, InetSocketAddress("127.0.0.1", (server.localAddress as InetSocketAddress).port))
                val socket = withTimeout(10.seconds) { accepted.await() } as NativeTcpSocket
                socket.openReadChannel()
                socket.openWriteChannel(autoFlush = true)
                val fd = socket.descriptor
                server.socketContext.cancel() // the hard stop: every accepted socket's job is cancelled under it
                withTimeout(10.seconds) { socket.socketContext.join() }
                socket.close()
                // the descriptor is closed once the selector was told (fcntl answers -1, EBADF)
                assertNotNull(
                    withTimeoutOrNull(5.seconds) { while (fcntl(fd, F_GETFD) != -1) delay(10) },
                    "descriptor $fd is still open",
                )
                client.close()
            } finally {
                server.close()
                selector.close()
            }
        }
}
