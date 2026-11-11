// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import platform.posix.FD_CLOEXEC
import platform.posix.F_GETFD
import platform.posix.F_GETFL
import platform.posix.O_NONBLOCK
import platform.posix.fcntl
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Every TCP descriptor (listening, connected, accepted) is non-blocking and close-on-exec: on Linux from the `socket` or
 * `accept4` call itself (`SOCK_NONBLOCK | SOCK_CLOEXEC`), on Apple through `fcntl` right after it.
 */
class CloseOnExecTest {
    private fun assertFlags(
        fd: Int,
        what: String,
    ) {
        assertTrue(fcntl(fd, F_GETFD) and FD_CLOEXEC != 0, "$what: no FD_CLOEXEC")
        assertTrue(fcntl(fd, F_GETFL) and O_NONBLOCK != 0, "$what: blocking")
    }

    @Test fun everyDescriptorIsNonBlockingAndCloseOnExec() =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            val server = bindTcp(selector, "127.0.0.1", 0)
            try {
                assertFlags((server as NativeTcpServerSocket).descriptor, "listening")
                val accepted = async { server.accept() }
                val client = connectTcp(selector, InetSocketAddress("127.0.0.1", (server.localAddress as InetSocketAddress).port))
                val peer = withTimeout(10.seconds) { accepted.await() }
                assertFlags((client as NativeTcpSocket).descriptor, "connected")
                assertFlags((peer as NativeTcpSocket).descriptor, "accepted")
                client.close()
                peer.close()
            } finally {
                server.close()
                selector.close()
            }
        }
}
