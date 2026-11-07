// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** `SO_RCVBUF` of [fd] as the system reports it. */
internal expect fun receiveBufferOf(fd: Int): Int

/**
 * [connectTcp]'s receiveBufferSize reaches the connecting socket (tests of slow readers use it). The size asked for, 1 MiB,
 * is above every platform's default; what a connected socket reports differs by system (Linux doubles the value and caps
 * it at rmem_max, Darwin adjusts it on connect), so the check is that it ends above the default one.
 */
class TcpReceiveBufferTest {
    @Test fun connectTcpSetsTheReceiveBuffer() =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            try {
                withTimeout(30.seconds) {
                    bindTcp(selector, "127.0.0.1", 0).use { server ->
                        val to = InetSocketAddress("127.0.0.1", (server.localAddress as InetSocketAddress).port)
                        val accepted = async { repeat(2) { server.accept().close() } }
                        val default = connectTcp(selector, to).use { receiveBufferOf((it as NativeTcpSocket).descriptor) }
                        val asked = 1 shl 20
                        val got =
                            connectTcp(
                                selector,
                                to,
                                receiveBufferSize = asked,
                            ).use { receiveBufferOf((it as NativeTcpSocket).descriptor) }
                        assertTrue(got > default, "SO_RCVBUF $got with $asked asked for, $default by default")
                        accepted.await()
                    }
                }
            } finally {
                selector.close()
            }
        }
}
