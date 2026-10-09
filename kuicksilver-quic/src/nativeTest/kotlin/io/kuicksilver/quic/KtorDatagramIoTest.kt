// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.toByteArray
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalKuicksilverApi::class)
class KtorDatagramIoTest {
    @Test fun loopbackClientSendReceive() =
        runBlocking {
            val a = DatagramIo.open(InetSocketAddress("127.0.0.1", 0))
            val b = DatagramIo.open(InetSocketAddress("127.0.0.1", 0))
            try {
                val out = PacketBatch(1)
                out.buffer(0).copyFrom(byteArrayOf(5, 6, 7), 0, 0, 3)
                out.setLength(0, 3)
                out.setAddress(0, b.localAddress)
                assertEquals(1, a.send(out))
                val inb = PacketBatch(4)
                withTimeout(5.seconds) { while (inb.count == 0) b.receive(inb) }
                assertContentEquals(byteArrayOf(5, 6, 7), inb.buffer(0).toByteArray(inb.length(0)))
                assertEquals(a.localAddress.port, inb.address(0)!!.port)
                out.close()
                inb.close()
            } finally {
                a.close()
                b.close()
            }
        }
}
