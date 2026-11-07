// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslException
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** [KslUdpSocket.sender]: send-only clones of one socket (`ksl_udp_sender`), one sender thread each, on the same port. */
class KslUdpSenderTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
    }

    private fun loopback() = KslUdpSocket.encodeAddress(byteArrayOf(127, 0, 0, 1), 0)

    private fun send(
        from: KslUdpSocket,
        to: ByteArray,
        payload: ByteArray,
    ): Int {
        PacketBuffer.allocate(payload.size).use { buf ->
            buf.copyFrom(payload, 0, 0, payload.size)
            return from.send(arrayOf(buf), intArrayOf(payload.size), to, ByteArray(1), 1)
        }
    }

    /** One datagram within two seconds, or null. */
    private fun receive(on: KslUdpSocket): Pair<ByteArray, ByteArray>? {
        PacketBuffer.allocate(2048).use { buf ->
            val lens = IntArray(1)
            val addrs = ByteArray(KslUdpSocket.ADDR_LEN)
            if (on.receive(arrayOf(buf), lens, addrs, ByteArray(1), 1, 2000) != 1) return null
            return ByteArray(lens[0]).also { buf.copyTo(it, 0, 0, lens[0]) } to addrs
        }
    }

    @Test fun senderSharesPortAndCaps() {
        if (!KslUdpSocket.supported) return
        KslUdpSocket.open(loopback(), KslUdpSocket.ECN or KslUdpSocket.GSO or KslUdpSocket.DF).use { base ->
            base.sender().use { clone ->
                assertEquals(KslUdpSocket.portOf(base.localAddress), KslUdpSocket.portOf(clone.localAddress))
                assertContentEquals(base.localAddress, clone.localAddress)
                assertEquals(base.grantedFlags, clone.grantedFlags)
                assertEquals(base.gsoMaxSegments, clone.gsoMaxSegments)
                KslUdpSocket.open(loopback(), 0).use { peer ->
                    assertEquals(1, send(clone, peer.localAddress, byteArrayOf(1, 2, 3)))
                    val (data, from) = receive(peer) ?: error("nothing from the clone")
                    assertContentEquals(byteArrayOf(1, 2, 3), data)
                    assertEquals(
                        KslUdpSocket.portOf(base.localAddress),
                        KslUdpSocket.portOf(from),
                        "the clone sends from the socket's port",
                    )
                }
            }
        }
    }

    @Test fun negative_senderCannotReceive() {
        if (!KslUdpSocket.supported) return
        KslUdpSocket.open(loopback(), 0).use { base ->
            base.sender().use { clone ->
                KslUdpSocket.open(loopback(), 0).use { peer ->
                    assertEquals(1, send(peer, base.localAddress, byteArrayOf(9)))
                    val e = assertFailsWith<KslException.Internal> { receive(clone) }
                    assertEquals(KslConst.E_NOT_SUPPORTED, e.alert)
                    assertContentEquals(byteArrayOf(9), receive(base)?.first, "the socket keeps its datagram")
                }
            }
        }
    }

    @Test fun senderOutlivesTheSocketButSendsNoMore() {
        if (!KslUdpSocket.supported) return
        val base = KslUdpSocket.open(loopback(), 0)
        val clone = base.sender()
        KslUdpSocket.open(loopback(), 0).use { peer ->
            base.close()
            // the socket is gone: a socket error for the clone's sender, never a silent zero it would retry forever
            assertFailsWith<KslException.Internal> { send(clone, peer.localAddress, byteArrayOf(7)) }
            clone.close()
        }
        assertFailsWith<IllegalStateException> { base.sender() }
        assertTrue(clone.isClosed)
    }
}
