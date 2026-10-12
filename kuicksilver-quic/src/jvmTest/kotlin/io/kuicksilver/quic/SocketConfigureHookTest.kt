// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.KslUdpSocket
import java.nio.channels.DatagramChannel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The hooks Android uses to bind a socket to a network (`Network.bindSocket`) before it carries a datagram. */
class SocketConfigureHookTest {
    private val lo = InetSocketAddress("127.0.0.1", 0)

    @Test fun nioHookRunsBeforeBind() {
        var seen: DatagramChannel? = null
        var boundAtHook = true
        val io =
            NioDatagramIo.open(lo) {
                seen = it
                boundAtHook = it.localAddress != null
            }
        try {
            assertFalse(boundAtHook, "Network.bindSocket needs a socket that is not bound to an address yet")
            assertTrue(seen!!.isOpen)
            assertTrue(io.localAddress.port != 0)
        } finally {
            io.close()
        }
    }

    @Test fun negative_nioHookFailureClosesTheChannel() {
        var seen: DatagramChannel? = null
        assertFailsWith<java.net.SocketException> {
            NioDatagramIo.open(lo) {
                seen = it
                throw java.net.SocketException("network gone")
            }
        }
        assertFalse(seen!!.isOpen, "no socket leaks when the network refuses it")
    }

    @Test fun kslHookSeesTheSocketDescriptor() {
        KslLoader.ensureLoaded()
        var fd = -1
        val io = KslDatagramIo.open(lo) { fd = it }
        if (!KslUdpSocket.supported) {
            assertNull(io)
            assertEquals(-1, fd, "no socket, no hook")
            return
        }
        try {
            assertTrue(fd >= 0)
        } finally {
            io!!.close()
        }
    }

    @Test fun negative_kslHookFailureClosesTheSocket() {
        KslLoader.ensureLoaded()
        if (!KslUdpSocket.supported) return // Linux only (ADR-0006)
        var fd = -1
        assertFailsWith<java.net.SocketException> {
            KslDatagramIo.open(lo) {
                fd = it
                throw java.net.SocketException("network gone")
            }
        }
        // the descriptor is gone: fstat on it through /proc fails
        assertFalse(java.io.File("/proc/self/fd/$fd").exists(), "fd $fd still open")
    }
}
