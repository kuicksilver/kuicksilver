// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class, NativeRuntimeApi::class, ObsoleteWorkersApi::class)

package io.kuicksilver.ktor.network

import io.kuicksilver.ktor.network.wsa.ksl_wsa_connect
import io.kuicksilver.ktor.network.wsa.ksl_wsa_recv
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.posix.AF_INET
import platform.posix.WSAECONNREFUSED
import platform.posix.WSAENOTCONN
import platform.posix.WSAEWOULDBLOCK
import platform.windows.GetTickCount64
import platform.windows.Sleep
import kotlin.concurrent.AtomicInt
import kotlin.native.concurrent.ObsoleteWorkersApi
import kotlin.native.concurrent.TransferMode
import kotlin.native.concurrent.Worker
import kotlin.native.runtime.GC
import kotlin.native.runtime.NativeRuntimeApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * The Winsock error of a failed call reaches Kotlin (kslwsa.def captures it in C): read from Kotlin after the call returned
 * it could already be reset by the runtime, and a pending connect to a listening 127.0.0.1 port failed with "POSIX error 0"
 * (GitHub Windows runner, ServerH1TimeoutTest).
 */
class WindowsWinsockErrorTest {
    private fun loopback(port: Int) = Sockaddr.v4(byteArrayOf(127, 0, 0, 1), port)

    private fun <T : Any> poll(
        what: String,
        timeoutMs: Long = 10_000,
        attempt: () -> T?,
    ): T {
        val deadline = GetTickCount64() + timeoutMs.toULong()
        while (true) {
            attempt()?.let { return it }
            check(GetTickCount64() < deadline) { "timed out waiting for $what" }
            Sleep(1u)
        }
    }

    @Test fun manyNonBlockingConnectsToALocalListenerAllSucceedWhileTheGcRuns() {
        tcpStartup()
        // a collector on another thread makes this thread stop for the GC on its way back from the socket calls: the
        // runtime path that lost the last error
        val stop = AtomicInt(0)
        val gc = Worker.start(name = "gc")
        val collecting =
            gc.execute(TransferMode.SAFE, { stop }) { flag ->
                var n = 0
                while (flag.value == 0) {
                    GC.collect()
                    n++
                }
                n
            }
        val listener = tcpOpen(AF_INET)
        try {
            tcpBindListen(listener, loopback(0), 256)
            val port = tcpAddressOf(listener, peer = false).port
            repeat(CONNECTS) { i ->
                val garbage = List(64) { ByteArray(1024) }
                val client = tcpOpen(AF_INET)
                try {
                    // throws on any error other than "would block", e.g. a lost WSAEWOULDBLOCK read as 0
                    tcpConnect(client, loopback(port))
                    val accepted = poll("connect #$i to be accepted") { tcpAccept(listener, ByteArray(SOCKADDR_STORAGE)) }
                    try {
                        assertEquals(0, tcpPendingError(client), "connect #$i has no socket error")
                        assertEquals(-1, tcpRecv(client, ByteArray(16)), "nothing to read yet on #$i: would block, not an error")
                        assertEquals(port, tcpAddressOf(client, peer = true).port)
                    } finally {
                        tcpClose(accepted)
                    }
                } finally {
                    tcpClose(client)
                }
                assertEquals(64, garbage.size)
            }
        } finally {
            tcpClose(listener)
            stop.value = 1
            assertTrue(collecting.result >= 0)
            gc.requestTermination().result
        }
    }

    @Test fun theShimReturnsTheWinsockErrorOfTheCall() {
        tcpStartup()
        val closedPort = closedLoopbackPort()
        val client = tcpOpen(AF_INET)
        try {
            memScoped {
                val err = alloc<IntVar>()
                // not connected: a synchronous error
                val n = ByteArray(16).usePinned { ksl_wsa_recv(client.convert(), it.addressOf(0), 16, err.ptr) }
                assertEquals(-1, n)
                assertEquals(WSAENOTCONN, err.value, "recv on an unconnected socket")

                // a non-blocking connect is pending: WSAEWOULDBLOCK, never 0
                err.value = -1
                val to = loopback(closedPort).bytes
                val rc = to.usePinned { ksl_wsa_connect(client.convert(), it.addressOf(0), to.size, err.ptr) }
                assertNotEquals(0, rc)
                assertEquals(WSAEWOULDBLOCK, err.value, "a non-blocking connect")
            }
            // nobody listens there: the refusal arrives as the socket's error (Windows retries a refused SYN for ~2 s)
            val refused = poll("the refused connect") { tcpPendingError(client).takeIf { it != 0 } }
            assertEquals(WSAECONNREFUSED, refused)
        } finally {
            tcpClose(client)
        }
    }

    @Test fun negative_aConnectToAClosedPortIsPendingThenRefused() {
        tcpStartup()
        val client = tcpOpen(AF_INET)
        try {
            assertFalse(tcpConnect(client, loopback(closedLoopbackPort())), "pending, not failed nor connected")
            assertEquals(WSAECONNREFUSED, poll("the refused connect") { tcpPendingError(client).takeIf { it != 0 } })
        } finally {
            tcpClose(client)
        }
    }

    /** A loopback port that was just free: bound, read and closed again. */
    private fun closedLoopbackPort(): Int {
        val s = tcpOpen(AF_INET)
        try {
            tcpBindListen(s, loopback(0), 1)
            return tcpAddressOf(s, peer = false).port
        } finally {
            tcpClose(s)
        }
    }

    private companion object {
        const val CONNECTS = 200
    }
}
