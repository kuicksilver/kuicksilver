// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.posix.SOL_SOCKET
import platform.posix.SO_EXCLUSIVEADDRUSE
import platform.posix.bind
import platform.posix.setsockopt
import kotlin.test.assertEquals

/**
 * The port is held by a socket bound to it with SO_EXCLUSIVEADDRUSE that never listens: Windows refuses a connect to it
 * (after retrying the SYN for about 2 s), no other socket can bind it, not even with SO_REUSEADDR, and no connect takes it
 * as its own port.
 */
@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun <T> withRefusedLoopbackPort(
    selector: SelectorManager,
    use: suspend (port: Int) -> T,
): T {
    tcpStartup()
    val holder = tcpOpen(afInet)
    try {
        memScoped {
            val one = alloc<IntVar>()
            one.value = 1
            val rc = setsockopt(holder.convert(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE, one.ptr.reinterpret(), sizeOf<IntVar>().toInt())
            assertEquals(0, rc, "setsockopt(SO_EXCLUSIVEADDRUSE) on the held port's socket")
        }
        val at = Sockaddr.v4(byteArrayOf(127, 0, 0, 1), 0).bytes
        assertEquals(0, at.usePinned { bind(holder.convert(), it.addressOf(0).reinterpret(), at.size) }, "bind the held port")
        return use(tcpAddressOf(holder, peer = false).port)
    } finally {
        tcpClose(holder)
    }
}
