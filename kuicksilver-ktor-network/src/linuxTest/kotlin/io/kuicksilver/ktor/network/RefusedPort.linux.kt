// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import platform.posix.bind
import kotlin.test.assertEquals

/**
 * The port is held by a socket bound to it that never listens: Linux answers a SYN to it with a reset (only listeners take
 * one), and no connect takes a port bound with bind() as its own.
 */
@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun <T> withRefusedLoopbackPort(
    selector: SelectorManager,
    use: suspend (port: Int) -> T,
): T {
    tcpStartup()
    val holder = tcpOpen(afInet)
    try {
        val at = Sockaddr.v4(byteArrayOf(127, 0, 0, 1), 0).bytes
        assertEquals(0, at.usePinned { bind(holder, it.addressOf(0).reinterpret(), at.size.convert()) }, "bind the held port")
        return use(tcpAddressOf(holder, peer = false).port)
    } finally {
        tcpClose(holder)
    }
}
