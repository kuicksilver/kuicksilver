// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * A loopback port the test owns, for a destination a request must not reach: every connection to it is counted and
 * closed at once. Tests point such requests here instead of at a well-known port of the host (80, 443, 1), where another
 * program may listen and answer.
 */
internal class Tripwire : AutoCloseable {
    private val socket = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
    val port: Int = socket.localPort
    val hits = AtomicInteger(0)

    init {
        thread(isDaemon = true, name = "tripwire-$port") {
            while (!socket.isClosed) {
                runCatching { socket.accept() }.getOrNull()?.use { hits.incrementAndGet() }
            }
        }
    }

    override fun close() = socket.close()
}
