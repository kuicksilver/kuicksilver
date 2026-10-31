// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.TimeSource

/** `TCP_NODELAY` of [fd] as the system reports it. */
internal expect fun noDelayOf(fd: Int): Boolean

/**
 * The native sockets the engines open and accept have Nagle off, as on the JVM: with it on, a head and a body flushed
 * separately waited for the peer's delayed ACK (KTOR-10005 is the same gap in ktor-network's accepted sockets, fixed in 3.6.1).
 */
class TcpNoDelayTest {
    @Test fun openedAndAcceptedSocketsHaveNoDelay() {
        tcpStartup()
        val listener = tcpOpen(afInet)
        var client = -1
        var accepted: Int? = null
        try {
            assertTrue(noDelayOf(listener), "an opened socket")
            tcpBindListen(listener, tcpResolve("127.0.0.1", 0, numericHost = true).first(), 4)
            val port = tcpAddressOf(listener, peer = false).port
            client = tcpOpen(afInet)
            tcpConnect(client, tcpResolve("127.0.0.1", port, numericHost = true).first())
            val deadline = TimeSource.Monotonic.markNow()
            while (accepted == null && deadline.elapsedNow().inWholeSeconds < 10) {
                accepted = tcpAccept(listener, ByteArray(128))
            }
            val a = accepted ?: error("no connection accepted within 10 s")
            assertTrue(noDelayOf(client), "a connecting socket")
            assertTrue(noDelayOf(a), "an accepted socket")
        } finally {
            accepted?.let { tcpClose(it) }
            if (client >= 0) tcpClose(client)
            tcpClose(listener)
        }
    }
}
