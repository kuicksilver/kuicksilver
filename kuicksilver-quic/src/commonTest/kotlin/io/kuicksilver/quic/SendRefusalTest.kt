// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** [isRefusedAsTooLarge]: which send failures are a datagram refused as too large, and which a failed socket. */
class SendRefusalTest {
    @Test fun refusalTexts() {
        assertTrue(isRefusedAsTooLarge(IOException("Message too long")))
        assertTrue(isRefusedAsTooLarge(IOException("sendto failed: EMSGSIZE (Message too long)"))) // Android
        assertTrue(isRefusedAsTooLarge(IOException("The message is larger than the maximum supported by the underlying transport: sendto")))
        assertTrue(isRefusedAsTooLarge(IOException("WSAEMSGSIZE")))
        assertFalse(isRefusedAsTooLarge(IOException("Network is unreachable")))
        assertFalse(isRefusedAsTooLarge(IOException("Connection refused")))
        assertFalse(isRefusedAsTooLarge(IOException()))
        // not an I/O failure, whatever its text: a bug is not a dropped payload
        assertFalse(isRefusedAsTooLarge(IllegalStateException("Message too long")))
    }

    @Test fun pathMtuRefusalAndCauses() {
        assertTrue(isRefusedAsTooLarge(PathMtuRefusedException(1200, InetSocketAddress("192.0.2.1", 443))))
        assertTrue(isRefusedAsTooLarge(IllegalStateException("send failed", PathMtuRefusedException(1000))))
        assertTrue(isRefusedAsTooLarge(IllegalStateException("send failed", IOException("Message too long"))))
        assertTrue(isRefusedAsTooLarge(IOException("send failed", IOException("Message too long"))))
        assertFalse(isRefusedAsTooLarge(IOException("send failed", IOException("Broken pipe"))))
    }

    /** A socket without DF for the destination is not a payload too large, whatever its causes say: it ends the tunnel. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun negative_noDontFragmentIsNeverARefusal() {
        val noDf = QuicException.DontFragmentUnavailable(IpFamily.V4, "Message too long")
        assertFalse(isRefusedAsTooLarge(noDf))
        assertFalse(isRefusedAsTooLarge(IllegalStateException("send failed", noDf)))
        assertFalse(isRefusedAsTooLarge(IOException("EMSGSIZE", noDf)))
    }

    /** The system's own text in its locale counts when known; without it, only the English texts do. */
    @Test fun localizedText() {
        assertTrue(namesEmsgsize("Nachricht zu lang", "Nachricht zu lang"))
        assertFalse(namesEmsgsize("Nachricht zu lang", null))
        assertFalse(namesEmsgsize("anything", ""))
    }

    /** A cause chain that loops, or is very long, ends. */
    @Test fun negative_causeLoopEnds() {
        val a = LoopingCause("a")
        a.next = IOException("b", a)
        assertFalse(isRefusedAsTooLarge(a))
        var deep: Throwable = IOException("Message too long")
        repeat(20) { deep = IllegalStateException("wrap", deep) }
        assertFalse(isRefusedAsTooLarge(deep))
    }

    private class LoopingCause(
        message: String,
    ) : IOException(message) {
        var next: Throwable? = null
        override val cause: Throwable? get() = next
    }
}
