// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.quic

import java.net.PortUnreachableException
import java.net.SocketException
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The JDK's own exceptions for a datagram the system refuses as too large, as its NIO channel throws them. */
class SendRefusalJvmTest {
    @Test fun jdkSocketExceptions() {
        // Linux, macOS: strerror(EMSGSIZE)
        assertTrue(isRefusedAsTooLarge(SocketException("Message too long")))
        // Windows: NET_ThrowNew(env, WSAEMSGSIZE, "sendto")
        assertTrue(
            isRefusedAsTooLarge(SocketException("The message is larger than the maximum supported by the underlying transport: sendto")),
        )
        // the portable socket's refusal at or below 1200 bytes keeps the JDK's as its cause
        assertTrue(isRefusedAsTooLarge(PathMtuRefusedException(1200, null, SocketException("Message too long"))))
        assertFalse(isRefusedAsTooLarge(SocketException("Network is unreachable")))
        assertFalse(isRefusedAsTooLarge(PortUnreachableException()))
    }

    /** The same texts as the portable socket's own check: one classifier. */
    @Test fun sameTextsAsTheNioSocket() {
        for (m in listOf("Message too long", "EMSGSIZE", "larger than the maximum supported by the underlying transport", "Broken pipe")) {
            assertTrue(NioDatagramIo.isMessageTooLong(SocketException(m)) == isRefusedAsTooLarge(SocketException(m)), m)
        }
    }

    /** strerror(EMSGSIZE) under this process's locale, where ksl reports it, is recognized whatever the language. */
    @Test fun systemTextIsRecognized() {
        val t = systemEmsgsizeText() ?: return // no ksl, or Windows
        assertTrue(isRefusedAsTooLarge(SocketException(t)))
    }
}
