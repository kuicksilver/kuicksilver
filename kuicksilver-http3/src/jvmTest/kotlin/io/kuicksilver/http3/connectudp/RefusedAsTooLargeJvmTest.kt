// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.connectudp

import java.net.PortUnreachableException
import java.net.SocketException
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The JDK's own exceptions for a datagram the OS refuses as too large (EMSGSIZE, WSAEMSGSIZE), as the NIO channel throws them. */
class RefusedAsTooLargeJvmTest {
    @Test fun jdkSocketExceptionsForEmsgsize() {
        // Linux, macOS: strerror(EMSGSIZE)
        assertTrue(isRefusedAsTooLarge(SocketException("Message too long")))
        // Windows: NET_ThrowNew(env, WSAEMSGSIZE, "sendto")
        assertTrue(
            isRefusedAsTooLarge(SocketException("The message is larger than the maximum supported by the underlying transport: sendto")),
        )
        assertFalse(isRefusedAsTooLarge(SocketException("Network is unreachable")))
        assertFalse(isRefusedAsTooLarge(PortUnreachableException()))
    }
}
