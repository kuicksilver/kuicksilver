// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The source address the system would pick for a destination, without sending anything (RFC 6724 section 6, Source(D)). */
class SourceAddressTest {
    @Test fun loopbackDestinationHasALoopbackSource() {
        assertEquals("127.0.0.1", sourceAddressFor(TcpAddress(byteArrayOf(127, 0, 0, 1), 9))?.hostText)
    }

    @Test fun ipv6LoopbackHasItselfOrNothing() {
        // a host without IPv6 has no source for ::1; one with it answers ::1
        val a = sourceAddressFor(TcpAddress(ByteArray(16).also { it[15] = 1 }, 9))
        assertTrue(a == null || a.hostText == "::1", "$a")
    }

    @Test fun answerIsOfTheDestinationsFamilyWithPortZero() {
        for (dest in listOf(
            TcpAddress(byteArrayOf(192.toByte(), 0, 2, 1), 443),
            TcpAddress(
                ByteArray(16).also {
                    it[0] = 0x20
                    it[1] = 0x01
                    it[2] =
                        0x0d
                    it[3] = 0xb8.toByte()
                    it[15] = 1
                },
                443,
            ),
        )) {
            val a = sourceAddressFor(dest) ?: continue // no route of that family on this host
            assertEquals(dest.isIpv6, a.isIpv6)
            assertEquals(0, a.port)
        }
    }
}
