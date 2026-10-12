// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.native

import platform.posix.AF_INET
import platform.posix.INVALID_SOCKET
import platform.posix.IPPROTO_UDP
import platform.posix.SOCK_DGRAM
import platform.posix.WSAGetLastError
import platform.posix.closesocket
import platform.posix.socket
import kotlin.test.Test
import kotlin.test.assertNotEquals

/**
 * Winsock is started when the program starts (ksl_udp_win.c, and again in ksl_init): ktor-network starts it only when it creates
 * a socket, so an address lookup before that failed with WSANOTINITIALISED (10093) — 295 kuicksilver-quic tests on the first
 * windows-2025 run. This binary has no ktor-network, so without ksl's start this socket() fails whatever the test order.
 * Runs only in CI's windows job.
 */
class WinsockReadyTest {
    @Test fun winsockIsStartedBeforeAnySocketOrKslCall() {
        val s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        val err = if (s == INVALID_SOCKET) WSAGetLastError() else 0
        if (s != INVALID_SOCKET) closesocket(s)
        assertNotEquals(INVALID_SOCKET, s, "socket() failed with WSA error $err (10093 = WSANOTINITIALISED)")
    }
}
