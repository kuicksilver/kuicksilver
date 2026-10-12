// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.native

import io.kuicksilver.native.cinterop.ksl_win_sockets_started_by
import platform.posix.AF_INET
import platform.posix.INVALID_SOCKET
import platform.posix.IPPROTO_UDP
import platform.posix.SOCK_DGRAM
import platform.posix.WSAGetLastError
import platform.posix.closesocket
import platform.posix.socket
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

/**
 * Winsock is started when the Kotlin/Native runtime starts (WinsockStart.mingw.kt): ktor-network starts it only when it creates
 * a socket, so an address lookup before that failed with WSANOTINITIALISED (10093) — 295 kuicksilver-quic tests on the first
 * windows-2025 run. Order-independent: whatever ran before in this process, the first starter recorded by ksl must be the
 * runtime start (1), not ksl_init (2) or ksl_udp_open (3) reached by an earlier test. Runs only in CI's windows job.
 */
class WinsockReadyTest {
    @Test fun winsockIsStartedByTheRuntimeBeforeAnyKotlinCode() {
        assertEquals(1, ksl_win_sockets_started_by(), "first Winsock start: 1 runtime start, 2 ksl_init, 3 ksl_udp_open, 0 none")
        val s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        val err = if (s == INVALID_SOCKET) WSAGetLastError() else 0
        if (s != INVALID_SOCKET) closesocket(s)
        assertNotEquals(INVALID_SOCKET, s, "socket() failed with WSA error $err (10093 = WSANOTINITIALISED)")
    }
}
