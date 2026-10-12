// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class, ExperimentalStdlibApi::class)
@file:Suppress("DEPRECATION")

package io.kuicksilver.native

import io.kuicksilver.native.cinterop.ksl_win_sockets_start
import kotlinx.cinterop.ExperimentalForeignApi
import kotlin.native.EagerInitialization

/**
 * Starts Winsock when the Kotlin/Native runtime starts, before any Kotlin code of the program runs: ktor-network's
 * `InetSocketAddress.resolveAddress()` calls `getaddrinfo`, which fails with WSANOTINITIALISED (10093) until someone has called
 * `WSAStartup`, and ktor-network calls it only when it creates a socket. An eager property is the one choke point every entry
 * path passes, including a caller's own address resolution before it touches kuicksilver; `ksl_init` and `ksl_udp_open` start
 * Winsock too. It is not a C constructor: in a sharedLib those run under the loader lock, where `WSAStartup` must not be called;
 * the runtime (and so this initializer) starts on the first call into Kotlin, outside it.
 */
@EagerInitialization
private val winsockStarted: Int = ksl_win_sockets_start(1)
