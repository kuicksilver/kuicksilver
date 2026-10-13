// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import platform.posix.MSG_NOSIGNAL

internal actual val bsdSockaddr: Boolean = false

internal actual val tcpSendFlags: Int = MSG_NOSIGNAL

internal actual fun tcpNoSigpipe(fd: Int) {}
