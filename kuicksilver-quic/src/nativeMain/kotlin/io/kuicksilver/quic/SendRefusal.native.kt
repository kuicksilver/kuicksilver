// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.utils.io.errors.PosixException
import platform.posix.EMSGSIZE

/** ktor's exceptions carry the errno; the message's text is not needed. */
internal actual fun systemEmsgsizeText(): String? = null

/** ktor's `PosixException` for EMSGSIZE (Darwin, Linux) or WSAEMSGSIZE (Windows, whose codes never collide with POSIX ones). */
internal actual fun isPlatformEmsgsize(e: Throwable): Boolean = e is PosixException && (e.errno == EMSGSIZE || e.errno == WSAEMSGSIZE)
