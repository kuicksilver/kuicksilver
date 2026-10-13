// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import platform.posix.EBADF
import platform.posix.EHOSTUNREACH
import platform.posix.ENETDOWN
import platform.posix.ENETUNREACH
import platform.posix.ENOTCONN
import platform.posix.ENOTSOCK
import platform.posix.EPIPE

/** The target's own errno values (Darwin, Linux); mingw's `ksl_udp` reports WSA codes, which never collide with them. */
internal actual fun isDefunctErrno(errno: Int): Boolean =
    errno == EBADF || errno == ENOTCONN || errno == EPIPE || errno == ENOTSOCK || errno == ENETDOWN || errno == ENETUNREACH ||
        errno == EHOSTUNREACH || isDefunctWsa(errno)
