// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

private val darwin =
    System
        .getProperty("os.name")
        .orEmpty()
        .lowercase()
        .let { it.contains("mac") || it.contains("darwin") }

/**
 * The errno values of `ksl_udp` on this JVM's system: Darwin (EBADF 9, EPIPE 32, ENOTSOCK 38, ENETDOWN 50, ENETUNREACH 51,
 * ENOTCONN 57, EHOSTUNREACH 65) or Linux and Android (EBADF 9, EPIPE 32, ENOTSOCK 88, ENETDOWN 100, ENETUNREACH 101,
 * ENOTCONN 107, EHOSTUNREACH 113); Windows reports WSA codes.
 */
internal actual fun isDefunctErrno(errno: Int): Boolean =
    errno == 9 || errno == 32 || isDefunctWsa(errno) ||
        if (darwin) {
            errno == 38 || errno == 50 || errno == 51 || errno == 57 || errno == 65
        } else {
            errno == 88 || errno == 100 || errno == 101 || errno == 107 || errno == 113
        }
