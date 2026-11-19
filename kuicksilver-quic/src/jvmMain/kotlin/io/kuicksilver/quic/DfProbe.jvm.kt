// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.quic

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.KslFdSocket
import io.kuicksilver.native.KslLoader
import java.nio.channels.DatagramChannel

/**
 * Through `ksl` (Linux and Windows; Apple has no probe mode): the channel's descriptor is read through JNI (the JDK's
 * `fdVal`), so nothing is opened up with `--add-opens`. Without the library, or on a runtime whose channel has no such
 * field, nothing is set.
 */
internal actual fun dfProbe(ch: DatagramChannel): Int =
    withFd(ch, 0) { fd ->
        KslFdSocket.dfProbe(fd).coerceAtLeast(0)
    }

internal actual fun dfModeOf(
    ch: DatagramChannel,
    family: Int,
): Int = withFd(ch, -1) { fd -> KslFdSocket.dfMode(fd, family) }

private inline fun withFd(
    ch: DatagramChannel,
    otherwise: Int,
    block: (Long) -> Int,
): Int =
    try {
        if (!KslLoader.isAvailable()) {
            otherwise
        } else {
            val fd = KslFdSocket.channelFd(ch)
            if (fd < 0) otherwise else block(fd.toLong())
        }
    } catch (_: LinkageError) {
        otherwise // a library without these entry points
    }
