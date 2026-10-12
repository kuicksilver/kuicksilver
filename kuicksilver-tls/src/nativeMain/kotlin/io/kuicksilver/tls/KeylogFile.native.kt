// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(DelicateKuicksilverApi::class, ExperimentalForeignApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import platform.posix.close
import platform.posix.fclose
import platform.posix.fdopen
import platform.posix.fputs
import platform.posix.getenv

/**
 * Opens [path] for appending as the key log and returns the descriptor, or -1 when the file is unfit: on POSIX targets the
 * open never follows a symlink, the file must be a regular one owned by the effective user, and lingering group/other bits
 * are cleared (0600); mingw only creates the file. The caller closes the descriptor.
 */
internal expect fun openKeylogFd(path: String): Int

public actual fun keylogFile(path: String): KeylogSink {
    val probe = openKeylogFd(path)
    if (probe < 0) throw IllegalArgumentException("keylog file $path refused: not a regular file of this user, a symlink, or not writable")
    close(probe)
    return KeylogSink { line ->
        val fd = openKeylogFd(path) // every line reopens without following links: a swap after the check lands nowhere either
        if (fd >= 0) {
            val f = fdopen(fd, "a") // stdio has the same signature on every target (write() differs between POSIX and mingw)
            if (f != null) {
                fputs(line + "\n", f)
                fclose(f)
            } else {
                close(fd)
            }
        }
    }
}

public actual fun keylogFromEnvironment(): KeylogSink? =
    getenv("SSLKEYLOGFILE")
        ?.toKString()
        ?.takeIf {
            it.isNotBlank()
        }?.let { keylogFile(it) }
