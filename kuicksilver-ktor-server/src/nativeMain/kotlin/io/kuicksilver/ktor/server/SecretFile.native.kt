// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, kotlin.experimental.ExperimentalNativeApi::class)

package io.kuicksilver.ktor.server

import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import kotlinx.io.IOException
import platform.posix.EINTR
import platform.posix._IONBF
import platform.posix.clearerr
import platform.posix.fclose
import platform.posix.ferror
import platform.posix.fopen
import platform.posix.fread
import platform.posix.posix_errno
import platform.posix.set_posix_errno
import platform.posix.setvbuf
import kotlin.native.OsFamily
import kotlin.native.Platform

/** Interrupted reads retried before the read fails. */
private const val MAX_EINTR_RETRIES = 8

/**
 * Reads the file unbuffered (`_IONBF`: `fread` goes straight into the pinned array, no stdio buffer keeps a copy) into an
 * array of our own, wiped after the characters are taken. The descriptor is not inherited by child processes: `e`
 * (`O_CLOEXEC`) on Linux and Apple platforms, `N` (no inheritance) in the Windows C runtime.
 */
internal actual fun readSecretFile(
    path: String,
    maxBytes: Long,
): CharArray {
    val mode = if (Platform.osFamily == OsFamily.WINDOWS) "rbN" else "rbe"
    val f = fopen(path, mode) ?: throw IOException("$path: cannot open (errno ${posix_errno()})")
    val buf = ByteArray(maxBytes.toInt() + 1)
    try {
        setvbuf(f, null, _IONBF, 0u)
        var n = 0
        var interrupted = 0
        buf.usePinned { p ->
            while (n < buf.size) {
                set_posix_errno(0)
                val r = fread(p.addressOf(n), 1u, (buf.size - n).convert(), f).toInt()
                if (r > 0) {
                    n += r
                    continue
                }
                if (ferror(f) == 0) break // end of file
                val e = posix_errno()
                if (e == EINTR && ++interrupted <= MAX_EINTR_RETRIES) {
                    clearerr(f) // the error flag is sticky: cleared, or the retry would see the old one
                    continue
                }
                throw IOException("$path: read failed (errno $e)")
            }
        }
        if (n > maxBytes) throw IOException("$path is larger than $maxBytes bytes")
        return CharArray(n) { (buf[it].toInt() and 0xff).toChar() }
    } finally {
        buf.fill(0)
        fclose(f)
    }
}
