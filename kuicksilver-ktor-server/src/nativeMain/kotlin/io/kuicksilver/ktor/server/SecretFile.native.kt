// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.ktor.server

import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import kotlinx.io.IOException
import platform.posix.EINTR
import platform.posix._IONBF
import platform.posix.errno
import platform.posix.fclose
import platform.posix.ferror
import platform.posix.fopen
import platform.posix.fread
import platform.posix.setvbuf

/**
 * Reads the file unbuffered (`_IONBF`: `fread` goes straight into the pinned array, no stdio buffer keeps a copy) into an
 * array of our own, wiped after the characters are taken.
 */
internal actual fun readSecretFile(
    path: String,
    maxBytes: Long,
): CharArray {
    val f = fopen(path, "rb") ?: throw IOException("$path: cannot open (errno $errno)")
    val buf = ByteArray(maxBytes.toInt() + 1)
    try {
        setvbuf(f, null, _IONBF, 0u)
        var n = 0
        buf.usePinned { p ->
            while (n < buf.size) {
                val r = fread(p.addressOf(n), 1u, (buf.size - n).convert(), f).toInt()
                if (r <= 0) {
                    if (ferror(f) != 0 && errno == EINTR) continue
                    if (ferror(f) != 0) throw IOException("$path: read failed (errno $errno)")
                    break
                }
                n += r
            }
        }
        if (n > maxBytes) throw IOException("$path is larger than $maxBytes bytes")
        return CharArray(n) { (buf[it].toInt() and 0xff).toChar() }
    } finally {
        buf.fill(0)
        fclose(f)
    }
}
