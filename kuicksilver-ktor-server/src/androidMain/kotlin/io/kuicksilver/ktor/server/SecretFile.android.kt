// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer

/**
 * Reads the file through a direct buffer of its own, which is wiped before it is dropped: a heap buffer would go through the
 * JDK's cached temporary direct buffers, and kotlinx-io through pooled segments, neither of which is ever wiped.
 */
internal actual fun readSecretFile(
    path: String,
    maxBytes: Long,
): CharArray =
    RandomAccessFile(path, "r").use { f ->
        val ch = f.channel
        val size = ch.size()
        if (size > maxBytes) throw IOException("$path is larger than $maxBytes bytes")
        val buf = ByteBuffer.allocateDirect(size.toInt())
        try {
            while (buf.hasRemaining()) {
                if (ch.read(buf) < 0) break
            }
            buf.flip()
            CharArray(buf.remaining()) { (buf.get().toInt() and 0xff).toChar() }
        } finally {
            buf.clear()
            while (buf.hasRemaining()) buf.put(0)
        }
    }
