// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, ExperimentalForeignApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import platform.posix.FILE
import platform.posix.close
import platform.posix.fclose
import platform.posix.fdopen
import platform.posix.fwrite

/** Creates the directory [path] owner-only (0700) if it is missing; returns the reason it is unfit, or null when it may be used. */
internal expect fun privateDirectoryProblem(path: String): String?

/**
 * Opens [path] for writing only if nothing exists there (`O_CREAT | O_EXCL`, plus `O_NOFOLLOW` on POSIX), mode 0600.
 * Returns the descriptor, [EXISTS] when the name is taken, or -1 on another failure.
 */
internal expect fun openExclusive(path: String): Int

internal const val EXISTS: Int = -2

@InternalKuicksilverApi
public actual fun checkPrivateDirectory(path: String) {
    Path(path).parent?.let { if (!SystemFileSystem.exists(it)) SystemFileSystem.createDirectories(it) }
    privateDirectoryProblem(path)?.let { throw IllegalArgumentException("$path refused: $it") }
}

@InternalKuicksilverApi
public actual fun createPrivateFile(
    directory: String,
    name: String,
): PrivateFileWriter? {
    requirePlainName(name)
    val path = Path(directory, name).toString()
    val fd = openExclusive(path)
    if (fd == EXISTS) return null
    if (fd < 0) throw IllegalArgumentException("$path cannot be created")
    val f = fdopen(fd, "wb") // stdio: the same signatures on every target (write() differs between POSIX and mingw)
    if (f == null) {
        close(fd)
        throw IllegalArgumentException("$path cannot be opened")
    }
    return StdioWriter(f)
}

private class StdioWriter(
    private val f: kotlinx.cinterop.CPointer<FILE>,
) : PrivateFileWriter {
    private var open = true

    override fun write(bytes: ByteArray) {
        check(open) { "closed" }
        if (bytes.isEmpty()) return
        val n = bytes.usePinned { fwrite(it.addressOf(0), 1u.convert(), bytes.size.convert(), f) }
        if (n.toLong() != bytes.size.toLong()) throw IllegalStateException("short write")
    }

    override fun close() {
        if (open) {
            open = false
            fclose(f)
        }
    }
}
