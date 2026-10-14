// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.annotations.InternalKuicksilverApi

/**
 * A file the library writes for diagnostics (qlog traces), opened by [createPrivateFile]. [write] appends; [close] flushes and
 * releases the descriptor. Not thread-safe: one writer at a time.
 */
@InternalKuicksilverApi
public interface PrivateFileWriter : AutoCloseable {
    /** Appends [bytes]; throws when the write fails. */
    public fun write(bytes: ByteArray)
}

/**
 * Makes sure [path] is a directory the library may write diagnostics into, creating it (and its parents) when missing, the
 * last component owner-only (0700). Refused with [IllegalArgumentException] naming the reason: a symbolic link, not a
 * directory, owned by another user, or writable by group or others without the sticky bit (another user could then replace
 * the files in it). Windows checks only that it is a directory and not a reparse point (junction or symlink); the JVM
 * without a POSIX view (Windows) only that it is a real directory; Android below API 26 (no `java.nio.file`) refuses.
 */
@InternalKuicksilverApi
public expect fun checkPrivateDirectory(path: String)

/**
 * Creates [name] (one path component) inside [directory] exclusively, owner-only (0600): it fails when anything already
 * exists under that name, a symbolic link or a FIFO included, so a planted name is never followed, truncated or blocked on.
 * Returns null when the name exists; throws [IllegalArgumentException] for a name with a separator and for other failures.
 * Call [checkPrivateDirectory] first.
 */
@InternalKuicksilverApi
public expect fun createPrivateFile(
    directory: String,
    name: String,
): PrivateFileWriter?

internal fun requirePlainName(name: String) {
    require(name.isNotEmpty() && name != "." && name != ".." && name.none { it == '/' || it == '\\' || it == '\u0000' }) {
        "not a plain file name: $name"
    }
}
