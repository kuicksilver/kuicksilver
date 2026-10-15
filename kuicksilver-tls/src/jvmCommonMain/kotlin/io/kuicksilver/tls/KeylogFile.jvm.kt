// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(DelicateKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import java.io.Closeable
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.SeekableByteChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFileAttributes
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions

private val OWNER_ONLY = PosixFilePermissions.fromString("rw-------")
private val OPEN_APPEND =
    setOf<java.nio.file.OpenOption>(
        StandardOpenOption.CREATE,
        StandardOpenOption.APPEND,
        StandardOpenOption.WRITE,
        LinkOption.NOFOLLOW_LINKS,
    )

/**
 * Opens (creating it with mode 0600 when missing) the key log file once and checks it right after opening: a symlink, a
 * non-regular file, a file with more than one hard link or a file owned by another user is refused ([IllegalArgumentException]), lingering group/other bits of an
 * existing file are cleared. The returned channel is the one every line is written through, so a file removed and recreated
 * at the path later (by anyone) never receives a line: the lines keep going to the inode that was checked.
 */
private fun openKeylogChannel(p: Path): SeekableByteChannel {
    // NIO cannot open with O_NONBLOCK, and opening a FIFO for writing blocks until a reader appears: refuse anything that is
    // not a regular file before the open (the check after it covers a swap in between, except a FIFO swapped in at that
    // instant by a user who can replace names in the directory)
    try {
        val before = Files.readAttributes(p, java.nio.file.attribute.BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (!before.isRegularFile) throw IllegalArgumentException("keylog path $p is not a regular file")
    } catch (_: java.nio.file.NoSuchFileException) {
        // created by the open below
    } catch (e: IOException) {
        throw IllegalArgumentException("keylog file $p cannot be checked: ${e.message}", e)
    }
    val ch =
        try {
            Files.newByteChannel(p, OPEN_APPEND, PosixFilePermissions.asFileAttribute(OWNER_ONLY))
        } catch (e: UnsupportedOperationException) {
            throw noPosix(p, e)
        } catch (e: IOException) {
            throw IllegalArgumentException("keylog file $p cannot be opened: ${e.message}", e)
        }
    try {
        val attrs = Files.readAttributes(p, PosixFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (!attrs.isRegularFile) throw IllegalArgumentException("keylog path $p is not a regular file")
        val me =
            processUser()
                ?: throw IllegalArgumentException("keylog file $p cannot be checked: the user of this process is unknown")
        if (attrs.owner() != me) throw IllegalArgumentException("keylog file $p is owned by ${attrs.owner().name}, not by this user")
        if ("unix" in p.fileSystem.supportedFileAttributeViews() &&
            (Files.getAttribute(p, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toInt() != 1
        ) {
            throw IllegalArgumentException("keylog file $p has other hard links")
        }
        val perms = attrs.permissions()
        if (perms.any { it !in OWNER_ONLY && it != PosixFilePermission.OWNER_EXECUTE }) Files.setPosixFilePermissions(p, OWNER_ONLY)
        return ch
    } catch (e: Throwable) {
        ch.close()
        throw when (e) {
            // no POSIX view (Windows, some mounts): nothing can vouch for the file, and secrets do not go into an unchecked one
            is UnsupportedOperationException -> noPosix(p, e)

            is IOException -> IllegalArgumentException("keylog file $p cannot be checked: ${e.message}", e)

            else -> e
        }
    }
}

private fun noPosix(
    p: Path,
    e: Throwable,
) = IllegalArgumentException("keylog file $p: the file system has no POSIX permissions, refusing to log secrets there", e)

/**
 * The JVM key log: one channel, opened and checked when the sink is created, kept for the sink's lifetime. [close] releases
 * the descriptor; an unclosed sink keeps it until the channel is collected or the process exits.
 */
private class KeylogFileSink(
    private val path: Path,
    private val channel: SeekableByteChannel,
) : KeylogSink,
    Closeable {
    override fun log(line: String) {
        try {
            val buf = ByteBuffer.wrap((line + "\n").toByteArray())
            synchronized(channel) { while (buf.hasRemaining()) channel.write(buf) }
        } catch (e: IOException) {
            System.err.println("kuicksilver: keylog line dropped, $path: ${e.message}") // the handshake goes on; the secret is not retried
        }
    }

    override fun close() = channel.close()
}

public actual fun keylogFile(path: String): KeylogSink = openKeylogFile(path, HAS_NIO)

/** `java.nio.file`, which the checks need, is missing on Android API 24-25 (it arrived in API 26). */
private val HAS_NIO: Boolean =
    try {
        Class.forName("java.nio.file.Files")
        true
    } catch (_: ClassNotFoundException) {
        false
    }

/** [keylogFile] with the platform check as a parameter (tests); nothing below touches `java.nio.file` when [hasNio] is false. */
internal fun openKeylogFile(
    path: String,
    hasNio: Boolean,
): KeylogSink {
    // without java.nio.file nothing can vouch for the file (owner, links, mode), and secrets do not go into an unchecked one
    require(hasNio) { "keylog file $path: java.nio.file is unavailable (Android below API 26), refusing to log secrets there" }
    return openNioKeylogFile(path)
}

private fun openNioKeylogFile(path: String): KeylogSink {
    val p = Paths.get(path)
    return KeylogFileSink(p, openKeylogChannel(p))
}

public actual fun keylogFromEnvironment(): KeylogSink? = System.getenv("SSLKEYLOGFILE")?.takeIf { it.isNotBlank() }?.let { keylogFile(it) }
