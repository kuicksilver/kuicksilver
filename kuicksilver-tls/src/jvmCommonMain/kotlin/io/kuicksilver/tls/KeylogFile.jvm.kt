// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(DelicateKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
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
 * Opens (creating it with mode 0600 when missing) and checks the key log file: a symlink, a non-regular file or a file owned
 * by another user is refused ([IllegalArgumentException]), lingering group/other bits of an existing file are cleared. Returns
 * nothing; every write reopens the file without following links, so a swap after this check lands nowhere either.
 */
private fun checkKeylogPath(p: Path) {
    try {
        Files.newByteChannel(p, OPEN_APPEND, PosixFilePermissions.asFileAttribute(OWNER_ONLY)).close()
        val attrs = Files.readAttributes(p, java.nio.file.attribute.PosixFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (!attrs.isRegularFile) throw IllegalArgumentException("keylog path $p is not a regular file")
        val me = p.fileSystem.userPrincipalLookupService.lookupPrincipalByName(System.getProperty("user.name"))
        if (attrs.owner() != me) throw IllegalArgumentException("keylog file $p is owned by ${attrs.owner().name}, not by this user")
        val perms = attrs.permissions()
        if (perms.any { it !in OWNER_ONLY && it != PosixFilePermission.OWNER_EXECUTE }) Files.setPosixFilePermissions(p, OWNER_ONLY)
    } catch (e: UnsupportedOperationException) {
        // no POSIX view (Windows, some mounts): nothing can vouch for the file, and secrets do not go into an unchecked one
        throw IllegalArgumentException("keylog file $p: the file system has no POSIX permissions, refusing to log secrets there", e)
    } catch (e: IOException) {
        throw IllegalArgumentException("keylog file $p cannot be opened: ${e.message}", e)
    }
}

public actual fun keylogFile(path: String): KeylogSink {
    val p = Paths.get(path)
    checkKeylogPath(p)
    return KeylogSink { line ->
        try {
            Files.newByteChannel(p, OPEN_APPEND, PosixFilePermissions.asFileAttribute(OWNER_ONLY)).use {
                it.write(ByteBuffer.wrap((line + "\n").toByteArray()))
            }
        } catch (e: IOException) {
            System.err.println("kuicksilver: keylog line dropped, $p: ${e.message}") // the handshake goes on; the secret is not retried
        }
    }
}

public actual fun keylogFromEnvironment(): KeylogSink? = System.getenv("SSLKEYLOGFILE")?.takeIf { it.isNotBlank() }?.let { keylogFile(it) }
