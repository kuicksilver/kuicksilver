// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.InternalKuicksilverApi
import java.io.IOException
import java.io.OutputStream
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFileAttributes
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions

/** `java.nio.file`, which the checks need, is missing on Android API 24-25 (it arrived in API 26). */
private val HAS_NIO_FILES: Boolean =
    try {
        Class.forName("java.nio.file.Files")
        true
    } catch (_: ClassNotFoundException) {
        false
    }

@InternalKuicksilverApi
public actual fun checkPrivateDirectory(path: String) {
    require(HAS_NIO_FILES) { "$path: java.nio.file is unavailable (Android below API 26), refusing to write diagnostics" }
    checkNioDirectory(Paths.get(path))
}

private fun checkNioDirectory(dir: Path) {
    val posix = "posix" in dir.fileSystem.supportedFileAttributeViews()
    if (!Files.exists(dir, LinkOption.NOFOLLOW_LINKS)) {
        dir.parent?.let { Files.createDirectories(it) }
        try {
            if (posix) {
                Files.createDirectory(dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            } else {
                Files.createDirectory(dir)
            }
        } catch (_: FileAlreadyExistsException) {
            // made meanwhile by someone else: the checks below decide
        }
    }
    if (Files.isSymbolicLink(dir)) throw IllegalArgumentException("$dir is a symbolic link")
    if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) throw IllegalArgumentException("$dir is not a directory")
    if (!posix) return
    val attrs = Files.readAttributes(dir, PosixFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    val me = processUser() ?: throw IllegalArgumentException("$dir cannot be checked: the user of this process cannot be determined")
    if (attrs.owner() != me) throw IllegalArgumentException("$dir is owned by ${attrs.owner().name}, not by this user")
    val perms = attrs.permissions()
    if (PosixFilePermission.GROUP_WRITE in perms || PosixFilePermission.OTHERS_WRITE in perms) {
        // the sticky bit (others cannot remove or rename our files) is visible only through the "unix" view
        val sticky =
            "unix" in dir.fileSystem.supportedFileAttributeViews() &&
                (Files.getAttribute(dir, "unix:mode", LinkOption.NOFOLLOW_LINKS) as Int) and 0x200 != 0
        if (!sticky) throw IllegalArgumentException("$dir is writable by group or others without the sticky bit")
    }
}

/**
 * The user this process creates files as: the owner of a file created now in `java.io.tmpdir`, else the principal
 * `user.name` names; null when neither works. Not `user.name` first: Android sets it to a name that is not the app's
 * uid, and on any JVM it is only a property (`-Duser.name=`), while the owner of a new file is the effective uid.
 */
internal fun processUser(): java.nio.file.attribute.UserPrincipal? =
    runCatching {
        val probe = Files.createTempFile("ksl-owner", null)
        try {
            Files.getOwner(probe, LinkOption.NOFOLLOW_LINKS)
        } finally {
            Files.deleteIfExists(probe)
        }
    }.recoverCatching {
        java.nio.file.FileSystems
            .getDefault()
            .userPrincipalLookupService
            .lookupPrincipalByName(System.getProperty("user.name"))
    }.getOrNull()

@InternalKuicksilverApi
public actual fun createPrivateFile(
    directory: String,
    name: String,
): PrivateFileWriter? {
    requirePlainName(name)
    require(HAS_NIO_FILES) { "$directory: java.nio.file is unavailable (Android below API 26), refusing to write diagnostics" }
    val p = Paths.get(directory, name)
    val options = arrayOf<java.nio.file.OpenOption>(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)
    val out: OutputStream =
        try {
            if ("posix" in p.fileSystem.supportedFileAttributeViews()) {
                // CREATE_NEW is O_CREAT | O_EXCL: it fails on any existing name, a dangling symlink or a FIFO included
                Files
                    .newByteChannel(
                        p,
                        options.toSet(),
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")),
                    ).let {
                        java.nio.channels.Channels
                            .newOutputStream(it)
                    }
            } else {
                Files.newOutputStream(p, *options)
            }
        } catch (_: FileAlreadyExistsException) {
            return null
        } catch (e: IOException) {
            throw IllegalArgumentException("$p cannot be created: ${e.message}", e)
        }
    val buffered = out.buffered(64 * 1024)
    return object : PrivateFileWriter {
        override fun write(bytes: ByteArray) = buffered.write(bytes)

        override fun close() = buffered.close()
    }
}
