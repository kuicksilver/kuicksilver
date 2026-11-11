// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, ExperimentalKuicksilverApi::class)

package io.kuicksilver.native

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.AclEntry
import java.nio.file.attribute.AclEntryFlag
import java.nio.file.attribute.AclEntryPermission
import java.nio.file.attribute.AclEntryType
import java.nio.file.attribute.AclFileAttributeView
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.FileAttribute
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFileAttributes
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.nio.file.attribute.UserPrincipal
import java.security.MessageDigest
import java.util.EnumSet

/**
 * Loads `libksl` on the JVM: an explicit path (`-Dkuicksilver.native.path`), otherwise the jar resource
 * extracted into an owner-only directory and checked against the SHA-256 manifest; `-Dkuicksilver.native.system=true` falls
 * back to `System.loadLibrary("ksl")`. The ABI is checked right after loading. One attempt per process, its outcome kept
 * (see [availability]). The library is never unloaded.
 */
public actual object KslLoader {
    private val state =
        KslLoadState {
            JvmLoader.attempt(
                System.getProperties().entries.associate { it.key.toString() to it.value.toString() },
                KslLoader::class.java.classLoader,
            )
        }

    public actual fun ensureLoaded() {
        state.ensureLoaded()
    }

    @ExperimentalKuicksilverApi
    public actual fun availability(): NativeAvailability = state.availability()

    @ExperimentalKuicksilverApi
    public actual fun isAvailable(): Boolean = availability() is NativeAvailability.Available
}

/** Testable pieces of the loader; internal, reached by this module's tests. */
internal object JvmLoader {
    /** The whole load sequence of [KslLoader] (load, ABI, init) with resources looked up in [classLoader]; never throws. */
    internal fun attempt(
        props: Map<String, String>,
        classLoader: ClassLoader,
    ): NativeAvailability =
        attemptLoad {
            load(props, classLoader)
            checkAbi(KSL_ABI_VERSION)
            checkInit(KslNative.init())
        }

    private const val PATH = "kuicksilver.native.path"
    private const val WORKDIR = "kuicksilver.native.workdir"
    private const val SYSTEM = "kuicksilver.native.system"

    /**
     * Loads the library as the system properties in [props] say: `kuicksilver.native.path` (that file, loaded as given, no
     * hash check), else `kuicksilver.native.system=true` (`System.loadLibrary("ksl")`, also unchecked), else the jar resource,
     * extracted to [privateWorkDir] and checked against the SHA-256 manifest. Throws [KslException.NativeLoad]; the ABI is
     * checked separately by [checkAbi].
     */
    fun load(props: Map<String, String>) {
        load(props, KslLoader::class.java.classLoader)
    }

    internal fun load(
        props: Map<String, String>,
        classLoader: ClassLoader,
    ) {
        val explicit = resolveExplicitPath(props)
        try {
            when {
                explicit != null -> System.load(explicit.absolutePath)
                props[SYSTEM] == "true" -> System.loadLibrary("ksl")
                else -> System.load(extractResource(props, classLoader).absolutePath)
            }
        } catch (e: UnsatisfiedLinkError) {
            throw KslException.NativeLoad(
                JvmNativeNames.os,
                JvmNativeNames.classifier,
                "${e.message}; if the work directory is mounted noexec set -D$WORKDIR",
                e,
            )
        }
    }

    /** The file named by `kuicksilver.native.path` in [props], or null without it; [KslException.NativeLoad] when it is no regular file. */
    fun resolveExplicitPath(props: Map<String, String>): File? {
        val p = props[PATH] ?: return null
        val f = File(p)
        if (!f.isFile) throw KslException.NativeLoad(JvmNativeNames.os, JvmNativeNames.classifier, "$PATH=$p does not exist")
        return f
    }

    /** Maps ksl_init codes (system-OpenSSL builds, Linux only) to exceptions. */
    fun checkInit(code: Int) {
        when (code) {
            0 -> return

            -2 -> throw KslException.Version(KslNative.version(), "OpenSSL 3.5+ (not 4.x)")

            -3 -> throw KslException.MissingSymbol("SSL_set_quic_tls_cbs")

            -4 -> throw KslException.NativeLoad(
                JvmNativeNames.os,
                JvmNativeNames.classifier,
                "SSLKEYLOGFILE is set and the system libssl may honour it; unset it (keylog)",
            )

            else -> throw KslException.NativeLoad(JvmNativeNames.os, JvmNativeNames.classifier, "ksl_init failed ($code)")
        }
    }

    /** Throws [KslException.AbiMismatch] unless the loaded library reports ABI [expected]; call it after [load]. */
    fun checkAbi(expected: Int) {
        val native = KslNative.abiVersion()
        if (native != expected) throw KslException.AbiMismatch(native, expected)
    }

    /**
     * The directory the jar resource is extracted to: `kuicksilver.native.workdir` from [props], else
     * `<java.io.tmpdir>/kuicksilver-native-<user.name>`. It is created when missing ([createWorkDir]) and then checked by
     * [checkWorkDir]: a symbolic link or other reparse point, something other than a directory, a directory owned by another
     * user or one that keeps access for others after it is made owner-only fails with [KslException.NativeLoad]
     * (`IntegrityMismatch`). The default directory is also refused when a directory above it lets another user rename it
     * ([checkAncestors]); for `kuicksilver.native.workdir` the directories above are the operator's choice. Set the property
     * when the temporary directory is mounted `noexec`.
     */
    fun privateWorkDir(props: Map<String, String> = emptyMap()): File {
        val explicit = props[WORKDIR]
        val base =
            explicit?.let(::File)
                ?: File(System.getProperty("java.io.tmpdir"), "kuicksilver-native-" + System.getProperty("user.name"))
        val dir = base.toPath()
        createWorkDir(dir)
        val me = currentUser(dir)
        checkWorkDir(dir, me)
        if (explicit == null) checkAncestors(dir, me)
        return base
    }

    /**
     * Creates [dir] when nothing is at that path, together with any missing parent, each in one call with owner-only access:
     * `rwx------` where the file system has a POSIX view, an ACL with one entry for this process's user where it has an ACL
     * view (Windows), never under the umask or the inherited ACL first. An existing entry, including a symbolic link, is left
     * for [checkWorkDir] to judge.
     */
    internal fun createWorkDir(dir: Path) {
        if (Files.exists(dir, LinkOption.NOFOLLOW_LINKS)) return
        val attrs = ownerOnlyDirectory(dir)
        dir.toAbsolutePath().parent?.let { Files.createDirectories(it, *attrs) }
        try {
            Files.createDirectory(dir, *attrs)
        } catch (_: FileAlreadyExistsException) {
            // another JVM won the race; checkWorkDir decides whether it is acceptable
        }
    }

    private fun hasPosix(p: Path): Boolean = "posix" in p.fileSystem.supportedFileAttributeViews()

    private fun hasAcl(p: Path): Boolean = "acl" in p.fileSystem.supportedFileAttributeViews()

    /** The attribute that creates a directory owner-only on [dir]'s file system; none where it has neither view. */
    private fun ownerOnlyDirectory(dir: Path): Array<FileAttribute<*>> =
        when {
            hasPosix(dir) -> {
                arrayOf(PosixFilePermissions.asFileAttribute(OWNER_ONLY))
            }

            hasAcl(dir) -> {
                currentUser(dir.toAbsolutePath().parent ?: dir)?.let { arrayOf(aclAttribute(ownerOnlyAcl(it, true))) }
                    ?: emptyArray()
            }

            else -> {
                emptyArray()
            }
        }

    private fun aclAttribute(acl: List<AclEntry>): FileAttribute<List<AclEntry>> =
        object : FileAttribute<List<AclEntry>> {
            override fun name() = "acl:acl"

            override fun value() = acl
        }

    /**
     * Refuses [dir] as the extraction directory unless it is a real directory (not a symbolic link or other reparse point)
     * owned by [expectedOwner] and private to it: anyone else who may write to it could replace the library between the
     * manifest check and `System.load`. With a POSIX view group/other permissions are stripped first and a directory that
     * keeps them (a sticky or ACL-managed mount) is refused; with an ACL view (Windows) the ACL is replaced by one entry for
     * the owner and a directory that still allows anyone else anything is refused. When this process's user cannot be
     * determined ([expectedOwner] null) the directory is refused rather than left unchecked. A file system with neither view
     * gets only the directory check.
     */
    internal fun checkWorkDir(
        dir: Path,
        expectedOwner: UserPrincipal? = currentUser(dir),
    ) {
        fun refuse(why: String): Nothing = refuseWorkDir(dir, why)
        if (Files.isSymbolicLink(dir)) refuse("is a symbolic link")
        val basic =
            try {
                Files.readAttributes(dir, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            } catch (e: IOException) {
                refuse("cannot be read: ${e.message}")
            }
        if (basic.isSymbolicLink || (basic.isDirectory && basic.isOther)) refuse("is a symbolic link") // or a Windows junction
        if (!basic.isDirectory) refuse("is not a directory")
        val posix = hasPosix(dir)
        val acl = !posix && hasAcl(dir)
        if (!posix && !acl) return
        if (expectedOwner == null) refuse("cannot be checked: the user of this process cannot be determined")
        if (posix) {
            val view = Files.getFileAttributeView(dir, PosixFileAttributeView::class.java, LinkOption.NOFOLLOW_LINKS)
            val owner = view.readAttributes().owner()
            if (owner != expectedOwner) refuse("is owned by ${owner.name}, not by this user")
            try {
                view.setPermissions(OWNER_ONLY) // through the view: never follows a link put there meanwhile
            } catch (_: IOException) {
            }
            val perms = view.readAttributes().permissions()
            if (perms.any { it !in OWNER_ONLY }) refuse("keeps group/other permissions ${PosixFilePermissions.toString(perms)}")
        } else {
            val view = Files.getFileAttributeView(dir, AclFileAttributeView::class.java, LinkOption.NOFOLLOW_LINKS)
            val owner = view.owner
            if (owner != expectedOwner) refuse("is owned by ${owner.name}, not by this user")
            try {
                view.acl = ownerOnlyAcl(owner, directory = true)
            } catch (_: IOException) {
            }
            val others = foreignAccess(view.acl, owner)
            if (others.isNotEmpty()) refuse("keeps group/other permissions for ${others.joinToString()}")
        }
    }

    private fun refuseWorkDir(
        dir: Path,
        why: String,
    ): Nothing =
        throw KslException.NativeLoad(
            JvmNativeNames.os,
            JvmNativeNames.classifier,
            "work directory $dir $why; set -D$WORKDIR to a directory only you own",
            null,
            NativeUnavailableReason.IntegrityMismatch,
        )

    /**
     * Refuses [dir] when a directory above it (resolved, so `/var` -> `/private/var` counts as `/private/var`) belongs to
     * someone other than root or [expectedOwner], or may be written by group or others without the sticky bit: either one
     * could rename the work directory and put another in its place between the checks and `System.load`. A sticky
     * world-writable directory (`/tmp`) passes, since there only the owner of an entry may rename it. Needs the `unix` view
     * (Linux, macOS); without it (Windows) nothing is checked here: the work directory's own ACL denies others the deletion
     * a rename needs.
     */
    internal fun checkAncestors(
        dir: Path,
        expectedOwner: UserPrincipal? = currentUser(dir),
    ) {
        if ("unix" !in dir.fileSystem.supportedFileAttributeViews()) return
        val parent = dir.toAbsolutePath().parent ?: return
        var p: Path? =
            try {
                parent.toRealPath()
            } catch (e: IOException) {
                refuseWorkDir(dir, "lies in $parent, which cannot be read: ${e.message}")
            }
        while (p != null) {
            val uid = Files.getAttribute(p, "unix:uid", LinkOption.NOFOLLOW_LINKS) as Int
            val mode = Files.getAttribute(p, "unix:mode", LinkOption.NOFOLLOW_LINKS) as Int
            val owner = Files.getOwner(p, LinkOption.NOFOLLOW_LINKS)
            if (uid != 0 && (expectedOwner == null || owner != expectedOwner)) {
                refuseWorkDir(dir, "lies in $p, owned by ${owner.name}, not by this user or root")
            }
            if (mode and GROUP_OTHER_WRITE != 0 && mode and STICKY == 0) {
                refuseWorkDir(dir, "lies in $p, writable by group or others without the sticky bit")
            }
            p = p.parent
        }
    }

    private const val GROUP_OTHER_WRITE = 0x12 // 0o022
    private const val STICKY = 0x200 // 0o1000

    private val OWNER_ONLY = PosixFilePermissions.fromString("rwx------")
    private val OWNER_ONLY_FILE = PosixFilePermissions.fromString("rw-------")

    /** The names of the principals other than [owner] that [acl] allows anything; deny entries take nothing away from the owner. */
    internal fun foreignAccess(
        acl: List<AclEntry>,
        owner: UserPrincipal,
    ): List<String> = acl.filter { it.type() == AclEntryType.ALLOW && it.principal() != owner }.map { it.principal().name }.distinct()

    /** One entry allowing [owner] everything; for a [directory] it is inherited by what is created inside. */
    internal fun ownerOnlyAcl(
        owner: UserPrincipal,
        directory: Boolean,
    ): List<AclEntry> =
        listOf(
            AclEntry
                .newBuilder()
                .setType(AclEntryType.ALLOW)
                .setPrincipal(owner)
                .setPermissions(EnumSet.allOf(AclEntryPermission::class.java))
                .apply { if (directory) setFlags(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT) }
                .build(),
        )

    /**
     * The principal this process creates files as: the owner of a file created now next to [near] (in it when it is a
     * directory), else in `java.io.tmpdir`, else the principal `user.name` names; null when none works. Not `user.name`
     * first: it is only a property, a uid without a passwd entry has no name to look up, and on Windows an elevated process
     * creates files owned by the Administrators group.
     */
    private fun currentUser(near: Path): UserPrincipal? {
        fun ownerOfNewFile(dir: Path?): UserPrincipal {
            val probe = if (dir == null) Files.createTempFile("ksl-owner", null) else Files.createTempFile(dir, "ksl-owner", null)
            try {
                return Files.getOwner(probe, LinkOption.NOFOLLOW_LINKS)
            } finally {
                Files.deleteIfExists(probe)
            }
        }
        val abs = near.toAbsolutePath()
        val here = if (Files.isDirectory(abs, LinkOption.NOFOLLOW_LINKS)) abs else abs.parent
        return runCatching { ownerOfNewFile(here?.takeIf { Files.isDirectory(it, LinkOption.NOFOLLOW_LINKS) } ?: error("no directory")) }
            .recoverCatching { ownerOfNewFile(null) }
            .recoverCatching { abs.fileSystem.userPrincipalLookupService.lookupPrincipalByName(System.getProperty("user.name")) }
            .getOrNull()
    }

    /**
     * Throws [KslException.NativeLoad] unless the SHA-256 of [file] equals the hash on the [manifest] line (`<hex> <path>`)
     * whose path ends with [entryName]; a file without an entry fails too, so a tampered or unlisted library never loads.
     */
    fun verifyAgainstManifest(
        file: File,
        manifest: String,
        entryName: String = file.name,
    ) {
        val expected =
            manifest
                .lines()
                .map { it.trim().split(Regex("\\s+")) }
                .firstOrNull { it.size >= 2 && it[1].endsWith(entryName) }
                ?.get(0)
                ?: throw KslException.NativeLoad(
                    JvmNativeNames.os,
                    JvmNativeNames.classifier,
                    "no sha256 entry for $entryName in the manifest",
                    null,
                    NativeUnavailableReason.IntegrityMismatch,
                )
        val actual = MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString("") { "%02x".format(it) }
        if (actual !=
            expected
        ) {
            throw KslException.NativeLoad(
                JvmNativeNames.os,
                JvmNativeNames.classifier,
                "sha256 mismatch for ${file.name}: resource was tampered with or corrupted",
                null,
                NativeUnavailableReason.IntegrityMismatch,
            )
        }
    }

    /**
     * Writes the library unless an identical, manifest-verified copy owned by this process's user, which nobody else may
     * write, is already there (another JVM may have it mapped); new content, or a replacement for any other copy, goes
     * through a new owner-only temp file (`rw-------`, created exclusively, never through a link) and an atomic rename. Where
     * the file system knows owners an undeterminable current user fails with [KslException.NativeLoad].
     */
    fun installLibrary(
        out: File,
        content: ByteArray,
        manifest: String,
    ): Unit = installLibrary(out, content, manifest, currentUser(out.toPath().toAbsolutePath().parent ?: out.toPath()))

    internal fun installLibrary(
        out: File,
        content: ByteArray,
        manifest: String,
        expectedOwner: UserPrincipal?,
    ) {
        val path = out.toPath()
        val posix = hasPosix(path)
        val acl = !posix && hasAcl(path)
        if ((posix || acl) && expectedOwner == null) {
            throw KslException.NativeLoad(
                JvmNativeNames.os,
                JvmNativeNames.classifier,
                "library ${out.name} cannot be installed: the user of this process cannot be determined",
                null,
                NativeUnavailableReason.IntegrityMismatch,
            )
        }
        val reusable =
            Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
                runCatching { (!posix && !acl) || onlyOwnerMayWrite(path, posix, expectedOwner!!) }.getOrDefault(false) &&
                runCatching { verifyAgainstManifest(out, manifest) }.isSuccess
        if (reusable) return
        val dir = path.toAbsolutePath().parent
        val attrs: Array<FileAttribute<*>> = if (posix) arrayOf(PosixFilePermissions.asFileAttribute(OWNER_ONLY_FILE)) else emptyArray()
        val tmp = dir.resolve("${out.name}.${java.util.UUID.randomUUID()}.tmp")
        try {
            // CREATE_NEW is O_CREAT | O_EXCL: it fails on any existing name, a link included; on Windows the file inherits
            // the work directory's owner-only ACL
            Files.newByteChannel(tmp, EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), *attrs).use { ch ->
                val buf = ByteBuffer.wrap(content)
                while (buf.hasRemaining()) ch.write(buf)
            } // fully written and closed before loading
            verifyAgainstManifest(tmp.toFile(), manifest, out.name)
            try {
                Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            Files.deleteIfExists(tmp)
        }
    }

    /** Whether [file] (not followed) belongs to [owner] and nobody else may write it: no group/other write bit, or no ACL entry for anyone else. */
    private fun onlyOwnerMayWrite(
        file: Path,
        posix: Boolean,
        owner: UserPrincipal,
    ): Boolean {
        if (posix) {
            val attrs = Files.readAttributes(file, PosixFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            return attrs.owner() == owner &&
                PosixFilePermission.GROUP_WRITE !in attrs.permissions() &&
                PosixFilePermission.OTHERS_WRITE !in attrs.permissions()
        }
        val view = Files.getFileAttributeView(file, AclFileAttributeView::class.java, LinkOption.NOFOLLOW_LINKS)
        return view.owner == owner && foreignWriters(view.acl, owner).isEmpty()
    }

    private val WRITE_PERMISSIONS =
        EnumSet.of(
            AclEntryPermission.WRITE_DATA,
            AclEntryPermission.APPEND_DATA,
            AclEntryPermission.WRITE_NAMED_ATTRS,
            AclEntryPermission.WRITE_ATTRIBUTES,
            AclEntryPermission.DELETE,
            AclEntryPermission.WRITE_ACL,
            AclEntryPermission.WRITE_OWNER,
        )

    /** The principals other than [owner] that [acl] allows to change the file (read access of others is fine for a library). */
    private fun foreignWriters(
        acl: List<AclEntry>,
        owner: UserPrincipal,
    ): List<AclEntry> =
        acl.filter {
            it.type() == AclEntryType.ALLOW && it.principal() != owner &&
                it.permissions().any { p -> p in WRITE_PERMISSIONS }
        }

    /**
     * Throws [KslException.NativeLoad] when the classpath carries several copies of the library resource with different
     * content (two Kuicksilver versions, a shaded copy), since which one loads would be an accident; identical copies pass.
     */
    fun checkDuplicates(contents: List<ByteArray>) {
        val hashes = contents.map { MessageDigest.getInstance("SHA-256").digest(it).toList() }.toSet()
        if (hashes.size >
            1
        ) {
            throw KslException.NativeLoad(
                JvmNativeNames.os,
                JvmNativeNames.classifier,
                "duplicate native resources with different content on the classpath",
                null,
                NativeUnavailableReason.IntegrityMismatch,
            )
        }
    }

    private fun extractResource(
        props: Map<String, String>,
        cl: ClassLoader,
    ): File {
        val name = JvmNativeNames.libraryFileName()
        val urls = cl.getResources(JvmNativeNames.RESOURCE_DIR + name).toList()
        if (urls.isEmpty()) {
            throw KslException.NativeLoad(
                JvmNativeNames.os,
                JvmNativeNames.classifier,
                "resource ${JvmNativeNames.RESOURCE_DIR}$name not on the classpath",
                null,
                NativeUnavailableReason.NoLibraryForPlatform,
            )
        }
        val bytes = urls.map { it.openStream().use { s -> s.readBytes() } }
        checkDuplicates(bytes)
        val manifest =
            cl.getResourceAsStream(JvmNativeNames.RESOURCE_DIR + "manifest.sha256")?.use { String(it.readBytes()) }
                ?: throw KslException.NativeLoad(
                    JvmNativeNames.os,
                    JvmNativeNames.classifier,
                    "manifest.sha256 missing",
                    null,
                    NativeUnavailableReason.IntegrityMismatch,
                )
        val dir = privateWorkDir(props)
        val out = File(dir, name)
        installLibrary(out, bytes[0], manifest)
        // the file stays: its name carries the ABI, its content was verified, and another JVM may be between its own check and System.load
        return out
    }
}
