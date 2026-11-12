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
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.AclEntry
import java.nio.file.attribute.AclEntryFlag
import java.nio.file.attribute.AclEntryPermission
import java.nio.file.attribute.AclEntryType
import java.nio.file.attribute.AclFileAttributeView
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.FileAttribute
import java.nio.file.attribute.GroupPrincipal
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
     * extracted to a work directory ([workDirs]) and checked against the SHA-256 manifest. Throws [KslException.NativeLoad]; the ABI is
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
                else -> extractAndLoad(props, classLoader)
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

    /** A work directory ready for the library; [fresh] when it was made for this process only (removed at exit where possible). */
    internal class PreparedDir(
        val dir: Path,
        val fresh: Boolean,
    )

    /**
     * The directories the jar resource may be extracted to, best first, each created and checked only when reached:
     * - `kuicksilver.native.workdir` from [props]: only that directory. It is created owner-only when missing and refused
     *   ([KslException.NativeLoad], `IntegrityMismatch`) when it is a symbolic link, no directory, owned by another user or
     *   keeps group/other permissions ([checkWorkDir]); the directories above it are the operator's choice.
     * - otherwise `<java.io.tmpdir>/kuicksilver-native-<user.name>` (with `-admin` for an elevated Windows process, whose files
     *   belong to the Administrators group), built on the resolved temporary directory. When a directory above it would let
     *   another user rename it and put another in its place ([ancestorRisk]), a private location of this user comes first:
     *   `$XDG_RUNTIME_DIR/kuicksilver-native`, then the user's cache directory; the temporary directory stays the last
     *   resort, used with a warning. When the default directory itself is unusable (planted by another user, a link, wrong
     *   permissions) the process uses a new private directory next to it, with a warning, instead of failing.
     */
    internal fun workDirs(
        props: Map<String, String>,
        env: Map<String, String>,
        warn: (String) -> Unit,
    ): List<() -> PreparedDir> {
        props[WORKDIR]?.let { explicit ->
            val dir = Paths.get(explicit).toAbsolutePath()
            return listOf({
                createWorkDir(dir)
                checkWorkDir(dir, currentUser(dir), strictAcl = false, warn = warn)
                PreparedDir(dir, fresh = false)
            })
        }
        val tmp = resolved(Paths.get(props["java.io.tmpdir"] ?: System.getProperty("java.io.tmpdir")))
        val me = currentUser(tmp)
        val primary = tmp.resolve(defaultDirName(props["user.name"] ?: System.getProperty("user.name"), me))
        val default = { prepareDefault(primary, tmp, warn) }
        val risk = ancestorRisk(primary, me) ?: return listOf(default)
        val alternatives =
            listOfNotNull(runtimeDir(env, me), cacheDir(props, env, me)).map { dir ->
                {
                    createWorkDir(dir)
                    checkWorkDir(dir, currentUser(dir))
                    PreparedDir(dir, fresh = false)
                }
            }
        val lastResort = {
            warn(
                "native library work directory $primary: $risk, so another user could replace the library before it is loaded; " +
                    "set -D$WORKDIR to a directory only you can write to",
            )
            default()
        }
        return alternatives + lastResort
    }

    /** The default directory's name: per user, and per elevation on Windows (an elevated process's files belong to Administrators). */
    internal fun defaultDirName(
        userName: String,
        me: UserPrincipal?,
    ): String = "kuicksilver-native-$userName" + if (me is GroupPrincipal) "-admin" else ""

    private fun prepareDefault(
        primary: Path,
        tmp: Path,
        warn: (String) -> Unit,
    ): PreparedDir {
        sweepStaleFreshDirs(primary, tmp)
        try {
            createWorkDir(primary)
            checkWorkDir(primary, currentUser(primary))
            return PreparedDir(primary, fresh = false)
        } catch (e: KslException.NativeLoad) {
            val fresh = Files.createTempDirectory(tmp, "${primary.fileName}-", *ownerOnlyDirectory(tmp.resolve("${primary.fileName}-")))
            checkWorkDir(fresh, currentUser(fresh))
            warn("${e.reason.substringBefore("; set -D")}; this process uses the new private directory $fresh instead")
            return PreparedDir(fresh, fresh = true)
        }
    }

    /**
     * Removes, best effort, the per-process directories `<primary>-*` an earlier process left in [tmp]: owned by this user,
     * real directories, untouched for [STALE_AFTER_MS] (a process that has just created one may be about to load from it),
     * holding only regular files. On Windows a library still loaded by a running process cannot be deleted: that directory
     * stays until a later start. Every failure is ignored.
     */
    internal fun sweepStaleFreshDirs(
        primary: Path,
        tmp: Path,
        now: Long = System.currentTimeMillis(),
    ) {
        val me = currentUser(tmp) ?: return
        runCatching {
            Files.newDirectoryStream(tmp, "${primary.fileName}-*").use { entries ->
                for (dir in entries) {
                    runCatching {
                        val attrs = Files.readAttributes(dir, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                        if (!attrs.isDirectory || attrs.isOther) return@runCatching
                        if (now - attrs.lastModifiedTime().toMillis() < STALE_AFTER_MS) return@runCatching
                        if (Files.getOwner(dir, LinkOption.NOFOLLOW_LINKS) != me) return@runCatching
                        Files.newDirectoryStream(dir).use { files ->
                            for (f in files) {
                                if (Files.isRegularFile(f, LinkOption.NOFOLLOW_LINKS)) runCatching { Files.delete(f) }
                            }
                        }
                        Files.delete(dir)
                    }
                }
            }
        }
    }

    private const val STALE_AFTER_MS = 10 * 60 * 1000L

    /** `$XDG_RUNTIME_DIR/kuicksilver-native` when that directory is this user's, private, and safe from above; else null. */
    private fun runtimeDir(
        env: Map<String, String>,
        me: UserPrincipal?,
    ): Path? {
        val base = env["XDG_RUNTIME_DIR"]?.let { Paths.get(it) }?.takeIf { it.isAbsolute } ?: return null
        return runCatching {
            val attrs = Files.readAttributes(base, PosixFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            val dir = base.resolve("kuicksilver-native")
            dir.takeIf {
                attrs.isDirectory &&
                    attrs.owner() == me &&
                    attrs.permissions().all { p -> p in OWNER_ONLY } &&
                    ancestorRisk(dir, me) == null
            }
        }.getOrNull()
    }

    /** The user's cache directory for the library (`$XDG_CACHE_HOME` or `~/.cache` on Linux, `~/Library/Caches` on macOS) when safe from above; else null. */
    private fun cacheDir(
        props: Map<String, String>,
        env: Map<String, String>,
        me: UserPrincipal?,
    ): Path? {
        val home = (props["user.home"] ?: System.getProperty("user.home"))?.let { Paths.get(it) }?.takeIf { it.isAbsolute }
        val base =
            when (JvmNativeNames.os) {
                "osx" -> home?.resolve("Library/Caches")
                else -> env["XDG_CACHE_HOME"]?.let { Paths.get(it) }?.takeIf { it.isAbsolute } ?: home?.resolve(".cache")
            } ?: return null
        val dir = base.resolve("kuicksilver-native")
        return dir.takeIf { runCatching { ancestorRisk(dir, me) == null }.getOrDefault(false) }
    }

    /** [p] with its links resolved, as far as it exists (the rest appended); [p] made absolute when nothing of it resolves. */
    private fun resolved(p: Path): Path {
        val abs = p.toAbsolutePath()
        var existing: Path? = abs
        while (existing != null && !Files.exists(existing)) existing = existing.parent
        if (existing == null) return abs
        return runCatching { existing.toRealPath().resolve(existing.relativize(abs)) }.getOrDefault(abs)
    }

    /**
     * The first work directory that can be prepared ([workDirs]); the failure of the last one when none can. Tests and
     * callers that only need the directory use it; the loader itself also moves on when `System.load` fails in one.
     */
    fun privateWorkDir(
        props: Map<String, String> = emptyMap(),
        env: Map<String, String> = System.getenv(),
        warn: (String) -> Unit = ::warnOnStderr,
    ): File {
        var failure: Exception? = null
        for (prepare in workDirs(props, env, warn)) {
            try {
                return prepare().dir.toFile()
            } catch (e: KslException.NativeLoad) {
                failure = failure ?: e
            } catch (e: IOException) {
                failure = failure ?: e
            }
        }
        throw failure ?: IllegalStateException("no work directory")
    }

    /** Warnings go to the `System.Logger` "io.kuicksilver.native" (java.util.logging by default, on standard error). */
    internal fun warnOnStderr(message: String) {
        System.getLogger("io.kuicksilver.native").log(System.Logger.Level.WARNING, message)
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

    /** Whether the file store [p] is (or would be) on keeps ACLs: NTFS does, FAT, exFAT and some network shares do not. */
    private fun hasAcl(p: Path): Boolean {
        var existing: Path? = p.toAbsolutePath()
        while (existing != null && !Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) existing = existing.parent
        if (existing == null) return false
        return runCatching { Files.getFileStore(existing).supportsFileAttributeView(AclFileAttributeView::class.java) }.getOrDefault(false)
    }

    /** The attribute that creates a directory owner-only on [dir]'s file system; none where it has neither view. */
    private fun ownerOnlyDirectory(dir: Path): Array<FileAttribute<*>> =
        when {
            hasPosix(dir) -> {
                arrayOf(PosixFilePermissions.asFileAttribute(OWNER_ONLY))
            }

            hasAcl(dir) -> {
                currentUser(dir.toAbsolutePath().parent ?: dir)
                    ?.let { arrayOf<FileAttribute<*>>(aclAttribute(ownerOnlyAcl(it, true))) }
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
     * Refuses [dir] as the extraction directory unless it is a real directory (not a symbolic link) owned by [expectedOwner]
     * and private to it: anyone else who may write to it could replace the library between the manifest check and
     * `System.load`. With a POSIX view group/other permissions are stripped first and a directory that keeps them (a sticky
     * or ACL-managed mount) is refused; an undeterminable user ([expectedOwner] null) is refused too. With an ACL view
     * (Windows) the ACL is replaced by one entry for the owner; a junction, another owner, or an ACL that still allows
     * someone else (SYSTEM, Administrators and TrustedInstaller aside) is refused when [strictAcl], else reported through
     * [warn] (an explicit `kuicksilver.native.workdir`, which 0.2 accepted). A file system with neither view gets only the
     * directory check. Attributes that cannot be read give the refusal "cannot be read".
     */
    internal fun checkWorkDir(
        dir: Path,
        expectedOwner: UserPrincipal? = currentUser(dir),
        strictAcl: Boolean = true,
        warn: (String) -> Unit = ::warnOnStderr,
    ) {
        fun refuse(why: String): Nothing = refuseWorkDir(dir, why)

        fun windows(why: String) {
            if (strictAcl) refuse(why) else warn("work directory $dir $why; another user may be able to replace the library")
        }
        val basic =
            try {
                Files.readAttributes(dir, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            } catch (e: IOException) {
                refuse("cannot be read: ${e.message}")
            }
        if (basic.isSymbolicLink) refuse("is a symbolic link")
        if (!basic.isDirectory) refuse("is not a directory")
        val posix = hasPosix(dir)
        val acl = !posix && hasAcl(dir)
        if (!posix && !acl) return
        if (expectedOwner == null) refuse("cannot be checked: the user of this process cannot be determined")
        try {
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
                if (basic.isOther) return windows("is a junction") // a directory reparse point that is no symbolic link
                val view = Files.getFileAttributeView(dir, AclFileAttributeView::class.java, LinkOption.NOFOLLOW_LINKS)
                val owner = view.owner
                if (owner != expectedOwner && !isTrustedWindowsPrincipal(owner)) {
                    return windows("is owned by ${owner.name}, not by this user")
                }
                try {
                    view.acl = ownerOnlyAcl(expectedOwner, directory = true)
                } catch (_: IOException) {
                }
                val others = foreignAccess(view.acl, expectedOwner)
                if (others.isNotEmpty()) windows("keeps group/other permissions for ${others.joinToString()}")
            }
        } catch (e: IOException) {
            refuse("cannot be read: ${e.message}")
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
     * Why a directory above [dir] would let another user rename [dir] and put another in its place between the checks and
     * `System.load`, or null when none does: the first existing directory above it (resolved) and each one up to `/` must
     * belong to root or [me], and must not be writable by others, nor by a group other than root's or [me]'s own (a user
     * private group), unless it has the sticky bit (`/tmp`). Needs the `unix` view (Linux, macOS); elsewhere (Windows) null:
     * there the parent's ACL is not inspected. Unreadable attributes count as a risk.
     */
    internal fun ancestorRisk(
        dir: Path,
        me: UserPrincipal?,
    ): String? {
        if ("unix" !in dir.fileSystem.supportedFileAttributeViews()) return null
        var p: Path? = dir.toAbsolutePath().parent
        while (p != null && !Files.exists(p, LinkOption.NOFOLLOW_LINKS)) p = p.parent
        p = p?.let { runCatching { it.toRealPath() }.getOrElse { e -> return "$p cannot be read (${e.message})" } }
        while (p != null) {
            val risk =
                try {
                    val posix = Files.readAttributes(p, PosixFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                    ancestorRisk(
                        p.toString(),
                        uid = Files.getAttribute(p, "unix:uid", LinkOption.NOFOLLOW_LINKS) as Int,
                        owner = posix.owner().name,
                        ownerIsMe = me != null && posix.owner() == me,
                        gid = Files.getAttribute(p, "unix:gid", LinkOption.NOFOLLOW_LINKS) as Int,
                        groupIsMine = me != null && posix.group().name == me.name,
                        mode = Files.getAttribute(p, "unix:mode", LinkOption.NOFOLLOW_LINKS) as Int,
                    )
                } catch (e: IOException) {
                    "$p cannot be read (${e.message})"
                }
            if (risk != null) return risk
            p = p.parent
        }
        return null
    }

    /** The rule of [ancestorRisk] for one directory [path], on its numeric owner, group and mode. */
    internal fun ancestorRisk(
        path: String,
        uid: Int,
        owner: String,
        ownerIsMe: Boolean,
        gid: Int,
        groupIsMine: Boolean,
        mode: Int,
    ): String? {
        val sticky = mode and STICKY != 0
        return when {
            uid != 0 && !ownerIsMe -> "$path belongs to $owner, not to this user or root"
            sticky -> null
            mode and OTHER_WRITE != 0 -> "$path is writable by others without the sticky bit"
            mode and GROUP_WRITE != 0 && gid != 0 && !groupIsMine -> "$path is writable by its group without the sticky bit"
            else -> null
        }
    }

    private const val OTHER_WRITE = 0x2 // 0o002
    private const val GROUP_WRITE = 0x10 // 0o020
    private const val STICKY = 0x200 // 0o1000

    private val OWNER_ONLY = PosixFilePermissions.fromString("rwx------")
    private val OWNER_ONLY_FILE = PosixFilePermissions.fromString("rw-------")

    /**
     * The Windows principals that already control every file of the machine: the owner of `%SystemRoot%\System32`
     * (TrustedInstaller), and SYSTEM (S-1-5-18) and Administrators (S-1-5-32-544) as they appear in that directory's ACL.
     * They are taken from that system directory, not looked up by name (the names are localized). The JDK exposes a
     * principal's SID only through `equals` and its hash code (`sidString.hashCode()`): the hash code only picks the two
     * candidates out of an ACL the system itself controls; membership is then `equals`, a comparison of the full SID.
     * Empty where there is no such directory (not Windows) or it cannot be read.
     */
    private val trustedWindowsPrincipals: Set<UserPrincipal> by lazy {
        val dir = Paths.get(System.getenv("SystemRoot") ?: return@lazy emptySet(), "System32")
        runCatching {
            val view = Files.getFileAttributeView(dir, AclFileAttributeView::class.java) ?: return@runCatching emptySet()
            val wellKnown = setOf("S-1-5-18".hashCode(), "S-1-5-32-544".hashCode())
            setOf(view.owner) + view.acl.map { it.principal() }.filter { it.hashCode() in wellKnown }
        }.getOrDefault(emptySet())
    }

    internal fun isTrustedWindowsPrincipal(p: UserPrincipal): Boolean = p in trustedWindowsPrincipals

    /** The names of the principals other than [owner] (and the trusted Windows ones) that [acl] allows anything. */
    internal fun foreignAccess(
        acl: List<AclEntry>,
        owner: UserPrincipal,
    ): List<String> =
        acl
            .filter { it.type() == AclEntryType.ALLOW && it.principal() != owner && !isTrustedWindowsPrincipal(it.principal()) }
            .map { it.principal().name }
            .distinct()

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
     * Writes the library unless an identical, manifest-verified copy owned by this process's user, which nobody else may
     * write, is already there (another JVM may have it mapped), and returns the file to load. New content, or a replacement
     * for any other copy, goes through a new owner-only temp file (`rw-------`, created exclusively, never through a link)
     * and an atomic rename. When the rename fails (Windows does not replace a library another process has loaded; another
     * JVM may have won the race) a copy that is now acceptable is used, else the library goes under a name that carries its
     * hash. Where the file system knows owners an undeterminable current user fails with [KslException.NativeLoad].
     */
    fun installLibrary(
        out: File,
        content: ByteArray,
        manifest: String,
    ): File = installLibrary(out, content, manifest, currentUser(out.toPath().toAbsolutePath().parent ?: out.toPath()))

    internal fun installLibrary(
        out: File,
        content: ByteArray,
        manifest: String,
        expectedOwner: UserPrincipal?,
    ): File {
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

        fun reusable(f: Path): Boolean =
            Files.isRegularFile(f, LinkOption.NOFOLLOW_LINKS) &&
                runCatching { (!posix && !acl) || onlyOwnerMayWrite(f, posix, expectedOwner!!) }.getOrDefault(false) &&
                runCatching { verifyAgainstManifest(f.toFile(), manifest, out.name) }.isSuccess
        if (reusable(path)) return out
        try {
            writeAndMove(path, content, manifest, out.name, posix)
            return out
        } catch (e: KslException) {
            throw e
        } catch (e: IOException) {
            if (reusable(path)) return out
            val hashed = path.resolveSibling(hashedName(out.name, content))
            if (reusable(hashed)) return hashed.toFile()
            try {
                writeAndMove(hashed, content, manifest, out.name, posix)
            } catch (e2: IOException) {
                if (reusable(hashed)) return hashed.toFile() // another JVM wrote and loaded the same copy meanwhile
                e2.addSuppressed(e)
                throw e2
            }
            return hashed.toFile()
        }
    }

    /** [content] into a new owner-only temp file next to [target], verified as [entryName], then renamed to [target]. */
    private fun writeAndMove(
        target: Path,
        content: ByteArray,
        manifest: String,
        entryName: String,
        posix: Boolean,
    ) {
        val attrs: Array<FileAttribute<*>> = if (posix) arrayOf(PosixFilePermissions.asFileAttribute(OWNER_ONLY_FILE)) else emptyArray()
        val tmp = target.resolveSibling("${target.fileName}.${java.util.UUID.randomUUID()}.tmp")
        try {
            // CREATE_NEW is O_CREAT | O_EXCL: it fails on any existing name, a link included; on Windows the file inherits
            // the work directory's owner-only ACL
            Files.newByteChannel(tmp, EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), *attrs).use { ch ->
                val buf = ByteBuffer.wrap(content)
                while (buf.hasRemaining()) ch.write(buf)
            } // fully written and closed before loading
            verifyAgainstManifest(tmp.toFile(), manifest, entryName)
            moveHookForTest?.invoke(tmp, target)
            try {
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            Files.deleteIfExists(tmp)
        }
    }

    /**
     * Called with (temp file, target) right before the rename in [installLibrary]; tests set it to act as another process
     * (a JVM that wins the race, Windows refusing to replace a loaded library), which a POSIX rename cannot reproduce.
     */
    @Volatile
    internal var moveHookForTest: ((Path, Path) -> Unit)? = null

    /** `libksl_7_windows_x86_64.dll` -> `libksl_7_windows_x86_64-<12 hex digits of the content's SHA-256>.dll`. */
    internal fun hashedName(
        name: String,
        content: ByteArray,
    ): String {
        val hash =
            MessageDigest
                .getInstance("SHA-256")
                .digest(content)
                .joinToString("") { "%02x".format(it) }
                .take(12)
        val dot = name.lastIndexOf('.')
        return if (dot <= 0) "$name-$hash" else name.substring(0, dot) + "-" + hash + name.substring(dot)
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

    /** The entries of principals other than [owner] (and the trusted Windows ones) that allow changing the file (reading is fine for a library). */
    private fun foreignWriters(
        acl: List<AclEntry>,
        owner: UserPrincipal,
    ): List<AclEntry> =
        acl.filter {
            it.type() == AclEntryType.ALLOW &&
                it.principal() != owner &&
                !isTrustedWindowsPrincipal(it.principal()) &&
                it.permissions().any { p -> p in WRITE_PERMISSIONS }
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

    /**
     * Extracts the jar resource into the first usable work directory of [workDirs] and loads it from there. A directory that
     * cannot be prepared, or from which `System.load` fails (an alternative location mounted `noexec`), gives way to the
     * next; when none works the first failure is thrown.
     */
    private fun extractAndLoad(
        props: Map<String, String>,
        cl: ClassLoader,
        env: Map<String, String> = System.getenv(),
        warn: (String) -> Unit = ::warnOnStderr,
    ) {
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
        var failure: Throwable? = null
        for (prepare in workDirs(props, env, warn)) {
            val lib =
                try {
                    val prepared = prepare()
                    installLibrary(prepared.dir.resolve(name).toFile(), bytes[0], manifest).also {
                        // a private per-process copy goes at exit (POSIX unlinks a loaded library fine; Windows keeps it)
                        if (prepared.fresh) {
                            prepared.dir.toFile().deleteOnExit()
                            it.deleteOnExit()
                        }
                    }
                } catch (e: KslException.NativeLoad) {
                    failure = failure ?: e
                    continue
                } catch (e: IOException) {
                    failure = failure ?: e
                    continue
                }
            // the file stays: its name carries the ABI, its content was verified, and another JVM may be between its own check and System.load
            try {
                System.load(lib.absolutePath)
                return
            } catch (e: UnsatisfiedLinkError) {
                failure = failure ?: e
            }
        }
        throw failure ?: IllegalStateException("no work directory for the native library")
    }
}
