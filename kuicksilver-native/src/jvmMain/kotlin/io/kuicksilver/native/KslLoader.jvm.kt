// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, ExperimentalKuicksilverApi::class)

package io.kuicksilver.native

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.nio.file.attribute.UserPrincipal
import java.security.MessageDigest

/**
 * Loads `libksl` on the JVM: an explicit path (`-Dkuicksilver.native.path`), otherwise the jar resource
 * extracted into a private directory and checked against the SHA-256 manifest; `-Dkuicksilver.native.system=true` falls
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

/** Testable pieces of the loader. */
public object JvmLoader {
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
    public fun load(props: Map<String, String>) {
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
    public fun resolveExplicitPath(props: Map<String, String>): File? {
        val p = props[PATH] ?: return null
        val f = File(p)
        if (!f.isFile) throw KslException.NativeLoad(JvmNativeNames.os, JvmNativeNames.classifier, "$PATH=$p does not exist")
        return f
    }

    /** Maps ksl_init codes (system-OpenSSL builds, Linux only) to exceptions. */
    public fun checkInit(code: Int) {
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
    public fun checkAbi(expected: Int) {
        val native = KslNative.abiVersion()
        if (native != expected) throw KslException.AbiMismatch(native, expected)
    }

    /**
     * The directory the jar resource is extracted to: `kuicksilver.native.workdir` from [props], else
     * `<java.io.tmpdir>/kuicksilver-native-<user.name>`. It is created when missing and then checked by [checkWorkDir]: a
     * symbolic link, something other than a directory, a directory owned by another user or one that keeps group/other
     * permissions after `rwx------` is applied fails with [KslException.NativeLoad] (`IntegrityMismatch`). Set the property
     * when the temporary directory is mounted `noexec`.
     */
    public fun privateWorkDir(props: Map<String, String> = emptyMap()): File {
        val base =
            props[WORKDIR]?.let(::File)
                ?: File(System.getProperty("java.io.tmpdir"), "kuicksilver-native-" + System.getProperty("user.name"))
        if (!Files.isSymbolicLink(base.toPath())) base.mkdirs()
        checkWorkDir(base.toPath())
        return base
    }

    /**
     * Refuses [dir] as the extraction directory unless it is a real directory (not a symbolic link) owned by [expectedOwner]
     * and private to it: the owner of the directory could replace the library between the manifest check and `System.load`.
     * Group/other permissions are stripped first; a directory that keeps them (a sticky or ACL-managed mount) is refused as well.
     * Without a POSIX view (Windows) only the directory check applies.
     */
    internal fun checkWorkDir(
        dir: Path,
        expectedOwner: UserPrincipal? = currentUser(dir),
    ) {
        fun refuse(why: String): Nothing =
            throw KslException.NativeLoad(
                JvmNativeNames.os,
                JvmNativeNames.classifier,
                "work directory $dir $why; set -D$WORKDIR to a directory only you own",
                null,
                NativeUnavailableReason.IntegrityMismatch,
            )
        if (Files.isSymbolicLink(dir)) refuse("is a symbolic link")
        val attrs =
            try {
                Files.readAttributes(dir, PosixFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            } catch (_: UnsupportedOperationException) {
                if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) refuse("is not a directory")
                return
            } catch (e: IOException) {
                refuse("cannot be read: ${e.message}")
            }
        if (!attrs.isDirectory) refuse("is not a directory")
        if (expectedOwner != null && attrs.owner() != expectedOwner) refuse("is owned by ${attrs.owner().name}, not by this user")
        try {
            Files.setPosixFilePermissions(dir, OWNER_ONLY)
        } catch (_: IOException) {
        }
        val perms = Files.getPosixFilePermissions(dir, LinkOption.NOFOLLOW_LINKS)
        if (perms.any { it !in OWNER_ONLY }) refuse("keeps group/other permissions ${PosixFilePermissions.toString(perms)}")
    }

    private val OWNER_ONLY = PosixFilePermissions.fromString("rwx------")

    /** The principal of this process: `user.name` looked up on [dir]'s file system, else the owner of a file created now; null when neither works. */
    private fun currentUser(dir: Path): UserPrincipal? =
        runCatching { dir.fileSystem.userPrincipalLookupService.lookupPrincipalByName(System.getProperty("user.name")) }
            .recoverCatching {
                val probe = Files.createTempFile("ksl-owner", null)
                try {
                    Files.getOwner(probe)
                } finally {
                    Files.deleteIfExists(probe)
                }
            }.getOrNull()

    /**
     * Throws [KslException.NativeLoad] unless the SHA-256 of [file] equals the hash on the [manifest] line (`<hex> <path>`)
     * whose path ends with [entryName]; a file without an entry fails too, so a tampered or unlisted library never loads.
     */
    public fun verifyAgainstManifest(
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

    /** Writes the library unless an identical, manifest-verified copy is already there (another JVM may have it mapped); new content goes through a temp file and an atomic rename. */
    public fun installLibrary(
        out: File,
        content: ByteArray,
        manifest: String,
    ) {
        if (out.isFile && runCatching { verifyAgainstManifest(out, manifest) }.isSuccess) return
        val tmp = File.createTempFile(out.name, ".tmp", out.parentFile)
        try {
            Files.newOutputStream(tmp.toPath()).use { it.write(content) } // fully written and closed before loading
            verifyAgainstManifest(tmp, manifest, out.name)
            try {
                Files.move(
                    tmp.toPath(),
                    out.toPath(),
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                )
            } catch (
                _: java.nio.file.AtomicMoveNotSupportedException,
            ) {
                Files.move(tmp.toPath(), out.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            tmp.delete()
        }
    }

    /**
     * Throws [KslException.NativeLoad] when the classpath carries several copies of the library resource with different
     * content (two Kuicksilver versions, a shaded copy), since which one loads would be an accident; identical copies pass.
     */
    public fun checkDuplicates(contents: List<ByteArray>) {
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
