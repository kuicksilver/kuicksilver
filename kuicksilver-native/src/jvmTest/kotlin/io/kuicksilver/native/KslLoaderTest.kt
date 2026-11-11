// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.native

import io.kuicksilver.annotations.InternalKuicksilverApi
import java.io.File
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.attribute.AclEntry
import java.nio.file.attribute.AclEntryPermission
import java.nio.file.attribute.AclEntryType
import java.nio.file.attribute.AclFileAttributeView
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** The loader contract: resource + SHA-256 manifest, ABI check, explicit path override, private work dir. */
class KslLoaderTest {
    /** False on Windows: no POSIX view, so the loader checks only that the work directory is a real directory (KslLoader.jvm.kt). */
    private val posix = "posix" in FileSystems.getDefault().supportedFileAttributeViews()
    private val unix = "unix" in FileSystems.getDefault().supportedFileAttributeViews()
    private val resourceDir = File(System.getProperty("ksl.native.resources")!!) // META-INF/native as the jar would carry it

    @Test fun loadsFromResourceAndVerifiesSha256() {
        KslLoader.ensureLoaded()
        assertEquals(KSL_ABI_VERSION, Ksl.abiVersion())
        val manifest = File(resourceDir, "META-INF/native/manifest.sha256").readText()
        assertTrue(manifest.lines().any { it.contains(JvmNativeNames.libraryFileName()) }, manifest)
    }

    @Test fun negative_tamperedNativeArtifact() {
        val lib = File(resourceDir, "META-INF/native/" + JvmNativeNames.libraryFileName())
        val tampered = Files.createTempDirectory("ksl-tamper").toFile().apply { deleteOnExit() }
        val copy = File(tampered, lib.name)
        lib.copyTo(copy)
        copy.writeBytes(copy.readBytes().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 0x5a).toByte() })
        val e =
            assertFailsWith<KslException.NativeLoad> {
                JvmLoader.verifyAgainstManifest(copy, File(resourceDir, "META-INF/native/manifest.sha256").readText())
            }
        assertTrue(e.reason.contains("sha256"), e.reason)
    }

    @Test fun negative_nativeAbiVersionMismatch() {
        KslLoader.ensureLoaded()
        val e = assertFailsWith<KslException.AbiMismatch> { JvmLoader.checkAbi(expected = 99) }
        assertEquals(99, e.kotlin)
        assertEquals(KSL_ABI_VERSION, e.native)
    }

    @Test fun explicitPathOverrideIsHonoured() {
        val lib = File(resourceDir, "META-INF/native/" + JvmNativeNames.libraryFileName())
        assertEquals(lib.canonicalPath, JvmLoader.resolveExplicitPath(mapOf("kuicksilver.native.path" to lib.path))!!.canonicalPath)
        assertFailsWith<KslException.NativeLoad> {
            JvmLoader.resolveExplicitPath(
                mapOf("kuicksilver.native.path" to "/nonexistent/libksl.so"),
            )
        }
    }

    @Test fun workdirIsPrivate() {
        val dir = JvmLoader.privateWorkDir()
        if (!posix) return assertTrue(dir.isDirectory, "$dir") // Windows: no mode bits to check
        val perms = Files.getPosixFilePermissions(dir.toPath())
        assertTrue(PosixFilePermission.GROUP_READ !in perms && PosixFilePermission.OTHERS_READ !in perms, perms.toString())
    }

    /** A symlink at the work directory (planted by another user of the shared temp directory) is refused, whatever it points to. */
    @Test fun negative_workdirSymlinkRefused() {
        val real = Files.createTempDirectory("ksl-workdir-real").toFile().apply { deleteOnExit() }
        val link = File(real.parentFile, real.name + "-link").apply { deleteOnExit() }
        Files.createSymbolicLink(link.toPath(), real.toPath())
        val e = assertFailsWith<KslException.NativeLoad> { JvmLoader.privateWorkDir(mapOf("kuicksilver.native.workdir" to link.path)) }
        assertTrue(e.reason.contains("symbolic link"), e.reason)
    }

    /** A directory owned by someone else is refused: its owner could swap the library between the hash check and System.load. */
    @Test fun negative_workdirForeignOwnerRefused() {
        val dir = Files.createTempDirectory("ksl-workdir-owner").toFile().apply { deleteOnExit() }
        val e = assertFailsWith<KslException.NativeLoad> { JvmLoader.checkWorkDir(dir.toPath(), foreignUser(dir.toPath())) }
        assertTrue(e.reason.contains("owned by"), e.reason)
        JvmLoader.checkWorkDir(dir.toPath()) // our own directory passes
    }

    /** When this process's user cannot be resolved on a POSIX file system, the owner check is not skipped: the directory is refused. */
    @Test fun negative_workdirUnknownUserRefused() {
        val dir = Files.createTempDirectory("ksl-workdir-nouser").toFile().apply { deleteOnExit() }
        val e = assertFailsWith<KslException.NativeLoad> { JvmLoader.checkWorkDir(dir.toPath(), null) }
        assertTrue(e.reason.contains("cannot be determined"), e.reason)
    }

    /** The final work directory is created with rwx------ in the same call, not under the umask and tightened afterwards. */
    @Test fun workDirCreatedWithOwnerOnlyPermissions() {
        val parent = Files.createTempDirectory("ksl-workdir-parent").toFile().apply { deleteOnExit() }
        val dir = File(parent, "a/b/kuicksilver-native").toPath()
        JvmLoader.createWorkDir(dir)
        dir.toFile().deleteOnExit()
        if (!posix) return assertTrue(Files.isDirectory(dir), "$dir") // Windows: the ACL, see workDirAclIsOwnerOnly
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir)))
        JvmLoader.createWorkDir(dir) // an existing directory is left to checkWorkDir
        for (created in listOf(File(parent, "a"), File(parent, "a/b"))) {
            created.deleteOnExit()
            assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(created.toPath())), "$created")
        }
    }

    /**
     * The default work directory lies in `java.io.tmpdir`: a directory there can be renamed and replaced by any user who may
     * write to a directory above it, unless that one has the sticky bit. Such an ancestor, or one owned by another user, is
     * refused; a sticky world-writable one (`/tmp`) passes.
     */
    @Test fun negative_workdirUnderWritableNonStickyParentRefused() {
        if (!unix) return
        val shared = Files.createTempDirectory("ksl-shared-parent").toFile().apply { deleteOnExit() }
        val dir = File(shared, "kuicksilver-native-test").toPath()
        JvmLoader.createWorkDir(dir)
        dir.toFile().deleteOnExit()
        chmod("777", shared)
        val e = assertFailsWith<KslException.NativeLoad> { JvmLoader.checkAncestors(dir) }
        assertTrue(e.reason.contains("without the sticky bit"), e.reason)
        assertEquals(NativeUnavailableReason.IntegrityMismatch, e.kind)
        chmod("1777", shared)
        JvmLoader.checkAncestors(dir)
        chmod("700", shared)
        JvmLoader.checkAncestors(dir)
        if (Files.getAttribute(shared.toPath(), "unix:uid") == 0) return // running as root: a root-owned ancestor is trusted anyway
        val owner = assertFailsWith<KslException.NativeLoad> { JvmLoader.checkAncestors(dir, foreignUser(shared.toPath())) }
        assertTrue(owner.reason.contains("owned by"), owner.reason)
    }

    /** The ACL check of a work directory without a POSIX view: only the owner may be allowed anything. */
    @Test fun negative_aclGrantingOthersIsRefused() {
        val me = FakePrincipal("me")
        val other = FakePrincipal("other")

        fun entry(
            who: java.nio.file.attribute.UserPrincipal,
            type: AclEntryType = AclEntryType.ALLOW,
            vararg perms: AclEntryPermission = AclEntryPermission.values(),
        ) = AclEntry
            .newBuilder()
            .setType(type)
            .setPrincipal(who)
            .setPermissions(*perms)
            .build()
        assertEquals(emptyList(), JvmLoader.foreignAccess(listOf(entry(me)), me))
        assertEquals(emptyList(), JvmLoader.foreignAccess(listOf(entry(me), entry(other, AclEntryType.DENY)), me))
        assertEquals(
            listOf("other"),
            JvmLoader.foreignAccess(listOf(entry(me), entry(other, perms = arrayOf(AclEntryPermission.READ_DATA))), me),
        )
        assertEquals(listOf("other"), JvmLoader.foreignAccess(listOf(entry(other, perms = arrayOf(AclEntryPermission.APPEND_DATA))), me))
        assertEquals(
            listOf(AclEntry::class.java.simpleName),
            listOf(JvmLoader.ownerOnlyAcl(me, directory = true).single()::class.java.simpleName),
        )
        assertEquals(me, JvmLoader.ownerOnlyAcl(me, directory = true).single().principal())
    }

    /** With an ACL view (Windows) the work directory is reduced to one entry for its owner, whatever the parent passes on. */
    @Test fun workDirAclIsOwnerOnly() {
        val dir = Files.createTempDirectory("ksl-workdir-acl").resolve("kuicksilver-native")
        JvmLoader.createWorkDir(dir)
        dir.toFile().deleteOnExit()
        JvmLoader.checkWorkDir(dir)
        val view = Files.getFileAttributeView(dir, AclFileAttributeView::class.java) ?: return // POSIX: covered above
        assertEquals(listOf(view.owner), view.acl.filter { it.type() == AclEntryType.ALLOW }.map { it.principal() })
        val e = assertFailsWith<KslException.NativeLoad> { JvmLoader.checkWorkDir(dir, FakePrincipal("other")) }
        assertTrue(e.reason.contains("owned by"), e.reason)
        val n = assertFailsWith<KslException.NativeLoad> { JvmLoader.checkWorkDir(dir, null) }
        assertTrue(n.reason.contains("cannot be determined"), n.reason)
    }

    /** A file in the work directory is not deleted when a JVM exits: another JVM may have just verified it and be about to load it. */
    @Test fun sharedLibrarySurvivesOtherJvmExit() {
        val dir = Files.createTempDirectory("ksl-workdir-shared").toFile().apply { deleteOnExit() }
        val javaBin =
            ProcessHandle
                .current()
                .info()
                .command()
                .orElseThrow()
        val p =
            ProcessBuilder(
                javaBin,
                "-cp",
                System.getProperty("java.class.path"),
                "-Dkuicksilver.native.workdir=" + dir.path,
                "io.kuicksilver.native.ChildLoadMain",
            ).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        assertTrue(p.waitFor(60, TimeUnit.SECONDS) && p.exitValue() == 0, "child JVM loaded the library: $out")
        assertTrue(out.contains("loaded abi $KSL_ABI_VERSION"), out)
        val lib = File(dir, JvmNativeNames.libraryFileName())
        assertTrue(lib.isFile, "the shared library is still there after the other JVM exited: ${dir.list()?.toList()}")
    }

    /** A regular file at the work directory's path is refused. */
    @Test fun negative_workdirFileRefused() {
        val dir = Files.createTempDirectory("ksl-workdir-file").toFile().apply { deleteOnExit() }
        val file = File(dir, "not-a-dir").apply { writeText("x") }.apply { deleteOnExit() }
        val e = assertFailsWith<KslException.NativeLoad> { JvmLoader.checkWorkDir(file.toPath()) }
        assertTrue(e.reason.contains("not a directory"), e.reason)
    }

    private fun chmod(
        mode: String,
        f: File,
    ) {
        val p = ProcessBuilder("/bin/chmod", mode, f.path).inheritIO().start()
        assertTrue(p.waitFor(30, TimeUnit.SECONDS) && p.exitValue() == 0, "chmod $mode $f")
    }

    @Test fun duplicateResourceWithDifferentHashIsRefused() {
        val e = assertFailsWith<KslException.NativeLoad> { JvmLoader.checkDuplicates(listOf("aa".toByteArray(), "bb".toByteArray())) }
        assertTrue(e.reason.contains("duplicate"), e.reason)
    }
}

/**
 * A user that does not own [path]: "root", or "nobody"/"daemon" when the tests themselves run as root (the Docker JVM
 * steps run in a Temurin container as root, where "root" is no foreign owner and the negative tests would pass nothing).
 */
internal fun foreignUser(path: java.nio.file.Path): java.nio.file.attribute.UserPrincipal {
    val owner = Files.getOwner(path)
    if ("posix" !in path.fileSystem.supportedFileAttributeViews()) return FakePrincipal("not-${owner.name}")
    val lookup = path.fileSystem.userPrincipalLookupService
    return listOf("root", "nobody", "daemon")
        .firstNotNullOfOrNull { name ->
            runCatching { lookup.lookupPrincipalByName(name) }.getOrNull()?.takeIf { it != owner }
        } ?: error("no user other than ${owner.name} to own $path")
}

/** A principal no file system knows: it owns nothing, so it stands for "another user" where no real one can be looked up (Windows). */
internal data class FakePrincipal(
    private val n: String,
) : java.nio.file.attribute.UserPrincipal {
    override fun getName(): String = n
}

class SystemOpenSslMappingTest {
    @Test fun initCodesMapToExceptions() {
        KslLoader.ensureLoaded()
        kotlin.test.assertFailsWith<KslException.Version> { JvmLoader.checkInit(-2) }
        kotlin.test.assertFailsWith<KslException.MissingSymbol> { JvmLoader.checkInit(-3) }
        val e = kotlin.test.assertFailsWith<KslException.NativeLoad> { JvmLoader.checkInit(-4) }
        kotlin.test.assertTrue(e.reason.contains("keylog"))
        JvmLoader.checkInit(0)
    }
}

class LoaderInstallTest {
    @Test fun existingMatchingLibraryIsNotRewritten() {
        val resourceDir = File(System.getProperty("ksl.native.resources")!!)
        val lib = File(resourceDir, "META-INF/native/" + JvmNativeNames.libraryFileName())
        val manifest = File(resourceDir, "META-INF/native/manifest.sha256").readText()
        val dir = Files.createTempDirectory("ksl-install").toFile().apply { deleteOnExit() }
        val out = File(dir, lib.name)
        JvmLoader.installLibrary(out, lib.readBytes(), manifest)
        val mtime = out.lastModified()
        Thread.sleep(1100)
        JvmLoader.installLibrary(out, lib.readBytes(), manifest)
        kotlin.test.assertEquals(mtime, out.lastModified(), "a verified identical copy is left alone (another JVM may have it mapped)")
        out.writeBytes(byteArrayOf(1, 2, 3))
        JvmLoader.installLibrary(out, lib.readBytes(), manifest)
        kotlin.test.assertTrue(
            out.length() == lib.length() &&
                dir.listFiles()!!.none {
                    it.name.endsWith(".tmp")
                },
            "a corrupt copy is replaced atomically, no temp files left",
        )
    }

    /** A verified copy that belongs to someone else is not reused: it is replaced by a fresh file of this user. */
    @Test fun negative_existingLibraryWithForeignOwnerIsReinstalled() {
        val resourceDir = File(System.getProperty("ksl.native.resources")!!)
        val lib = File(resourceDir, "META-INF/native/" + JvmNativeNames.libraryFileName())
        val manifest = File(resourceDir, "META-INF/native/manifest.sha256").readText()
        val dir = Files.createTempDirectory("ksl-install-owner").toFile().apply { deleteOnExit() }
        val out = File(dir, lib.name).apply { deleteOnExit() }
        JvmLoader.installLibrary(out, lib.readBytes(), manifest)
        val before = Files.readAttributes(out.toPath(), java.nio.file.attribute.BasicFileAttributes::class.java).fileKey()
        JvmLoader.installLibrary(out, lib.readBytes(), manifest, foreignUser(out.toPath()))
        val after = Files.readAttributes(out.toPath(), java.nio.file.attribute.BasicFileAttributes::class.java).fileKey()
        if (before != null) kotlin.test.assertNotEquals(before, after, "a copy owned by another user was reused") // Windows: no file key
        kotlin.test.assertTrue(dir.listFiles()!!.none { it.name.endsWith(".tmp") }, "no temp files left")
        val e = assertFailsWith<KslException.NativeLoad> { JvmLoader.installLibrary(out, lib.readBytes(), manifest, null) }
        kotlin.test.assertTrue(e.reason.contains("cannot be determined"), e.reason)
    }

    /** The extracted library is written owner-only (rw-------), in the creating call, not under the umask. */
    @Test fun installedLibraryIsOwnerOnly() {
        val resourceDir = File(System.getProperty("ksl.native.resources")!!)
        val lib = File(resourceDir, "META-INF/native/" + JvmNativeNames.libraryFileName())
        val manifest = File(resourceDir, "META-INF/native/manifest.sha256").readText()
        val dir = Files.createTempDirectory("ksl-install-mode").toFile().apply { deleteOnExit() }
        val out = File(dir, lib.name).apply { deleteOnExit() }
        JvmLoader.installLibrary(out, lib.readBytes(), manifest)
        if ("posix" !in FileSystems.getDefault().supportedFileAttributeViews()) return // Windows: inherits the work directory's ACL
        kotlin.test.assertEquals(
            "rw-------",
            java.nio.file.attribute.PosixFilePermissions
                .toString(Files.getPosixFilePermissions(out.toPath())),
        )
    }

    /** A verified copy of this user that group or others may write to is not reused: it is replaced by an owner-only file. */
    @Test fun negative_existingLibraryWritableByOthersIsReinstalled() {
        if ("posix" !in FileSystems.getDefault().supportedFileAttributeViews()) return // Windows: the ACL check, see foreignAccess
        val resourceDir = File(System.getProperty("ksl.native.resources")!!)
        val lib = File(resourceDir, "META-INF/native/" + JvmNativeNames.libraryFileName())
        val manifest = File(resourceDir, "META-INF/native/manifest.sha256").readText()
        val dir = Files.createTempDirectory("ksl-install-writable").toFile().apply { deleteOnExit() }
        val out = File(dir, lib.name).apply { deleteOnExit() }
        JvmLoader.installLibrary(out, lib.readBytes(), manifest)
        Files.setPosixFilePermissions(
            out.toPath(),
            java.nio.file.attribute.PosixFilePermissions
                .fromString("rw-rw-rw-"),
        )
        val before = Files.readAttributes(out.toPath(), java.nio.file.attribute.BasicFileAttributes::class.java).fileKey()
        JvmLoader.installLibrary(out, lib.readBytes(), manifest)
        val after = Files.readAttributes(out.toPath(), java.nio.file.attribute.BasicFileAttributes::class.java).fileKey()
        kotlin.test.assertNotEquals(before, after, "a copy others may write to was reused")
        kotlin.test.assertEquals(
            "rw-------",
            java.nio.file.attribute.PosixFilePermissions
                .toString(Files.getPosixFilePermissions(out.toPath())),
        )
    }
}
