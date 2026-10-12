// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.native

import io.kuicksilver.annotations.InternalKuicksilverApi
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** The loader contract: resource + SHA-256 manifest, ABI check, explicit path override, private work dir. */
class KslLoaderTest {
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
        val root =
            dir
                .toPath()
                .fileSystem.userPrincipalLookupService
                .lookupPrincipalByName("root")
        val e = assertFailsWith<KslException.NativeLoad> { JvmLoader.checkWorkDir(dir.toPath(), root) }
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
        assertEquals("rwx------", java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(dir)))
        JvmLoader.createWorkDir(dir) // an existing directory is left to checkWorkDir
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

    @Test fun duplicateResourceWithDifferentHashIsRefused() {
        val e = assertFailsWith<KslException.NativeLoad> { JvmLoader.checkDuplicates(listOf("aa".toByteArray(), "bb".toByteArray())) }
        assertTrue(e.reason.contains("duplicate"), e.reason)
    }
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
        val root = dir.toPath().fileSystem.userPrincipalLookupService.lookupPrincipalByName("root")
        JvmLoader.installLibrary(out, lib.readBytes(), manifest, root)
        val after = Files.readAttributes(out.toPath(), java.nio.file.attribute.BasicFileAttributes::class.java).fileKey()
        kotlin.test.assertNotEquals(before, after, "a copy owned by another user was reused")
        kotlin.test.assertTrue(dir.listFiles()!!.none { it.name.endsWith(".tmp") }, "no temp files left")
        val e = assertFailsWith<KslException.NativeLoad> { JvmLoader.installLibrary(out, lib.readBytes(), manifest, null) }
        kotlin.test.assertTrue(e.reason.contains("cannot be determined"), e.reason)
    }
}
