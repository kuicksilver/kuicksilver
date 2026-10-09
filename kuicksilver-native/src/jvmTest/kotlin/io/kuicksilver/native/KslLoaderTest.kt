// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.native

import io.kuicksilver.annotations.InternalKuicksilverApi
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
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
}
