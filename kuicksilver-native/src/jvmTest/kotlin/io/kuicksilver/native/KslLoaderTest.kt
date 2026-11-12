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
        if (JvmLoader.isTrustedWindowsPrincipal(Files.getOwner(dir.toPath()))) {
            // an elevated Windows process: its directories belong to Administrators, which every user already trusts
            return JvmLoader.checkWorkDir(dir.toPath(), foreignUser(dir.toPath()))
        }
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
     * A temporary directory others may write to without the sticky bit (an `emptyDir` mounted at /tmp) is no reason to
     * refuse: the library goes to a private location of the user (here its cache directory) instead, without a warning.
     */
    @Test fun workdirUnderWritableNonStickyTmpUsesTheUserCache() {
        if (!unix) return
        val shared = Files.createTempDirectory("ksl-shared-tmp").toFile().apply { deleteOnExit() }
        chmod("777", shared)
        val home = Files.createTempDirectory("ksl-home").toFile().apply { deleteOnExit() }
        val warnings = mutableListOf<String>()
        val dir = JvmLoader.privateWorkDir(mapOf("java.io.tmpdir" to shared.path, "user.home" to home.path), emptyMap(), warnings::add)
        dir.deleteOnExit()
        assertTrue(dir.canonicalPath.startsWith(home.canonicalPath), "$dir")
        assertEquals(emptyList(), warnings)
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir.toPath())))
    }

    /** With no private location to use, the temporary directory is still used (it loaded in 0.2), with a warning that says why. */
    @Test fun workdirUnderWritableNonStickyTmpWithoutAlternativeWarns() {
        if (!unix) return
        val shared = Files.createTempDirectory("ksl-shared-tmp").toFile().apply { deleteOnExit() }
        chmod("777", shared)
        val warnings = mutableListOf<String>()
        val props = mapOf("java.io.tmpdir" to shared.path, "user.home" to noHome().path, "user.name" to "t")
        val dir = JvmLoader.privateWorkDir(props, emptyMap(), warnings::add)
        dir.deleteOnExit()
        assertEquals(File(shared.canonicalFile, "kuicksilver-native-t"), dir)
        assertTrue(warnings.single().contains("writable by others without the sticky bit"), warnings.toString())
    }

    /** A child JVM whose `java.io.tmpdir` is world-writable without the sticky bit, and that has no home, still loads. */
    @Test fun childLoadsUnderWritableNonStickyTmp() {
        if (!unix) return
        val shared = Files.createTempDirectory("ksl-shared-tmp").toFile().apply { deleteOnExit() }
        chmod("777", shared)
        val out = runChild("-Djava.io.tmpdir=" + shared.path, "-Duser.home=" + noHome().path)
        assertTrue(out.contains("loaded abi $KSL_ABI_VERSION"), out)
        assertTrue(out.contains("WARNING") && out.contains("without the sticky bit"), out) // System.Logger -> java.util.logging
    }

    /** A default directory planted by someone else (here a symbolic link) gives a new private directory for the process, not a failure. */
    @Test fun negative_plantedDefaultWorkdirIsNotUsed() {
        val tmp = Files.createTempDirectory("ksl-planted-tmp").toFile().apply { deleteOnExit() }
        val elsewhere = Files.createTempDirectory("ksl-planted-target").toFile().apply { deleteOnExit() }
        // the name the loader uses: an elevated Windows process (files owned by Administrators) gets "-admin"
        val probe = Files.createTempFile(tmp.toPath(), "probe", null)
        val me = Files.getOwner(probe).also { Files.delete(probe) }
        val primary = File(tmp, JvmLoader.defaultDirName("t", me)).apply { deleteOnExit() }
        Files.createSymbolicLink(primary.toPath(), elsewhere.toPath())
        val warnings = mutableListOf<String>()
        val dir = JvmLoader.privateWorkDir(mapOf("java.io.tmpdir" to tmp.path, "user.name" to "t"), emptyMap(), warnings::add)
        dir.deleteOnExit()
        assertTrue(dir.name.startsWith(primary.name + "-") && dir.parentFile == tmp.canonicalFile, "$dir")
        assertTrue(Files.isDirectory(dir.toPath(), java.nio.file.LinkOption.NOFOLLOW_LINKS), "$dir")
        assertTrue(warnings.single().contains("symbolic link") && warnings.single().contains("new private directory"), warnings.toString())
        if (posix) assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir.toPath())))
        val out = runChild("-Djava.io.tmpdir=" + tmp.path, "-Duser.name=t")
        assertTrue(out.contains("loaded abi $KSL_ABI_VERSION"), out)
        assertTrue(elsewhere.list()!!.isEmpty(), "nothing written through the planted link: ${elsewhere.list()!!.toList()}")
    }

    /** The rule for a directory above the default work directory, on the setups it must accept and the ones it must report. */
    @Test fun negative_ancestorRiskRule() {
        fun risk(
            uid: Int = 0,
            mine: Boolean = false,
            gid: Int = 0,
            myGroup: Boolean = false,
            mode: Int,
        ) = JvmLoader.ancestorRisk("/d", uid, "o", mine, gid, myGroup, mode)
        assertEquals(null, risk(mode = "1777".toInt(8)), "/tmp")
        assertEquals(null, risk(mode = "755".toInt(8)), "/var")
        assertEquals(null, risk(uid = 501, mine = true, gid = 501, myGroup = true, mode = "775".toInt(8)), "umask 002, user private group")
        assertEquals(null, risk(uid = 0, gid = 0, mode = "775".toInt(8)), "group-writable by root's group (OpenShift gid 0)")
        assertEquals(null, risk(uid = 501, mine = true, gid = 0, mode = "770".toInt(8)), "own directory, root's group")
        assertTrue(risk(mode = "777".toInt(8))!!.contains("writable by others without the sticky bit"))
        assertTrue(risk(gid = 20, mode = "775".toInt(8))!!.contains("writable by its group"))
        assertTrue(risk(uid = 1001, mode = "755".toInt(8))!!.contains("belongs to o"))
        assertTrue(
            risk(uid = 1001, mode = "1777".toInt(8))!!.contains("belongs to o"),
            "a sticky directory of another user: its owner may rename",
        )
    }

    /** An elevated Windows process creates files owned by the Administrators group: it gets a directory of its own. */
    @Test fun elevatedProcessGetsItsOwnDefaultDirectory() {
        assertEquals("kuicksilver-native-u", JvmLoader.defaultDirName("u", FakePrincipal("u")))
        val admins =
            object : java.nio.file.attribute.GroupPrincipal {
                override fun getName() = "BUILTIN\\Administrators"
            }
        assertEquals("kuicksilver-native-u-admin", JvmLoader.defaultDirName("u", admins))
        assertEquals(false, JvmLoader.isTrustedWindowsPrincipal(FakePrincipal("S-1-5-18")))
    }

    /** SYSTEM, Administrators and TrustedInstaller come from %SystemRoot%\\System32 itself; a user is never among them. */
    @Test fun trustedWindowsPrincipalsComeFromSystem32() {
        val root = System.getenv("SystemRoot") ?: return // not Windows
        val system32 =
            java.nio.file.Paths
                .get(root, "System32")
        assertTrue(JvmLoader.isTrustedWindowsPrincipal(Files.getOwner(system32)), "owner of $system32: ${Files.getOwner(system32)}")
        val acl =
            Files
                .getFileAttributeView(system32, AclFileAttributeView::class.java)
                .acl
                .map { it.principal() }
                .distinct()
        assertTrue(acl.count { JvmLoader.isTrustedWindowsPrincipal(it) } >= 2, "SYSTEM and Administrators among $acl")
        assertTrue(acl.any { !JvmLoader.isTrustedWindowsPrincipal(it) }, "Users and others are not trusted: $acl")
        val f = Files.createTempFile("ksl-trust", null)
        val owner = Files.getOwner(f).also { Files.delete(f) }
        // an elevated process's files belong to Administrators, which is trusted; a normal one's to the user, which is not
        assertEquals(owner is java.nio.file.attribute.GroupPrincipal, JvmLoader.isTrustedWindowsPrincipal(owner), "$owner")
    }

    /** Per-process directories an earlier process left are removed at a later start, unless recent, foreign or links. */
    @Test fun staleFreshDirectoriesAreSwept() {
        val tmp = Files.createTempDirectory("ksl-sweep").toFile().apply { deleteOnExit() }
        val primary = File(tmp, "kuicksilver-native-t").toPath()
        val old = File(tmp, "kuicksilver-native-t-1").apply { mkdir() }
        File(old, "libksl.so").writeText("x")
        val recent = File(tmp, "kuicksilver-native-t-2").apply { mkdir() }.apply { deleteOnExit() }
        val other = File(tmp, "kuicksilver-native-u-1").apply { mkdir() }.apply { deleteOnExit() }
        val target = Files.createTempDirectory("ksl-sweep-target").toFile().apply { deleteOnExit() }
        File(target, "keep").apply { writeText("x") }.deleteOnExit()
        val link = File(tmp, "kuicksilver-native-t-3").apply { deleteOnExit() }
        Files.createSymbolicLink(link.toPath(), target.toPath())
        val now = System.currentTimeMillis()
        old.setLastModified(now - 3_600_000)
        other.setLastModified(now - 3_600_000)
        JvmLoader.sweepStaleFreshDirs(primary, tmp.toPath(), now)
        assertTrue(!old.exists(), "a stale per-process directory is removed")
        assertTrue(recent.isDirectory, "a recent one stays: its process may be about to load from it")
        assertTrue(other.isDirectory, "another name's directory stays")
        assertTrue(File(target, "keep").isFile, "nothing is deleted through a link")
    }

    /**
     * A FIFO named like a stale per-process directory (anyone may create one in /tmp) is never opened: opening it would block
     * the start for good. The sweep returns at once and leaves it alone.
     */
    @Test fun negative_fifoInPlaceOfAStaleDirectoryDoesNotBlock() {
        if (!unix || !File("/usr/bin/mkfifo").canExecute()) return
        val tmp = Files.createTempDirectory("ksl-sweep-fifo").toFile().apply { deleteOnExit() }
        val fifo = File(tmp, "kuicksilver-native-t-9").apply { deleteOnExit() }
        val p = ProcessBuilder("/usr/bin/mkfifo", fifo.path).inheritIO().start()
        assertTrue(p.waitFor(30, TimeUnit.SECONDS) && p.exitValue() == 0, "mkfifo $fifo")
        val now = System.currentTimeMillis()
        fifo.setLastModified(now - 3_600_000)
        val sweep =
            java.util.concurrent.CompletableFuture.runAsync {
                JvmLoader.sweepStaleFreshDirs(File(tmp, "kuicksilver-native-t").toPath(), tmp.toPath(), now)
            }
        sweep.get(30, TimeUnit.SECONDS) // a blocking open of the FIFO would never return
        assertTrue(Files.exists(fifo.toPath(), java.nio.file.LinkOption.NOFOLLOW_LINKS), "the FIFO is left alone")
    }

    /** Below a directory others may write to without the sticky bit nothing is swept: a directory could be swapped for a link. */
    @Test fun negative_noSweepUnderRiskyParent() {
        if (!unix) return
        val tmp = Files.createTempDirectory("ksl-sweep-risky").toFile().apply { deleteOnExit() }
        val old = File(tmp, "kuicksilver-native-t-1").apply { mkdir() }.apply { deleteOnExit() }
        File(old, "libksl.so").apply { writeText("x") }.deleteOnExit()
        val now = System.currentTimeMillis()
        old.setLastModified(now - 3_600_000)
        chmod("777", tmp)
        val primary = File(tmp, "kuicksilver-native-t").toPath()
        JvmLoader.sweepStaleFreshDirs(primary, tmp.toPath(), now)
        assertTrue(File(old, "libksl.so").isFile, "nothing removed below a risky parent")
        chmod("700", tmp)
        JvmLoader.sweepStaleFreshDirs(primary, tmp.toPath(), now)
        assertTrue(!old.exists(), "removed once the parent is private")
    }

    /** A home directory path that is a regular file: nothing can be created below it, not even by root (the Docker JVM steps). */
    private fun noHome(): File = Files.createTempFile("ksl-no-home", null).toFile().apply { deleteOnExit() }

    private fun runChild(vararg jvmArgs: String): String {
        val javaBin =
            ProcessHandle
                .current()
                .info()
                .command()
                .orElseThrow()
        val pb =
            ProcessBuilder(
                listOf(javaBin, "-cp", System.getProperty("java.class.path")) + jvmArgs + "io.kuicksilver.native.ChildLoadMain",
            ).redirectErrorStream(true)
        // The child sees only what the test sets: $XDG_RUNTIME_DIR or $XDG_CACHE_HOME of the machine (GitHub's Linux runners
        // have a usable runtime directory) would be a private location the loader prefers, and JVM options from the
        // environment could name a work directory.
        pb.environment().keys.removeAll(childEnvRemoved)
        val p = pb.start()
        val out = p.inputStream.bufferedReader().readText()
        assertTrue(p.waitFor(60, TimeUnit.SECONDS) && p.exitValue() == 0, "child JVM loaded the library: $out")
        return out
    }

    private val childEnvRemoved = setOf("XDG_RUNTIME_DIR", "XDG_CACHE_HOME", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS")

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
        val n = assertFailsWith<KslException.NativeLoad> { JvmLoader.checkWorkDir(dir, null) }
        assertTrue(n.reason.contains("cannot be determined"), n.reason)
        if (JvmLoader.isTrustedWindowsPrincipal(view.owner)) return // elevated: a directory of Administrators is accepted for anyone
        val other = foreignUser(dir)
        val e = assertFailsWith<KslException.NativeLoad> { JvmLoader.checkWorkDir(dir, other) }
        assertTrue(e.reason.contains("owned by"), e.reason)
        val warnings = mutableListOf<String>()
        JvmLoader.checkWorkDir(dir, other, strictAcl = false, warn = warnings::add) // an explicit workdir: 0.2 accepted it
        assertTrue(warnings.single().contains("owned by"), warnings.toString())
    }

    /** A file in the work directory is not deleted when a JVM exits: another JVM may have just verified it and be about to load it. */
    @Test fun sharedLibrarySurvivesOtherJvmExit() {
        val dir = Files.createTempDirectory("ksl-workdir-shared").toFile().apply { deleteOnExit() }
        val out = runChild("-Dkuicksilver.native.workdir=" + dir.path)
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
    if ("posix" !in path.fileSystem.supportedFileAttributeViews()) return untrustedWindowsPrincipal(owner)
    val lookup = path.fileSystem.userPrincipalLookupService
    return listOf("root", "nobody", "daemon")
        .firstNotNullOfOrNull { name ->
            runCatching { lookup.lookupPrincipalByName(name) }.getOrNull()?.takeIf { it != owner }
        } ?: error("no user other than ${owner.name} to own $path")
}

/** A real Windows principal that is neither [notThis] nor trusted by the loader: BUILTIN\\Users, from the ACL of System32. */
internal fun untrustedWindowsPrincipal(notThis: java.nio.file.attribute.UserPrincipal): java.nio.file.attribute.UserPrincipal {
    val system32 =
        java.nio.file.Paths
            .get(System.getenv("SystemRoot")!!, "System32")
    return Files
        .getFileAttributeView(system32, AclFileAttributeView::class.java)
        .acl
        .map { it.principal() }
        .first { it != notThis && !JvmLoader.isTrustedWindowsPrincipal(it) }
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

    /** When the library cannot be replaced (Windows: another process has it loaded) it goes under a name with its hash. */
    @Test fun negative_unreplaceableLibraryGoesUnderItsHashedName() {
        val resourceDir = File(System.getProperty("ksl.native.resources")!!)
        val lib = File(resourceDir, "META-INF/native/" + JvmNativeNames.libraryFileName())
        val manifest = File(resourceDir, "META-INF/native/manifest.sha256").readText()
        val dir = Files.createTempDirectory("ksl-install-busy").toFile().apply { deleteOnExit() }
        val out = File(dir, lib.name).apply { deleteOnExit() }
        // a non-empty directory at the library's name: a rename cannot replace it
        File(out, "busy").apply { parentFile.mkdirs() }.apply { writeText("x") }.deleteOnExit()
        val installed = JvmLoader.installLibrary(out, lib.readBytes(), manifest).apply { deleteOnExit() }
        kotlin.test.assertEquals(JvmLoader.hashedName(lib.name, lib.readBytes()), installed.name)
        JvmLoader.verifyAgainstManifest(installed, manifest, lib.name)
        val again = JvmLoader.installLibrary(out, lib.readBytes(), manifest)
        kotlin.test.assertEquals(installed, again, "the hashed copy is reused")
        kotlin.test.assertTrue(dir.listFiles()!!.none { it.name.endsWith(".tmp") }, "no temp files left")
    }

    /** When writing the hashed copy fails because another JVM put the same copy there first, that copy is used. */
    @Test fun negative_hashedCopyRaceUsesTheWinnersCopy() {
        val resourceDir = File(System.getProperty("ksl.native.resources")!!)
        val lib = File(resourceDir, "META-INF/native/" + JvmNativeNames.libraryFileName())
        val manifest = File(resourceDir, "META-INF/native/manifest.sha256").readText()
        val dir = Files.createTempDirectory("ksl-install-race").toFile().apply { deleteOnExit() }
        val out = File(dir, lib.name).apply { deleteOnExit() }
        File(out, "busy").apply { parentFile.mkdirs() }.apply { writeText("x") }.deleteOnExit() // the plain name cannot be replaced
        val hashed = File(dir, JvmLoader.hashedName(lib.name, lib.readBytes())).apply { deleteOnExit() }
        val otherJvmWins: (java.nio.file.Path, java.nio.file.Path) -> Unit = { from, target ->
            if (target.fileName.toString() == hashed.name) {
                lib.copyTo(hashed) // the other JVM's copy, verified and in place
                throw java.io.IOException("in use by another process")
            }
            JvmLoader.replaceAtomically(from, target)
        }
        val owner = Files.getOwner(dir.toPath())
        kotlin.test.assertEquals(hashed, JvmLoader.installLibrary(out, lib.readBytes(), manifest, owner, otherJvmWins))
        kotlin.test.assertTrue(dir.listFiles()!!.none { it.name.endsWith(".tmp") }, "no temp files left")
    }
}
