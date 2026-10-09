// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.native

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import java.io.File
import java.net.URLClassLoader
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.test.fail

/** The non-throwing availability check: classification of every load failure, caching, and one shared load attempt. */
class KslAvailabilityTest {
    private val resourceDir = File(System.getProperty("ksl.native.resources")!!)

    @Test fun hostLibraryIsAvailable() {
        assertSame(NativeAvailability.Available, KslLoader.availability())
        assertTrue(KslLoader.isAvailable())
        KslLoader.ensureLoaded() // the same cached outcome: no throw
    }

    @Test fun missingExplicitPathIsUnavailableWithoutThrowing() {
        val a = JvmLoader.attempt(mapOf("kuicksilver.native.path" to "/nonexistent/libksl.so"), KslLoader::class.java.classLoader)
        assertIs<NativeAvailability.Unavailable>(a)
        assertEquals(NativeUnavailableReason.LoadFailed, a.reason)
        assertIs<KslException.NativeLoad>(a.cause)
        assertTrue(a.detail.contains("does not exist"), a.detail)
    }

    @Test fun noResourceForTheHostIsNoLibraryForPlatform() {
        val empty = object : ClassLoader(null) {}
        val a = JvmLoader.attempt(emptyMap(), empty)
        assertIs<NativeAvailability.Unavailable>(a)
        assertEquals(NativeUnavailableReason.NoLibraryForPlatform, a.reason)
        assertTrue(a.detail.contains("not on the classpath"), a.detail)
    }

    @Test fun negative_tamperedResourceIsIntegrityMismatchAndNeverLoaded() {
        val root = Files.createTempDirectory("ksl-avail").toFile().apply { deleteOnExit() }
        val native = File(root, "META-INF/native").apply { mkdirs() }
        val lib = File(resourceDir, "META-INF/native/" + JvmNativeNames.libraryFileName())
        val copy = File(native, lib.name)
        copy.writeBytes(lib.readBytes().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 0x5a).toByte() })
        File(resourceDir, "META-INF/native/manifest.sha256").copyTo(File(native, "manifest.sha256"))
        val workDir = Files.createTempDirectory("ksl-avail-work").toFile().apply { deleteOnExit() }
        URLClassLoader(arrayOf(root.toURI().toURL()), null).use { cl ->
            val a = JvmLoader.attempt(mapOf("kuicksilver.native.workdir" to workDir.path), cl)
            assertIs<NativeAvailability.Unavailable>(a)
            assertEquals(NativeUnavailableReason.IntegrityMismatch, a.reason)
            assertTrue(a.detail.contains("sha256"), a.detail)
        }
        assertTrue(workDir.listFiles()!!.none { it.name == lib.name }, "a tampered library is never installed")
    }

    @Test fun failuresAreClassified() {
        assertEquals(NativeUnavailableReason.AbiMismatch, unavailable(KslException.AbiMismatch(3, 4)).reason)
        assertEquals(NativeUnavailableReason.LoadFailed, unavailable(KslException.Version("3.0.2", "3.5+")).reason)
        assertEquals(NativeUnavailableReason.LoadFailed, unavailable(KslException.MissingSymbol("SSL_set_quic_tls_cbs")).reason)
        assertEquals(NativeUnavailableReason.LoadFailed, unavailable(KslException.NativeLoad("osx", "osx-aarch_64", "x")).reason)
        assertEquals(NativeUnavailableReason.LoadFailed, unavailable(UnsatisfiedLinkError("no symbol")).reason)
        val io = java.io.IOException("disk full")
        val u = unavailable(io)
        assertSame(io, u.cause)
        assertTrue(u.detail.contains("disk full"), u.detail)
    }

    @Test fun unavailableIsCachedAndEnsureLoadedThrowsTheSameException() {
        val attempts = AtomicInteger()
        val failure = KslException.NativeLoad("linux", "linux-riscv64", "resource not on the classpath")
        val state =
            KslLoadState {
                attempts.incrementAndGet()
                unavailable(failure)
            }
        val first = state.availability()
        assertIs<NativeAvailability.Unavailable>(first)
        assertSame(first, state.availability())
        val e1 = runCatching { state.ensureLoaded() }.exceptionOrNull() ?: fail("ensureLoaded must throw")
        val e2 = runCatching { state.ensureLoaded() }.exceptionOrNull() ?: fail("ensureLoaded must throw")
        assertSame(failure, e1)
        assertSame(failure, e2)
        assertEquals(1, attempts.get(), "one load attempt for every call")
    }

    @Test fun ensureLoadedFirstSharesItsAttemptWithAvailability() {
        val attempts = AtomicInteger()
        val state = KslLoadState { attempts.incrementAndGet().let { NativeAvailability.Available } }
        state.ensureLoaded()
        state.ensureLoaded()
        assertSame(NativeAvailability.Available, state.availability())
        assertEquals(1, attempts.get())
    }

    @Test fun concurrentFirstCallsMakeOneAttempt() {
        val attempts = AtomicInteger()
        val state = KslLoadState { attempts.incrementAndGet().let { NativeAvailability.Available } }
        val pool = Executors.newFixedThreadPool(8)
        val start = CountDownLatch(1)
        val results =
            (1..8).map {
                pool.submit<NativeAvailability> {
                    start.await()
                    state.availability()
                }
            }
        start.countDown()
        results.forEach { assertSame(NativeAvailability.Available, it.get(10, TimeUnit.SECONDS)) }
        pool.shutdown()
        assertEquals(1, attempts.get())
    }

    /** End to end in a fresh JVM, where the real [KslLoader] has not loaded anything yet. */
    @Test fun forkedJvmWithMissingExplicitPathFallsBackWithoutThrowing() {
        val java = File(System.getProperty("java.home"), "bin/java").path
        val p =
            ProcessBuilder(
                java,
                "-cp",
                System.getProperty("java.class.path"),
                "-Dkuicksilver.native.path=/nonexistent/libksl.so",
                AvailabilityProbe::class.java.name,
            ).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        assertTrue(p.waitFor(60, TimeUnit.SECONDS), out)
        assertEquals(0, p.exitValue(), out)
        assertTrue(out.contains("available=false reason=LoadFailed"), out)
        assertTrue(out.contains("ensureLoaded=NativeLoad same=true"), out)
    }
}

/** Run by [KslAvailabilityTest.forkedJvmWithMissingExplicitPathFallsBackWithoutThrowing] in a separate JVM. */
object AvailabilityProbe {
    @JvmStatic fun main(args: Array<String>) {
        val a = KslLoader.availability()
        println("available=${KslLoader.isAvailable()} reason=${(a as? NativeAvailability.Unavailable)?.reason}")
        val e1 = runCatching { KslLoader.ensureLoaded() }.exceptionOrNull()
        val e2 = runCatching { KslLoader.ensureLoaded() }.exceptionOrNull()
        println(
            "ensureLoaded=${e1?.javaClass?.simpleName} same=${e1 != null && e1 === e2 && e1 === (a as? NativeAvailability.Unavailable)?.cause}",
        )
    }
}
