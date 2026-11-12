// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.server

import io.ktor.util.logging.KtorSimpleLogger
import io.ktor.util.logging.Logger
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.io.IOException
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** The client CA file watcher (`kuicksilver.tls.clientCa` with `kuicksilver.tls.reloadInterval`), on files in memory. */
class ClientCaFileWatcherTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val pemA = TestCerts.toPem("CERTIFICATE", TestCerts.testCa)
    private val pemB = TestCerts.toPem("CERTIFICATE", TestCerts.otherCa)
    private val caA = Certificate(TestCerts.testCa)
    private val caB = Certificate(TestCerts.otherCa)

    private val files = HashMap<String, String>()
    private var reads = 0

    /** Warnings and infos, in order. */
    private class Lines : Logger by KtorSimpleLogger("io.kuicksilver.test") {
        val lines = ArrayList<Pair<String, String>>()

        override fun warn(message: String) {
            lines += "WARN" to message
        }

        override fun info(message: String) {
            lines += "INFO" to message
        }

        override fun debug(message: String) {
            lines += "DEBUG" to message
        }

        fun count(level: String) = lines.count { it.first == level }
    }

    private fun servingA(): TrustConfig.ReloadableCa {
        files["ca.pem"] = pemA
        return TrustConfig.reloadable(TrustConfig.AnchoredCa(listOf(caA)))
    }

    private fun watcher(
        r: TrustConfig.ReloadableCa,
        log: Logger,
    ) = ClientCaFileWatcher(
        "ca.pem",
        r,
        log,
        readText = {
            reads++
            files[it] ?: throw IOException("$it: no such file")
        },
    )

    @Test fun unchangedFileNeverReloads() {
        val r = servingA()
        val before = r.current
        val w = watcher(r, Lines())
        repeat(3) { assertFalse(w.checkOnce()) }
        assertEquals(IdentityFileWatcher.Outcome.Unchanged, w.lastOutcome)
        assertSame(before, r.current)
    }

    @Test fun changedBundleAppliedAfterTwoEqualReads() {
        val r = servingA()
        val log = Lines()
        val w = watcher(r, log)
        files["ca.pem"] = pemB
        assertFalse(w.checkOnce())
        assertEquals(IdentityFileWatcher.Outcome.Settling, w.lastOutcome, "read twice before it is used")
        assertEquals(listOf(caA), r.current.roots)
        files["ca.pem"] = pemB + pemA // the writer went on: read once more
        assertFalse(w.checkOnce())
        assertEquals(IdentityFileWatcher.Outcome.Settling, w.lastOutcome)
        assertTrue(w.checkOnce())
        assertEquals(listOf(caB, caA), r.current.roots, "the whole bundle")
        assertEquals("client CA bundle reloaded from ca.pem: 2 certificate(s)", log.lines.single { it.first == "INFO" }.second)
        assertFalse(w.checkOnce(), "nothing changed since")
    }

    @Test fun negative_bundleWithoutAValidCertificateKeepsOldAndWarnsOnce() {
        val r = servingA()
        val log = Lines()
        val w = watcher(r, log)
        files["ca.pem"] = TestCerts.toPem("CERTIFICATE", TestCerts.expired)
        repeat(5) { assertFalse(w.checkOnce()) }
        assertEquals(listOf(caA), r.current.roots, "the bundle in use stays")
        assertEquals(1, log.count("WARN"), "the same failure is warned about once: ${log.lines}")
        assertTrue("not reloaded" in log.lines.first { it.first == "WARN" }.second)
        assertEquals(3, log.count("DEBUG"), "its repeats go to debug")
    }

    @Test fun negative_fileWithPrivateKeyOrDamagedRefused() {
        val r = servingA()
        val log = Lines()
        val w = watcher(r, log)
        files["ca.pem"] = pemB + TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey)
        repeat(2) { assertFalse(w.checkOnce()) }
        assertEquals(IdentityFileWatcher.Outcome.Failed, w.lastOutcome)
        assertTrue("contains a private key; it must hold CA certificates only" in log.lines.first { it.first == "WARN" }.second)
        assertFalse(log.lines.any { "BEGIN PRIVATE KEY" in it.second }, "${log.lines}")
        files["ca.pem"] = "-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----\n"
        assertFalse(w.checkOnce())
        assertEquals(IdentityFileWatcher.Outcome.Failed, w.lastOutcome)
        files.remove("ca.pem")
        assertFalse(w.checkOnce())
        assertEquals(listOf(caA), r.current.roots)
        files["ca.pem"] = pemB
        assertFalse(w.checkOnce())
        assertTrue(w.checkOnce(), "a good file is applied after the failures")
        assertEquals(listOf(caB), r.current.roots)
    }

    /** Every certificate of the bundle is an anchor: a leaf among them is applied, with a warning that says what it means. */
    @Test fun nonCaCertificateInTheBundleWarns() {
        val r = servingA()
        val log = Lines()
        val w = watcher(r, log)
        files["ca.pem"] = pemB + TestCerts.toPem("CERTIFICATE", TestCerts.client)
        assertFalse(w.checkOnce())
        assertTrue(w.checkOnce())
        assertEquals(2, r.current.roots.size)
        val warning = log.lines.single { it.first == "WARN" }.second
        assertTrue("1 certificate(s) that are not CA certificates" in warning, warning)
        files["ca.pem"] = pemB
        assertFalse(w.checkOnce())
        assertTrue(w.checkOnce())
        assertEquals(1, log.count("WARN"), "a bundle of CA certificates only: no warning")
    }

    /** The reader the watcher uses on disk refuses a key with the CA file's own words, as the watcher's own check does. */
    @Test fun negative_privateKeyMessageNamesTheCaFile() {
        val r = servingA()
        val log = Lines()
        val w =
            ClientCaFileWatcher("ca.pem", r, log, readText = { throw PrivateKeyInPemFile(it, CA_FILE_HOLDS) })
        assertFalse(w.checkOnce())
        assertEquals(
            "client CA bundle not reloaded from ca.pem, the current one stays: ca.pem contains a private key; it must hold CA certificates only",
            log.lines.single { it.first == "WARN" }.second,
        )
    }

    @Test fun pollingOnVirtualTime() =
        runTest {
            val r = servingA()
            val w = watcher(r, Lines())
            val job = backgroundScope.launch { w.run(1.hours) }
            runCurrent()
            assertEquals(1, reads, "a check at once")
            advanceTimeBy(2.hours + 1.milliseconds)
            assertEquals(3, reads, "one check an hour while nothing changes")
            files["ca.pem"] = pemB
            advanceTimeBy(1.hours)
            assertEquals(IdentityFileWatcher.Outcome.Settling, w.lastOutcome)
            advanceTimeBy(1.seconds)
            assertEquals(listOf(caB), r.current.roots, "applied one settle period after the change was seen")
            advanceTimeBy(1.seconds)
            assertEquals(IdentityFileWatcher.Outcome.Unchanged, w.lastOutcome, "read once more one settle period after the reload")
            files.remove("ca.pem")
            advanceTimeBy(1.hours)
            assertEquals(IdentityFileWatcher.Outcome.Failed, w.lastOutcome)
            val first = reads
            advanceTimeBy(1.seconds)
            assertEquals(first + 1, reads, "first retry after 1 s")
            assertEquals(listOf(caB), r.current.roots)
            job.cancel()
        }
}
