// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.server

import io.ktor.util.logging.KtorSimpleLogger
import io.ktor.util.logging.Logger
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsIdentity
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.io.IOException
import kotlin.io.encoding.Base64
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** Every line a logger got, all levels: for asserting what the watcher says, and what it never says. */
private class AllLines : Logger by KtorSimpleLogger("io.kuicksilver.test") {
    val lines = ArrayList<Pair<String, String>>()

    override fun error(message: String) {
        lines += "ERROR" to message
    }

    override fun error(
        message: String,
        cause: Throwable,
    ) {
        lines += "ERROR" to "$message $cause"
    }

    override fun warn(message: String) {
        lines += "WARN" to message
    }

    override fun warn(
        message: String,
        cause: Throwable,
    ) {
        lines += "WARN" to "$message $cause"
    }

    override fun info(message: String) {
        lines += "INFO" to message
    }

    override fun info(
        message: String,
        cause: Throwable,
    ) {
        lines += "INFO" to "$message $cause"
    }

    override fun debug(message: String) {
        lines += "DEBUG" to message
    }

    override fun debug(
        message: String,
        cause: Throwable,
    ) {
        lines += "DEBUG" to "$message $cause"
    }

    fun count(level: String) = lines.count { it.first == level }
}

/**
 * The PEM file watcher of `kuicksilver.tls.reloadInterval`, on files held in memory and on virtual time: what triggers a
 * reload, how a half-written pair is waited out, how errors are retried and logged.
 */
class IdentityFileWatcherTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val chainA = TestCerts.toPem("CERTIFICATE", TestCerts.server)
    private val keyA = TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey)
    private val chainB =
        TestCerts.toPem("CERTIFICATE", TestCerts.serverViaIntermediate) + TestCerts.toPem("CERTIFICATE", TestCerts.intermediate)
    private val keyB = TestCerts.toPem("PRIVATE KEY", TestCerts.serverViaIntermediateKey)
    private val leafA = Certificate(TestCerts.server)
    private val leafB = Certificate(TestCerts.serverViaIntermediate)

    private val files = HashMap<String, String>()
    private var reads = 0

    private fun watcher(
        r: TlsIdentity.Reloadable,
        log: Logger,
    ) = IdentityFileWatcher(
        "chain.pem",
        "key.pem",
        r,
        log,
        readText = {
            reads++
            files[it] ?: throw IOException("$it: no such file")
        },
        readKey = { (files[it] ?: throw IOException("$it: no such file")).toCharArray() },
    )

    private fun servingA(): TlsIdentity.Reloadable {
        files["chain.pem"] = chainA
        files["key.pem"] = keyA
        return TlsIdentity.reloadable(TlsIdentity.fromPem(chainA, keyA.toCharArray()))
    }

    @Test fun unchangedFilesNeverReload() =
        runTest {
            val r = servingA()
            val before = r.current
            val w = watcher(r, AllLines())
            repeat(3) { assertFalse(w.checkOnce()) }
            assertEquals(IdentityFileWatcher.Outcome.Unchanged, w.lastOutcome)
            assertTrue(before === r.current)
            r.close()
        }

    /** certbot writes `fullchain.pem` before `privkey.pem`: until the key matches, the old identity serves and the pair is retried. */
    @Test fun chainWrittenBeforeKeyRetriesUntilPairMatches() =
        runTest {
            val r = servingA()
            val log = AllLines()
            val w = watcher(r, log)
            files["chain.pem"] = chainB
            assertFalse(w.checkOnce())
            assertEquals(IdentityFileWatcher.Outcome.Settling, w.lastOutcome, "a changed chain is read twice before it is used")
            assertFalse(w.checkOnce())
            assertEquals(IdentityFileWatcher.Outcome.Failed, w.lastOutcome, "the new chain with the old key")
            assertEquals(leafA, r.current.chain[0], "the old identity stays")
            assertEquals(1, log.count("WARN"), "${log.lines}")
            assertTrue("not reloaded" in log.lines.first { it.first == "WARN" }.second)
            files["key.pem"] = keyB
            assertTrue(w.checkOnce())
            assertEquals(listOf(leafB, Certificate(TestCerts.intermediate)), r.current.chain)
            assertEquals(1, log.count("INFO"))
            assertFalse(w.checkOnce(), "nothing changed since")
            r.close()
        }

    /** A chain file caught between two of its certificates is never served: the full chain differs from the cut one. */
    @Test fun chainCutBetweenCertificatesIsNotServed() =
        runTest {
            val r = servingA()
            val w = watcher(r, AllLines())
            files["key.pem"] = keyB
            files["chain.pem"] = TestCerts.toPem("CERTIFICATE", TestCerts.serverViaIntermediate) // the leaf only, so far
            assertFalse(w.checkOnce())
            files["chain.pem"] = chainB
            assertFalse(w.checkOnce())
            assertEquals(IdentityFileWatcher.Outcome.Settling, w.lastOutcome, "the text changed again: read it once more")
            assertEquals(leafA, r.current.chain[0])
            assertTrue(w.checkOnce())
            assertEquals(2, r.current.chain.size, "the whole chain")
            r.close()
        }

    @Test fun negative_expiredChainKeepsOldAndWarnsOnce() =
        runTest {
            val r = servingA()
            val log = AllLines()
            val w = watcher(r, log)
            files["chain.pem"] = TestCerts.toPem("CERTIFICATE", TestCerts.expired)
            files["key.pem"] = TestCerts.toPem("PRIVATE KEY", TestCerts.expiredKey)
            repeat(5) { assertFalse(w.checkOnce()) }
            assertEquals(leafA, r.current.chain[0])
            assertEquals(1, log.count("WARN"), "the same failure is warned about once: ${log.lines}")
            assertTrue("expired" in log.lines.first { it.first == "WARN" }.second)
            assertEquals(3, log.count("DEBUG"), "its repeats go to debug")
            r.close()
        }

    /** Whatever goes wrong, no log line carries key material: not the PEM header of a key, not a stretch of its Base64. */
    @Test fun negative_watcherNeverLogsKeyMaterial() =
        runTest {
            val r = servingA()
            val log = AllLines()
            val w = watcher(r, log)
            val keyBodies =
                listOf(
                    TestCerts.serverKey,
                    TestCerts.serverViaIntermediateKey,
                    TestCerts.serverOtherKeyKey,
                ).map { Base64.encode(it) }
            // a mismatched key, a truncated key, a key file that is gone, a chain file that is not PEM, then a good pair
            files["chain.pem"] = chainB
            files["key.pem"] = TestCerts.toPem("PRIVATE KEY", TestCerts.serverOtherKeyKey)
            repeat(2) { w.checkOnce() }
            files["key.pem"] = keyB.substring(0, keyB.length / 2)
            w.checkOnce()
            files.remove("key.pem")
            w.checkOnce()
            files["chain.pem"] = "-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----\n"
            w.checkOnce()
            files["chain.pem"] = chainB
            files["key.pem"] = keyB
            repeat(2) { w.checkOnce() }
            assertEquals(leafB, r.current.chain[0])
            assertTrue(log.count("WARN") >= 4, "${log.lines}")
            for ((_, line) in log.lines) {
                assertFalse("BEGIN PRIVATE KEY" in line, line)
                for (body in keyBodies) {
                    for (i in 0..body.length - 16 step 8) assertFalse(body.substring(i, i + 16) in line, line)
                }
            }
            r.close()
        }

    /**
     * The loop on virtual time: one read per interval while nothing changes (no busy polling), a change applied one settle
     * period after the tick that saw it, and failures retried after 1 s, 2 s, 4 s, ... up to the interval.
     */

    /** A chain file that also holds a private key (a combined PEM) is refused, and its text is not kept for a second read. */
    @Test fun negative_chainFileWithPrivateKeyRefused() =
        runTest {
            val r = servingA()
            val log = AllLines()
            val w = watcher(r, log)
            files["chain.pem"] = chainB + keyB
            files["key.pem"] = keyB
            repeat(3) { assertFalse(w.checkOnce()) }
            assertEquals(IdentityFileWatcher.Outcome.Failed, w.lastOutcome)
            assertEquals(leafA, r.current.chain[0])
            assertTrue("contains a private key" in log.lines.first { it.first == "WARN" }.second)
            files["chain.pem"] = chainB
            assertFalse(w.checkOnce())
            assertTrue(w.checkOnce(), "the chain alone is applied")
            r.close()
        }

    /** After a reload the file is read again one settle period later: a chain cut while its writer paused is corrected then. */
    @Test fun chainCompletedAfterReloadIsAppliedOneSettleLater() =
        runTest {
            val r = servingA()
            val w = watcher(r, AllLines())
            val job = backgroundScope.launch { w.run(1.hours) }
            runCurrent()
            files["key.pem"] = keyB
            files["chain.pem"] = TestCerts.toPem("CERTIFICATE", TestCerts.serverViaIntermediate) // the writer paused after the leaf
            advanceTimeBy(1.hours + 1.seconds + 1.milliseconds)
            assertEquals(1, r.current.chain.size, "two equal reads: the cut chain was applied")
            files["chain.pem"] = chainB
            advanceTimeBy(2.seconds)
            assertEquals(2, r.current.chain.size, "corrected two settle periods later, not an interval later")
            job.cancel()
            r.close()
        }

    @Test fun pollingOnVirtualTime() =
        runTest {
            val r = servingA()
            val w = watcher(r, AllLines())
            val job = backgroundScope.launch { w.run(1.hours) }
            runCurrent()
            assertEquals(1, reads, "a check at once")
            advanceTimeBy(3.hours + 1.milliseconds)
            assertEquals(4, reads, "one check an hour while nothing changes")
            files["chain.pem"] = chainB
            files["key.pem"] = keyB
            advanceTimeBy(1.hours)
            assertEquals(IdentityFileWatcher.Outcome.Settling, w.lastOutcome)
            assertEquals(leafA, r.current.chain[0])
            advanceTimeBy(1.seconds)
            assertEquals(leafB, r.current.chain[0], "applied one settle period after the change was seen")
            val applied = reads
            advanceTimeBy(1.seconds)
            assertEquals(applied + 1, reads, "read once more one settle period after the reload")
            assertEquals(IdentityFileWatcher.Outcome.Unchanged, w.lastOutcome)
            // a broken chain from now on: retried quickly at first, then less and less often, never more than the interval
            files["chain.pem"] = "-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----\n"
            advanceTimeBy(1.hours)
            assertEquals(IdentityFileWatcher.Outcome.Failed, w.lastOutcome)
            val first = reads
            advanceTimeBy(1.seconds)
            assertEquals(first + 1, reads, "first retry after 1 s")
            advanceTimeBy(10.hours)
            // after the first retry: 2, 4, ..., 2048 s (11 retries, 4095 s after the failure), then one an hour (8 in the rest)
            assertEquals(20, reads - first, "reads in the 10 h after the failure")
            assertEquals(leafB, r.current.chain[0])
            job.cancel()
            r.close()
        }
}
