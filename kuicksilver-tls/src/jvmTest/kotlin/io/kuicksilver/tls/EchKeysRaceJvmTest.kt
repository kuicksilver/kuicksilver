// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.runBlocking
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A server's ECH keys under concurrency: a context gets its keys when it is built, before any session, and racing rotations
 * and session starts never leave a context decrypting with an older set than the version it records (so a rotation is never
 * lost). The interleavings are forced with the test hooks of [EchServerKeys]; a wait that times out means the code under
 * test serialized the threads (what it should do), and the run goes on.
 */
class EchKeysRaceJvmTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        runBlocking { SessionCache.Default.clear() }
    }

    private fun listOf(pem: String): EchConfigList {
        val body = pem.substringAfter("-----BEGIN ECHCONFIG-----").substringBefore("-----END ECHCONFIG-----")
        return EchConfigList.parseBase64(body.lines().joinToString(""))
    }

    private fun handshake(
        list: EchConfigList,
        server: TlsConfig,
    ): EchStatus {
        val c = KslQuicCrypto.newSession(Fixtures.client { echConfigList = list })
        val s = KslQuicCrypto.newSession(server)
        c.setTransportParameters(Fixtures.tp)
        s.setTransportParameters(Fixtures.tp)
        val p = Pump(c, s)
        try {
            p.run()
            return p.c.echStatus
        } finally {
            p.close()
        }
    }

    /** MUST-1: the keys are in the context once it is built, not given by the first session made from it. */
    @Test fun keysAreAppliedWhenTheContextIsBuilt() {
        val keys = EchServerKeys(listOf(EchKey(EchTestKeys.A)))
        val lease = KslContext.acquire(Fixtures.server { echKeys = keys }, quic = true)
        try {
            assertEquals(keys.version, lease.ctx.echAppliedVersion, "applied by build, before any session")
        } finally {
            lease.close()
        }
    }

    /**
     * Two rotations at once: each gets its own version, so the context that applied the first one still takes the second
     * (with equal versions it took the second for applied already, and kept decrypting with the first).
     */
    @Test fun concurrentRotationsGetDistinctVersions() {
        val keys = EchServerKeys(listOf(EchKey(EchTestKeys.A)))
        val server = Fixtures.server { echKeys = keys }
        val lease = KslContext.acquire(server, quic = true)
        try {
            val reached = CountDownLatch(1)
            val go = CountDownLatch(1)
            val slow = Thread.currentThread().let { main -> { Thread.currentThread() !== main } }
            var first = true
            keys.beforeSwapForTest = {
                if (slow() && first) {
                    first = false
                    reached.countDown()
                    go.await(2, TimeUnit.SECONDS)
                }
            }
            val t = thread { keys.rotate(listOf(EchKey(EchTestKeys.B))) }
            assertTrue(reached.await(5, TimeUnit.SECONDS))
            keys.rotate(listOf(EchKey(EchTestKeys.A))) // the main thread's rotation completes first
            lease.ctx.ensureEchKeys() // a session start takes it
            go.countDown()
            t.join(5_000)
            keys.beforeSwapForTest = null
            assertEquals(EchStatus.Accepted, handshake(listOf(EchTestKeys.B), server), "the last rotation (B) is in use")
        } finally {
            lease.close()
        }
    }

    /**
     * Two session starts after two rotations: the one that read the older set applies it after the newer one went in, and
     * the newer one records its version last. The context must still decrypt with the newest set.
     */
    @Test fun racingAppliesNeverLeaveAnOlderSet() {
        val keys = EchServerKeys(listOf(EchKey(EchTestKeys.A)))
        val server = Fixtures.server { echKeys = keys }
        val lease = KslContext.acquire(server, quic = true)
        try {
            keys.rotate(listOf(EchKey(EchTestKeys.B))) // v2
            val olderRead = CountDownLatch(1)
            val olderGo = CountDownLatch(1)
            val newerApplied = CountDownLatch(1)
            val newerGo = CountDownLatch(1)
            val v2 = keys.version
            keys.applyHookForTest = { before, v ->
                if (before && v == v2) {
                    olderRead.countDown()
                    olderGo.await(2, TimeUnit.SECONDS)
                } else if (!before && v > v2) {
                    newerApplied.countDown()
                    newerGo.await(2, TimeUnit.SECONDS)
                }
            }
            val older = thread { lease.ctx.ensureEchKeys() }
            assertTrue(olderRead.await(5, TimeUnit.SECONDS))
            keys.rotate(listOf(EchKey(EchTestKeys.A))) // v3
            val newer = thread { lease.ctx.ensureEchKeys() }
            newerApplied.await(1, TimeUnit.SECONDS) // with the applies serialized, the newer one waits for the older one
            olderGo.countDown()
            older.join(5_000)
            newerGo.countDown()
            newer.join(5_000)
            keys.applyHookForTest = null
            assertEquals(keys.version, lease.ctx.echAppliedVersion)
            assertEquals(EchStatus.Accepted, handshake(listOf(EchTestKeys.A), server), "the newest set (A) is in use")
        } finally {
            lease.close()
        }
    }
}
