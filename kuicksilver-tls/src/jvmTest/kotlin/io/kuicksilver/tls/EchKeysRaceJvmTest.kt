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
 * lost). The interleavings are forced with the test hooks of [EchServerKeys]. A wait that must succeed has [MUST] (a slow
 * machine still meets it); only a wait whose timeout is the expected outcome (the code under test serialized the threads)
 * is short ([SERIALIZED]), and the run goes on after it.
 */
class EchKeysRaceJvmTest {
    private companion object {
        const val MUST = 30L // seconds: a wait that must succeed
        const val SERIALIZED = 1L // seconds: a wait expected to time out
    }

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
        val c = KslQuicCrypto.newSession(Fixtures.client { ech { configList = list } })
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
        val lease = KslContext.acquire(Fixtures.server { ech { this.keys = keys } }, quic = true)
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
        val server = Fixtures.server { ech { this.keys = keys } }
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
                    assertTrue(go.await(MUST, TimeUnit.SECONDS))
                }
            }
            val t = thread { keys.rotate(listOf(EchKey(EchTestKeys.B))) }
            assertTrue(reached.await(MUST, TimeUnit.SECONDS))
            keys.rotate(listOf(EchKey(EchTestKeys.A))) // the main thread's rotation completes first
            lease.ctx.ensureEchKeys() // a session start takes it
            go.countDown()
            t.join(MUST * 1000)
            assertTrue(!t.isAlive, "the slow rotation finished")
            keys.beforeSwapForTest = null
            assertEquals(EchStatus.Accepted, handshake(listOf(EchTestKeys.B), server), "the last rotation (B) is in use")
        } finally {
            lease.close()
        }
    }

    /**
     * N3: one apply at a time. A session start that finds a newer set while another one applies waits for it (blocked on the
     * lock, not spinning), and never enters the native apply beside it.
     */
    @Test fun appliesNeverOverlap() {
        val keys = EchServerKeys(listOf(EchKey(EchTestKeys.A)))
        val server = Fixtures.server { ech { this.keys = keys } }
        val lease = KslContext.acquire(server, quic = true)
        try {
            keys.rotate(listOf(EchKey(EchTestKeys.B)))
            val inside =
                java.util.concurrent.atomic
                    .AtomicInteger(0)
            val overlap =
                java.util.concurrent.atomic
                    .AtomicBoolean(false)
            val firstIn = CountDownLatch(1)
            val secondIn = CountDownLatch(1)
            keys.applyHookForTest = { before, _ ->
                if (before) {
                    if (inside.incrementAndGet() > 1) overlap.set(true)
                    if (firstIn.count == 1L) {
                        firstIn.countDown()
                        secondIn.await(SERIALIZED, TimeUnit.SECONDS) // the second may not come in: the timeout is expected
                    } else {
                        secondIn.countDown()
                    }
                } else {
                    inside.decrementAndGet()
                }
            }
            val a = thread { lease.ctx.ensureEchKeys() }
            assertTrue(firstIn.await(MUST, TimeUnit.SECONDS))
            keys.rotate(listOf(EchKey(EchTestKeys.A))) // a newer set, so the second start has one to apply
            val b = thread { lease.ctx.ensureEchKeys() }
            a.join(MUST * 1000)
            b.join(MUST * 1000)
            keys.applyHookForTest = null
            assertTrue(!a.isAlive && !b.isAlive, "both session starts finished")
            assertTrue(!overlap.get(), "two applies ran at once")
            assertEquals(keys.version, lease.ctx.echAppliedVersion)
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
        val server = Fixtures.server { ech { this.keys = keys } }
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
                    olderGo.await(MUST, TimeUnit.SECONDS)
                } else if (!before && v > v2) {
                    newerApplied.countDown()
                    newerGo.await(MUST, TimeUnit.SECONDS)
                }
            }
            val older = thread { lease.ctx.ensureEchKeys() }
            assertTrue(olderRead.await(MUST, TimeUnit.SECONDS))
            keys.rotate(listOf(EchKey(EchTestKeys.A))) // v3
            val newer = thread { lease.ctx.ensureEchKeys() }
            newerApplied.await(SERIALIZED, TimeUnit.SECONDS) // with the applies serialized, the newer one waits for the older one
            olderGo.countDown()
            older.join(MUST * 1000)
            newerGo.countDown()
            newer.join(MUST * 1000)
            assertTrue(!older.isAlive && !newer.isAlive, "both session starts finished")
            keys.applyHookForTest = null
            assertEquals(keys.version, lease.ctx.echAppliedVersion)
            assertEquals(EchStatus.Accepted, handshake(listOf(EchTestKeys.A), server), "the newest set (A) is in use")
        } finally {
            lease.close()
        }
    }
}
