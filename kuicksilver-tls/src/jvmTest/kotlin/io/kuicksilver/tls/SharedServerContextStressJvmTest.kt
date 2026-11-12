// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader
import java.util.Collections
import java.util.IdentityHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The shared server contexts under concurrency (P.3): sessions of ten configurations (more than the eight an identity keeps,
 * so the cache evicts all the time) are built and closed on four threads (sessions only, no handshakes: what is under test is
 * acquiring and releasing the shared contexts) while a fifth reloads the identity 60 times, spread over the workers' run. No
 * session may fail to build while the identity is open, and once everything is closed every context seen is freed and `ksl.ctx` / `ksl.pkey`
 * are back where they were.
 */
class SharedServerContextStressJvmTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun identityA() = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())

    private fun identityB() =
        TlsIdentity.fromDer(listOf(TestCerts.serverViaIntermediate, TestCerts.intermediate), TestCerts.serverViaIntermediateKey.copyOf())

    @Test fun sessionsReloadsAndEvictionsAtOnce() {
        val before = Ksl.liveObjects()
        val r = TlsIdentity.reloadable(identityA())
        val configs =
            List(10) {
                tlsConfig(TlsRole.Server) {
                    alpn = listOf("h3")
                    identity = r
                }
            }
        val seen = Collections.synchronizedSet(Collections.newSetFromMap(IdentityHashMap<KslContext, Boolean>()))
        val failures = Collections.synchronizedList(ArrayList<Throwable>())
        val start = CountDownLatch(1)
        val built =
            java.util.concurrent.atomic
                .AtomicInteger()
        val reloads =
            java.util.concurrent.atomic
                .AtomicInteger()
        // one deadline for the whole test: a thread still running past it fails the test with what it got through
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60)

        fun running() = System.nanoTime() < deadline && failures.isEmpty()
        val workers =
            List(4) { w ->
                Thread {
                    start.await()
                    val open = ArrayDeque<KslQuicTlsSession>()
                    try {
                        // at least 400 sessions each, and on until the reloader is through: every reload meets running workers
                        var i = 0
                        while ((i < 400 || reloads.get() < 60) && running()) {
                            val s =
                                KslQuicCrypto.newSession(
                                    configs[(w * 7 + i) % configs.size],
                                    earlyData = i % 2 == 0,
                                ) as KslQuicTlsSession
                            seen += s.context
                            built.incrementAndGet()
                            open += s
                            if (open.size > 12) repeat(6) { open.removeFirst().close() }
                            i++
                        }
                    } catch (t: Throwable) {
                        failures += t
                    } finally {
                        open.forEach { it.close() }
                    }
                }
            }
        val reloader =
            Thread {
                start.await()
                try {
                    // one reload per 25 sessions built: the reloads land throughout the workers' run, not at its start
                    var done = 0
                    while (done < 60 && running()) {
                        if (built.get() >= (done + 1) * 25) {
                            r.reload(if (done++ % 2 == 0) identityB() else identityA())
                            reloads.incrementAndGet()
                        } else {
                            Thread.onSpinWait()
                        }
                    }
                } catch (t: Throwable) {
                    failures += t
                }
            }
        (workers + reloader).forEach { it.start() }
        start.countDown()
        (workers + reloader).forEach {
            it.join(maxOf(1L, TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime()) + 5_000))
            assertTrue(!it.isAlive, "a thread did not finish within the 60 s deadline: ${built.get()} sessions, ${reloads.get()} reloads")
        }
        assertEquals(emptyList(), failures.toList(), "no failure while the identity is open")
        assertEquals(60, reloads.get(), "all 60 reloads ran while the workers built sessions")
        r.close()
        assertTrue(seen.size > 10, "contexts were rebuilt by reloads and evictions (${seen.size})")
        assertEquals(emptyList(), seen.filter { !it.isFreed }, "every context is freed once its sessions and the identity are closed")
        val after = Ksl.liveObjects()
        // other tests may still be freeing theirs, so never more than before
        assertTrue(
            after[KslConst.LIVE_CTX] <= before[KslConst.LIVE_CTX],
            "ksl.ctx ${before[KslConst.LIVE_CTX]} -> ${after[KslConst.LIVE_CTX]}",
        )
        assertTrue(
            after[KslConst.LIVE_PKEY] <= before[KslConst.LIVE_PKEY],
            "ksl.pkey ${before[KslConst.LIVE_PKEY]} -> ${after[KslConst.LIVE_PKEY]}",
        )
    }

    /**
     * The same with a client CA bundle that rotates as well (TrustConfig.ReloadableCa): four threads build and close sessions
     * of ten mTLS configurations while a fifth alternates 60 identity reloads and 60 bundle reloads. Contexts are keyed by both
     * snapshots, a replaced bundle's context leaves the registry while sessions may still hold it: once everything is closed
     * every context seen is freed and `ksl.ctx` / `ksl.pkey` are back where they were.
     */
    @Test fun sessionsWithIdentityAndClientCaReloadsAtOnce() {
        val before = Ksl.liveObjects()
        val r = TlsIdentity.reloadable(identityA())
        val bundles =
            listOf(
                TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa))),
                TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.otherCa))),
                TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa), Certificate(TestCerts.otherCa))),
            )
        // every reload installs a bundle object of its own, numbered in reload order: a session reads which it got
        val order = Collections.synchronizedMap(IdentityHashMap<TrustConfig.AnchoredCa, Int>())
        val first = TrustConfig.AnchoredCa(bundles[0].roots).also { order[it] = 0 }
        val ca = TrustConfig.reloadable(first)
        val configs =
            List(10) { i ->
                tlsConfig(TlsRole.Server) {
                    alpn = listOf("h3")
                    identity = r
                    clientAuth = if (i % 2 == 0) ClientAuth.Required else ClientAuth.Optional
                    trust = ca
                }
            }
        val seen = Collections.synchronizedSet(Collections.newSetFromMap(IdentityHashMap<KslContext, Boolean>()))
        val failures = Collections.synchronizedList(ArrayList<Throwable>())
        val start = CountDownLatch(1)
        val built =
            java.util.concurrent.atomic
                .AtomicInteger()
        val reloads =
            java.util.concurrent.atomic
                .AtomicInteger()
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60)

        fun running() = System.nanoTime() < deadline && failures.isEmpty()
        val workers =
            List(4) { w ->
                Thread {
                    start.await()
                    val open = ArrayDeque<KslQuicTlsSession>()
                    try {
                        var i = 0
                        while ((i < 400 || reloads.get() < 120) && running()) {
                            val atLeast = order.getValue(ca.current) // the bundle current before the handshake starts
                            val s = KslQuicCrypto.newSession(configs[(w * 7 + i) % configs.size]) as KslQuicTlsSession
                            val got = order.getValue(s.context.trustSnapshot!!)
                            check(got >= atLeast) { "a session built after reload $atLeast got the bundle of reload $got" }
                            seen += s.context
                            built.incrementAndGet()
                            open += s
                            if (open.size > 12) repeat(6) { open.removeFirst().close() }
                            i++
                        }
                    } catch (t: Throwable) {
                        failures += t
                    } finally {
                        open.forEach { it.close() }
                    }
                }
            }
        val reloader =
            Thread {
                start.await()
                try {
                    var done = 0
                    while (done < 120 && running()) {
                        if (built.get() >= (done + 1) * 12) {
                            if (done % 2 == 0) {
                                r.reload(if (done % 4 == 0) identityB() else identityA())
                            } else {
                                val next = TrustConfig.AnchoredCa(bundles[(done / 2 + 1) % bundles.size].roots)
                                order[next] = done / 2 + 1
                                ca.reload(next)
                            }
                            done++
                            reloads.incrementAndGet()
                        } else {
                            Thread.onSpinWait()
                        }
                    }
                } catch (t: Throwable) {
                    failures += t
                }
            }
        (workers + reloader).forEach { it.start() }
        start.countDown()
        (workers + reloader).forEach {
            it.join(maxOf(1L, TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime()) + 5_000))
            assertTrue(!it.isAlive, "a thread did not finish within the 60 s deadline: ${built.get()} sessions, ${reloads.get()} reloads")
        }
        assertEquals(emptyList(), failures.toList(), "no failure while the identity is open")
        assertEquals(120, reloads.get(), "all 120 reloads ran while the workers built sessions")
        assertTrue(seen.map { it.trustSnapshot }.toSet().size > bundles.size, "the bundles of many reloads got contexts")
        // registry retention: with the reloads over, one handshake per configuration under the current bundle leaves the
        // current identity's registry holding contexts of the current bundle only
        configs.forEach { (KslQuicCrypto.newSession(it) as KslQuicTlsSession).also { s -> seen += s.context }.close() }
        val kept = r.current.serverContexts.contextsForTest()
        assertTrue(kept.isNotEmpty())
        assertEquals(emptyList(), kept.filter { it.trustSnapshot !== ca.current }, "no context of a replaced bundle is kept")
        r.close()
        assertEquals(emptyList(), seen.filter { !it.isFreed }, "every context is freed once its sessions and the identity are closed")
        val after = Ksl.liveObjects()
        assertTrue(
            after[KslConst.LIVE_CTX] <= before[KslConst.LIVE_CTX],
            "ksl.ctx ${before[KslConst.LIVE_CTX]} -> ${after[KslConst.LIVE_CTX]}",
        )
        assertTrue(
            after[KslConst.LIVE_PKEY] <= before[KslConst.LIVE_PKEY],
            "ksl.pkey ${before[KslConst.LIVE_PKEY]} -> ${after[KslConst.LIVE_PKEY]}",
        )
    }
}
