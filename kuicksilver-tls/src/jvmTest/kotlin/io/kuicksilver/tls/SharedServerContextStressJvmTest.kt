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
 * so the cache evicts all the time) are built and closed on four threads while a fifth reloads the identity. No handshake
 * may fail while the identity is open, and once everything is closed every context seen is freed and `ksl.ctx` / `ksl.pkey`
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
        val workers =
            List(4) { w ->
                Thread {
                    start.await()
                    val open = ArrayDeque<KslQuicTlsSession>()
                    try {
                        repeat(400) { i ->
                            val s =
                                KslQuicCrypto.newSession(
                                    configs[(w * 7 + i) % configs.size],
                                    earlyData = i % 2 == 0,
                                ) as KslQuicTlsSession
                            seen += s.context
                            open += s
                            if (open.size > 12) repeat(6) { open.removeFirst().close() }
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
                    repeat(60) { i -> r.reload(if (i % 2 == 0) identityB() else identityA()) }
                } catch (t: Throwable) {
                    failures += t
                }
            }
        (workers + reloader).forEach { it.start() }
        start.countDown()
        (workers + reloader).forEach {
            it.join(TimeUnit.SECONDS.toMillis(60))
            assertTrue(!it.isAlive, "a thread did not finish within 60 s")
        }
        assertEquals(emptyList(), failures.toList(), "no failure while the identity is open")
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
}
