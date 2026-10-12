// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.api.ApiPair
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.time.Duration.Companion.seconds

/** [NetworkMigrator.start] and [NetworkMigrator.close] called from several threads at once. */
@OptIn(ExperimentalKuicksilverApi::class)
class NetworkMigratorConcurrencyTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun races(body: suspend (QuicConnection, CoroutineScope, CyclicBarrier, java.util.concurrent.ExecutorService) -> Unit) =
        runBlocking {
            ApiPair.open().use { p ->
                val (c, _) = p.connect()
                val pool = Executors.newFixedThreadPool(2)
                val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
                try {
                    body(c, scope, CyclicBarrier(2), pool)
                } finally {
                    scope.cancel()
                    pool.shutdownNow()
                    c.close()
                }
            }
        }

    private fun migrator(
        c: QuicConnection,
        scope: CoroutineScope,
    ) = NetworkMigrator(c, MutableStateFlow<Int?>(1), { error("never opened") }, scope)

    @Test fun concurrentStartRunsOnce() =
        races { c, scope, barrier, pool ->
            repeat(1000) {
                val m = migrator(c, scope)
                val results =
                    List(2) {
                        pool.submit<Result<Job>> {
                            barrier.await()
                            runCatching { m.start() }
                        }
                    }.map { it.get() }
                assertEquals(1, results.count { it.isSuccess }, "exactly one start() runs")
                assertIs<IllegalStateException>(results.single { it.isFailure }.exceptionOrNull())
                m.close()
                withTimeout(10.seconds) { results.single { it.isSuccess }.getOrThrow().join() }
            }
        }

    @Test fun closeRacingStartNeverLeavesItRunning() =
        races { c, scope, barrier, pool ->
            repeat(1000) {
                val m = migrator(c, scope)
                val started =
                    pool.submit<Job> {
                        barrier.await()
                        m.start()
                    }
                val closed =
                    pool.submit {
                        barrier.await()
                        m.close()
                    }
                closed.get()
                withTimeout(10.seconds) { started.get().join() } // a running migrator would never end
            }
        }
}
