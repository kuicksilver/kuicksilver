// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.soak

import io.ktor.client.HttpClient
import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.ktor.client.KuicksilverClientProbe
import io.kuicksilver.ktor.server.KuicksilverServerProbe
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.quicEndpointConfig
import io.kuicksilver.quic.runtime.QuicResourceProbe
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/** Run parameters; [fromEnvironment] reads the `KSL_SOAK_*` variables the Gradle build forwards from `-Pkuicksilver.soak.*`. */
internal class SoakConfig(
    val duration: Duration,
    val clients: Int = 8,
    /** Iterations per second over all clients (a ceiling: slow iterations make it lower). */
    val rate: Double = 40.0,
    val sampleEvery: Duration = 15.seconds,
    val warmup: Duration = maxOf(2.minutes, duration / 5),
    val reportDir: String? = null,
    val label: String = "soak",
    val seed: Long = 1,
    /** The scenarios of the mix (`-Pkuicksilver.soak.scenarios=…`), each with its usual weight; all by default. */
    val scenarios: Set<Scenario> = Scenario.entries.toSet(),
) {
    companion object {
        fun fromEnvironment(): SoakConfig? {
            val minutes = ProcessResources.env("KSL_SOAK_MINUTES")?.toDoubleOrNull() ?: return null
            val duration = (minutes * 60_000).toLong().milliseconds
            val d = SoakConfig(duration)
            return SoakConfig(
                duration = duration,
                clients = ProcessResources.env("KSL_SOAK_CLIENTS")?.toIntOrNull() ?: d.clients,
                rate = ProcessResources.env("KSL_SOAK_RATE")?.toDoubleOrNull() ?: d.rate,
                sampleEvery =
                    ProcessResources.env("KSL_SOAK_SAMPLE_SECONDS")?.toDoubleOrNull()?.let { (it * 1000).toLong().milliseconds }
                        ?: d.sampleEvery,
                warmup =
                    ProcessResources.env("KSL_SOAK_WARMUP_MINUTES")?.toDoubleOrNull()?.let { (it * 60_000).toLong().milliseconds }
                        ?: d.warmup,
                reportDir = ProcessResources.env("KSL_SOAK_REPORT") ?: ProcessResources.env("KSL_SOAK_DEFAULT_REPORT"),
                label = ProcessResources.env("KSL_SOAK_LABEL") ?: d.label,
                scenarios = Scenario.fromEnvironment(),
            )
        }
    }
}

/**
 * One sample: seconds since the start of the load, and every metric. Stored as a row of longs over a key table shared with
 * the previous sample (the keys rarely change), so a long run's own series do not show up in the heap it measures.
 */
internal class Sample private constructor(
    val t: Double,
    /** The metrics of this sample, in sampling order: the previous sample's list while the metrics do not change. */
    val metrics: List<String>,
    private val row: LongArray,
) {
    /** The value of `metrics[index]`. */
    fun valueAt(index: Int): Long = row[index]

    companion object {
        private var lastKeys: List<String> = emptyList()

        operator fun invoke(
            t: Double,
            values: Map<String, Long>,
        ): Sample {
            var keys = lastKeys
            if (keys.size != values.size || values.keys.withIndex().any { (i, k) -> keys[i] != k }) {
                keys = values.keys.toList()
                lastKeys = keys
            }
            return Sample(t, keys, LongArray(keys.size) { values.getValue(keys[it]) })
        }
    }
}

/** Per-scenario counts: iterations, outcomes by tag, unexpected failures by message. */
internal class ScenarioStats {
    var iterations = 0L
    val outcomes = LinkedHashMap<String, Long>()
    val failures = LinkedHashMap<String, Long>()
    var failed = 0L
}

/**
 * The soak: servers up, an idle baseline, N client coroutines running the weighted [Scenario] mix for the configured time
 * while a sampler records every resource, then a quiet period in which countable resources must return to the baseline.
 * The verdict ([SoakResult.passed]) needs every sampled series flat after warm-up ([Flatness]), every countable resource
 * back at its baseline, and unexpected failures below 0.5% of iterations.
 */
@OptIn(ExperimentalAtomicApi::class)
internal class Soak(
    private val config: SoakConfig,
) {
    private val clock = TimeSource.Monotonic

    suspend fun run(): SoakResult {
        KslLoader.ensureLoaded()
        QuicResourceProbe.enabled = true
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val (http, httpPort) = HttpServer.start()
        val raw = RawServer.start(scope)
        val refuser = RawServer.start(scope, acceptQueue = 2, acceptEvery = 500.milliseconds)
        val sampler = Sampler(http.engine, scope)
        settle()
        val baseline = sampler.sample()
        val local = InetSocketAddress("127.0.0.1", 0)
        val quic = QuicEndpoint.bind(local, quicEndpointConfig { })
        val zeroRtt = QuicEndpoint.bind(local, quicEndpointConfig { })
        val h1 = soakHttpClient(Http3DiscoveryMode.H1Only)
        val h3 = soakHttpClient(Http3DiscoveryMode.H3Only)
        sampler.clients = listOf(h1, h3)
        val work = Workload(httpPort, raw, refuser, quic, zeroRtt, h1, h3)
        val stats = Scenario.entries.associateWith { ScenarioStats() }
        val iterations = AtomicLong(0)
        val start = clock.markNow()
        val samples = ArrayList<Sample>()
        val workers =
            List(config.clients) { w ->
                scope.launch {
                    val r = Random(config.seed * 1_000 + w)
                    val pace = (config.clients / config.rate * 1000).toLong().milliseconds
                    while (isActive && start.elapsedNow() < config.duration) {
                        val began = clock.markNow()
                        val s = Scenario.pick(r, config.scenarios)
                        val outcome =
                            try {
                                withTimeout(ITERATION_TIMEOUT) { work.run(s, r) }
                            } catch (e: Throwable) {
                                if (e.isCancellation() && !isActive) throw e
                                e
                            }
                        iterations.incrementAndFetch()
                        if (outcome is Throwable) {
                            println("[soak ${config.label}] t=${start.elapsedNow().inWholeSeconds}s worker $w $s failed: $outcome")
                        }
                        record(stats.getValue(s), outcome)
                        val left = pace - began.elapsedNow()
                        if (left > Duration.ZERO) delay(left) else yield()
                    }
                }
            }
        val samplerJob =
            scope.launch {
                while (isActive) {
                    val t = start.elapsedNow().inWholeMilliseconds / 1000.0
                    val values = sampler.sample() + ("soak.iterations" to iterations.load())
                    samples += Sample(t, values) // only this coroutine writes; read after it joined
                    progress(t, values)
                    delay(config.sampleEvery)
                }
            }
        workers.forEach { it.join() }
        samplerJob.cancelAndJoin()
        val loadSamples = samples.toList()
        // quiet period: the shared clients go, then every countable resource must come back to the idle baseline
        h1.close()
        h3.close()
        quic.closeAndJoin()
        zeroRtt.closeAndJoin()
        sampler.clients = emptyList()
        val quietStart = clock.markNow()
        var end = sampler.sample()
        while (quietStart.elapsedNow() < QUIET_LIMIT && returned(baseline, end).any { !it.ok }) {
            delay(2.seconds)
            end = sampler.sample()
        }
        val quietTook = quietStart.elapsedNow()
        refuser.close()
        raw.close()
        http.stopSuspend(1000, 5000)
        scope.coroutineContext[Job]?.cancelAndJoin()
        QuicResourceProbe.enabled = false
        return SoakResult(config, baseline, loadSamples, end, returned(baseline, end), quietTook, stats)
    }

    /**
     * Leak attribution: each scenario alone, [iterations] times in a row, then a wait until no connection is left; the
     * change of every countable resource is that scenario's. Run it when the soak reports a leak (`-Pkuicksilver.soak.attribute=N`,
     * `-Pkuicksilver.soak.scenarios=QuicMigration,KtorH3` for some scenarios only).
     */
    suspend fun attribute(
        iterations: Int,
        only: Set<Scenario> = Scenario.entries.toSet(),
    ): Map<Scenario, Map<String, Long>> {
        KslLoader.ensureLoaded()
        QuicResourceProbe.enabled = true
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val (http, httpPort) = HttpServer.start()
        val raw = RawServer.start(scope)
        val refuser = RawServer.start(scope, acceptQueue = 2, acceptEvery = 500.milliseconds)
        val sampler = Sampler(http.engine, scope)
        val local = InetSocketAddress("127.0.0.1", 0)
        val quic = QuicEndpoint.bind(local, quicEndpointConfig { })
        val zeroRtt = QuicEndpoint.bind(local, quicEndpointConfig { })
        val h1 = soakHttpClient(Http3DiscoveryMode.H1Only)
        val h3 = soakHttpClient(Http3DiscoveryMode.H3Only)
        val work = Workload(httpPort, raw, refuser, quic, zeroRtt, h1, h3)
        val r = Random(config.seed)
        val out = LinkedHashMap<Scenario, Map<String, Long>>()

        suspend fun quiet(): Map<String, Long> {
            var m = sampler.sample()
            val t0 = clock.markNow()
            while ((m["quic.connections"] ?: 0) > 0 && t0.elapsedNow() < 30.seconds) {
                delay(500.milliseconds)
                m = sampler.sample()
            }
            return m
        }
        for (s in Scenario.entries.filter { it in only }) {
            repeat(2) { runCatching { withTimeout(ITERATION_TIMEOUT) { work.run(s, r) } } } // first-use allocations (tickets, pools)
            val before = quiet()
            var failed = 0
            repeat(iterations) { if (runCatching { withTimeout(ITERATION_TIMEOUT) { work.run(s, r) } }.isFailure) failed++ }
            val after = quiet()
            out[s] =
                (COUNTABLE.keys + MEMORY).filter { it in before && it in after }.associateWith {
                    after.getValue(
                        it,
                    ) - before.getValue(it)
                } +
                ("failed" to failed.toLong())
            println("[soak attribute] $s: " + out.getValue(s).filterValues { it != 0L })
        }
        h1.close()
        h3.close()
        quic.closeAndJoin()
        zeroRtt.closeAndJoin()
        refuser.close()
        raw.close()
        http.stopSuspend(1000, 5000)
        scope.coroutineContext[Job]?.cancelAndJoin()
        return out
    }

    private suspend fun settle() {
        delay(2.seconds) // the servers' first allocations (selectors, buffers) land before the baseline
    }

    private val statsLock = Mutex()

    private suspend fun record(
        s: ScenarioStats,
        outcome: Any,
    ) = statsLock.withLock {
        s.iterations++
        when (outcome) {
            is Outcome -> {
                s.outcomes[outcome.tag] = (s.outcomes[outcome.tag] ?: 0) + 1
            }

            is Throwable -> {
                s.failed++
                val key = (outcome::class.simpleName ?: "Throwable") + ": " + (outcome.message ?: "").take(120)
                s.failures[key] = (s.failures[key] ?: 0) + 1
            }
        }
    }

    private fun progress(
        t: Double,
        v: Map<String, Long>,
    ) {
        val keys =
            listOf("soak.iterations", "proc.rssKiB", "jvm.heapAfterGcKiB", "kn.heapAfterGcKiB", "proc.fds", "quic.connections", "ksl.ssl")
        println("[soak ${config.label}] t=${t.toInt()}s " + keys.filter { it in v }.joinToString(" ") { "$it=${v[it]}" })
    }

    companion object {
        val ITERATION_TIMEOUT: Duration = 60.seconds
        val QUIET_LIMIT: Duration = 90.seconds

        /** Memory series the attribution reports per scenario (informational: allocators and collectors keep some). */
        val MEMORY: List<String> = listOf("proc.rssKiB", "jvm.heapAfterGcKiB", "kn.heapAfterGcKiB", "jvm.directKiB")

        /** Countable resources must be back at their idle level after the load; `tolerance` absorbs what the platform keeps by itself. */
        val COUNTABLE: Map<String, Long> =
            linkedMapOf(
                "ksl.ctx" to 0,
                "ksl.ssl" to 0,
                "ksl.key" to 0,
                "ksl.pkey" to 0,
                "ksl.session" to 0,
                "ksl.udp" to 0,
                "ksl.wake" to 0,
                "quic.loops" to 0,
                "quic.connections" to 0,
                "quic.runtimes" to 0,
                "quic.streams" to 0,
                "quic.cids" to 0,
                "quic.perIp" to 0,
                "quic.byRemote" to 0,
                "quic.timerHeap" to 0,
                "quic.acceptedQueue" to 0,
                "quic.pendingAccept" to 0,
                "quic.handshaking" to 0,
                "quic.sessionCache" to 0,
                "quic.loopJobs" to 0,
                "server.h3Connections" to 0,
                "server.h3Jobs" to 0,
                "server.tcpJobs" to 0,
                "soak.serverJobs" to 0,
                "proc.fds" to 4,
                "jvm.threads" to 16,
            )

        fun returned(
            baseline: Map<String, Long>,
            end: Map<String, Long>,
        ): List<Returned> =
            COUNTABLE.mapNotNull { (k, tol) ->
                val b = baseline[k] ?: return@mapNotNull null
                val e = end[k] ?: return@mapNotNull null
                Returned(k, b, e, tol)
            }
    }
}

/** A countable resource after the quiet period against its idle baseline. */
internal class Returned(
    val metric: String,
    val baseline: Long,
    val end: Long,
    val tolerance: Long,
) {
    val ok: Boolean get() = end <= baseline + tolerance
}

/** Everything a sample reads: the process, the native live objects and the library's own tables. */
internal class Sampler(
    private val server: io.kuicksilver.ktor.server.KuicksilverApplicationEngine,
    private val harness: CoroutineScope,
) {
    @kotlin.concurrent.Volatile var clients: List<HttpClient> = emptyList()

    suspend fun sample(): Map<String, Long> {
        val m = LinkedHashMap<String, Long>()
        m += ProcessResources.sample()
        val live = Ksl.liveObjects()
        for ((i, name) in LIVE_NAMES.withIndex()) if (i < live.size) m["ksl.$name"] = live[i]
        m += QuicResourceProbe.snapshot()
        val sums = LinkedHashMap<String, Long>()
        for (c in clients) for ((k, v) in KuicksilverClientProbe.snapshot(c.engine)) sums[k] = (sums[k] ?: 0) + v
        m += sums
        m += KuicksilverServerProbe.snapshot(server)
        // the raw servers' accept loops and connection handlers (two accept loops when idle)
        m["soak.serverJobs"] = activeJobs(harness.coroutineContext[Job]!!)
        return m
    }

    private fun activeJobs(root: Job): Long = root.children.sumOf { (if (it.isActive) 1L else 0L) + activeJobs(it) }

    companion object {
        val LIVE_NAMES: List<String> =
            listOf("ctx", "ssl", "key", "pkey", "session", "udp", "wake").also { check(it.size == KslConst.LIVE_COUNT) }
    }
}
