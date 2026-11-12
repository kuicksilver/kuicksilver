// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.compose

import io.ktor.client.HttpClient
import io.ktor.client.request.prepareGet
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.ktor.client.KuicksilverEventListener
import io.kuicksilver.ktor.client.kuicksilverDiagnostics
import io.kuicksilver.quic.MigrationEvent
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlin.time.TimeSource

/** Where a lane of the Migration screen is. */
enum class LaneStatus { Idle, Running, Done, Failed }

/** One column of the Migration screen. */
data class LaneState(
    val name: String,
    val note: String,
    val received: Long = 0,
    val total: Long? = null,
    val status: LaneStatus = LaneStatus.Idle,
    /** The protocol (Kuicksilver's diagnostics for its lane), then the outcome. */
    val detail: String = "",
    val resumes: Int = 0,
)

/** The Migration screen. */
data class MigrationState(
    val running: Boolean = false,
    val network: String = "?",
    val lanes: List<LaneState> = emptyList(),
    /** Newest last: network changes, connectionMigrated events, breaks and resumes, each with the time since the start. */
    val events: List<String> = emptyList(),
)

/**
 * The Migration screen's model: parallel downloads of the same body, one per lane from [lanes] (new clients each run,
 * closed at the end). With `resumeTcp` a broken reference lane goes on with Range ([download]); the Kuicksilver lane
 * never does, so what it shows is the connection itself surviving the switch.
 */
class MigrationModel(
    private val scope: CoroutineScope,
    private val lanes: () -> List<Lane>,
) {
    private val mutable = MutableStateFlow(MigrationState())
    val state: StateFlow<MigrationState> = mutable.asStateFlow()
    private var job: Job? = null
    private var mark = TimeSource.Monotonic.markNow()

    fun start(
        path: String,
        resumeTcp: Boolean,
    ) {
        if (job?.isActive == true) return
        val ls = lanes()
        mark = TimeSource.Monotonic.markNow()
        mutable.update { s -> s.copy(running = true, lanes = ls.map { LaneState(it.name, it.note, status = LaneStatus.Running) }, events = emptyList()) }
        event("start: ${ls.size} downloads of $path; network ${mutable.value.network}")
        job =
            scope.launch {
                ls.forEachIndexed { i, lane -> launch { run(i, lane, path, resumeTcp && !lane.isKuicksilver) } }
            }.also { j ->
                j.invokeOnCompletion {
                    ls.forEach { it.close() }
                    mutable.update { s ->
                        s.copy(running = false, lanes = s.lanes.map { if (it.status == LaneStatus.Running) it.copy(status = LaneStatus.Failed, detail = "stopped") else it })
                    }
                }
            }
    }

    fun stop() {
        job?.cancel()
    }

    /** Waits for the current run (tests). */
    suspend fun join() {
        job?.join()
    }

    /** The default network changed to [name]. */
    fun network(name: String) {
        mutable.update { it.copy(network = name) }
        if (mutable.value.running) event("network: $name")
    }

    /** Adds a line to the event log, stamped with the time since the start. */
    fun event(text: String) {
        val ms = mark.elapsedNow().inWholeMilliseconds
        val line = "+${ms / 1000}.${(ms % 1000 / 100)} s  $text"
        mutable.update { it.copy(events = (it.events + line).takeLast(200)) }
    }

    private fun lane(
        i: Int,
        change: (LaneState) -> LaneState,
    ) = mutable.update { s -> s.copy(lanes = s.lanes.mapIndexed { k, l -> if (k == i) change(l) else l }) }

    private suspend fun run(
        i: Int,
        lane: Lane,
        path: String,
        resume: Boolean,
    ) {
        val r =
            download(
                lane.client,
                lane.baseUrl + path,
                resume = resume,
                onHead = { protocol, _ -> lane(i) { it.copy(detail = protocol) } },
                onProgress = { got, total -> lane(i) { it.copy(received = got, total = total) } },
                onEvent = { text -> event("${lane.name}: $text") },
            )
        when (r) {
            is DownloadResult.Completed -> {
                lane(i) {
                    it.copy(
                        status = LaneStatus.Done,
                        resumes = r.resumes,
                        detail = "${r.protocol}; done in ${r.elapsedMs} ms" + resumed(r.resumes, r.restarts),
                    )
                }
                event("${lane.name}: complete, ${r.bytes} bytes in ${r.elapsedMs} ms")
            }

            is DownloadResult.Failed -> {
                lane(i) { it.copy(status = LaneStatus.Failed, resumes = r.resumes, detail = r.error) }
                event("${lane.name}: failed at ${r.bytes} bytes: ${r.error}")
            }
        }
    }

    private fun resumed(
        resumes: Int,
        restarts: Int,
    ): String =
        when {
            resumes == 0 -> ""
            restarts == 0 -> "; resumed $resumes× with Range (a new connection each)"
            else -> "; resumed $resumes×, $restarts from byte 0"
        }
}

/** One row of the Lossy network screen. */
data class LossyRow(
    val name: String,
    val note: String,
    /** Time to the last byte of each download, ms. */
    val download: SeriesStats? = null,
    /** Time to the response head of each download, ms. */
    val ttfb: SeriesStats? = null,
    val failures: Int = 0,
)

/** The Lossy network screen. */
data class LossyState(
    val running: Boolean = false,
    val progress: String = "",
    val rows: List<LossyRow> = emptyList(),
)

/**
 * The Lossy network screen's model: [runs] downloads per lane, the lanes taking turns (the order flips every run, so
 * neither always goes first), over connections opened by one warm-up request per lane that is not counted. It reports
 * the median and p90 of the time to the last byte and to the response head. Nothing here makes the network lossy: the
 * server does (server/netem.sh).
 */
class LossyModel(
    private val scope: CoroutineScope,
    private val lanes: () -> List<Lane>,
) {
    private val mutable = MutableStateFlow(LossyState())
    val state: StateFlow<LossyState> = mutable.asStateFlow()
    private var job: Job? = null

    fun start(
        bytes: Long,
        runs: Int,
    ) {
        if (job?.isActive == true) return
        val ls = lanes()
        mutable.value = LossyState(running = true, progress = "warming up", rows = ls.map { LossyRow(it.name, it.note) })
        job =
            scope.launch {
                val times = List(ls.size) { mutableListOf<Double>() }
                val heads = List(ls.size) { mutableListOf<Double>() }
                val failures = IntArray(ls.size)
                for (lane in ls) {
                    download(lane.client, lane.baseUrl + "/bytes/1", resume = false) // opens the connection; not counted
                }
                for (run in 0 until runs) {
                    val order = if (run % 2 == 0) ls.indices else ls.indices.reversed()
                    for (i in order) {
                        mutable.update { it.copy(progress = "run ${run + 1} of $runs: ${ls[i].name}") }
                        var head = -1.0
                        val r = download(ls[i].client, ls[i].baseUrl + "/bytes/$bytes", resume = false, onHead = { _, ms -> head = ms.toDouble() })
                        if (r is DownloadResult.Completed) {
                            times[i] += r.elapsedMs.toDouble()
                            heads[i] += head
                        } else {
                            failures[i]++
                        }
                        mutable.update { s ->
                            s.copy(rows = s.rows.mapIndexed { k, row -> row.copy(download = seriesStats(times[k]), ttfb = seriesStats(heads[k]), failures = failures[k]) })
                        }
                    }
                }
            }.also { j ->
                j.invokeOnCompletion { e ->
                    ls.forEach { it.close() }
                    mutable.update { it.copy(running = false, progress = if (e == null) "done" else "stopped") }
                }
            }
    }

    fun stop() {
        job?.cancel()
    }

    suspend fun join() {
        job?.join()
    }
}

/** The Diagnostics screen. */
data class DiagnosticsState(
    val running: Boolean = false,
    val http3Allowed: Boolean = true,
    val lines: List<String> = emptyList(),
)

/**
 * The Diagnostics screen's model: a GET of any URL with Kuicksilver in Auto discovery (HTTP/1.1 first, HTTP/3 once the
 * origin announced it with Alt-Svc, as an app would run it), and the kill switch [setHttp3Allowed], which the engine reads
 * on every request. [clientFor] builds the client for a trust and the switch.
 */
class DiagnosticsModel(
    private val scope: CoroutineScope,
    private val clientFor: (trust: TrustConfig, http3Allowed: () -> Boolean) -> HttpClient,
) : AutoCloseable {
    private val mutable = MutableStateFlow(DiagnosticsState())
    val state: StateFlow<DiagnosticsState> = mutable.asStateFlow()
    private val clients = HashMap<Boolean, HttpClient>()

    private fun client(demoCa: Boolean): HttpClient =
        clients.getOrPut(demoCa) { clientFor(if (demoCa) demoTrust() else TrustConfig.Platform) { mutable.value.http3Allowed } }

    fun setHttp3Allowed(allowed: Boolean) {
        mutable.update { it.copy(http3Allowed = allowed) }
    }

    fun run(
        url: String,
        demoCa: Boolean,
    ) {
        if (mutable.value.running) return
        mutable.update { it.copy(running = true, lines = listOf("GET $url ...")) }
        val c = client(demoCa)
        scope.launch {
            val lines =
                try {
                    c.prepareGet(url).execute { r -> listOf("HTTP ${r.status.value}") + renderDiagnostics(r.kuicksilverDiagnostics?.toView()) }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    listOf("Failed: ${describe(e)}", "A failed call has no diagnostics: its exception says what happened")
                }
            mutable.update { it.copy(running = false, lines = lines) }
        }
    }

    override fun close() {
        clients.values.forEach { it.close() }
        clients.clear()
    }
}

/** The whole app: the demo server's address, the three screen models, and the network the system reports. */
class DemoApp(
    val platform: DemoPlatform,
) : AutoCloseable {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val serverState = MutableStateFlow(DemoServer(platform.defaultHost))
    val server: StateFlow<DemoServer> = serverState.asStateFlow()

    private val listener =
        object : KuicksilverEventListener() {
            override fun connectionMigrated(
                origin: String,
                event: MigrationEvent<*>,
            ) = migration.event("connectionMigrated: $event")
        }

    val migration: MigrationModel =
        MigrationModel(scope) {
            listOf(kuicksilverLane(platform, server.value, migrate = true, listener = listener)) + platform.referenceLanes(server.value)
        }

    val lossy: LossyModel =
        LossyModel(scope) { listOf(kuicksilverLane(platform, server.value, migrate = false, listener = null)) + platform.referenceLanes(server.value) }

    val diagnostics: DiagnosticsModel =
        DiagnosticsModel(scope) { trust, allowed ->
            kuicksilverClient(trust, Http3DiscoveryMode.Auto, migration = null, networkId = null, http3Allowed = allowed)
        }

    init {
        scope.launch { platform.networks().collect { migration.network(it) } }
    }

    fun setHost(host: String) {
        serverState.value = DemoServer(host.trim())
    }

    override fun close() {
        diagnostics.close()
        scope.cancel()
    }
}
