// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.soak

import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.prepareGet
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpProtocolVersion
import io.ktor.utils.io.readAvailable
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.ktor.client.closeHttp3Connections
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import okhttp3.ConnectionPool
import okhttp3.Dispatcher
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import java.io.ByteArrayInputStream
import java.lang.management.ManagementFactory
import java.net.Socket
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.time.Duration.Companion.seconds

/** One GET: the body is read to the end and counted in [Progress.bytes]; [onHeaders] runs when the response head arrives. */
internal interface BenchClient : AutoCloseable {
    suspend fun get(
        path: String,
        from: Long = 0,
        progress: Progress = Progress(),
        onHeaders: () -> Unit = {},
    )
}

internal class Progress {
    @Volatile var bytes: Long = 0
}

/** HTTP/1.1 clients open up to this many connections to the server, as browsers do. */
private const val H1_CONNECTIONS = 6

private const val HOST = "server.test"

/**
 * The client side of `tools/bench/why-quic.sh`. Options: `--client kuicksilver|okhttp`, `--protocol h1|h2|h3|h3-0rtt`,
 * `--scenario download|hol|connect|rebind|rebind-baseline`, `--reps`, `--warmup` (unrecorded runs before
 * `--after-warmup`, a shell command that sets up the emulated network), `--rtt` and `--loss` (only written into the
 * rows), `--port`, `--relay-port`, `--control-port`, `--timeout` (seconds per run). Prints one [WHY_QUIC_HEADER] row per
 * measured run on stdout.
 */
internal fun whyQuicClient(args: List<String>) {
    val o = args.chunked(2).associate { (k, v) -> k.removePrefix("--") to v }
    val client = o.getValue("client")
    val protocol = o.getValue("protocol")
    val scenario = o.getValue("scenario")
    val reps = o["reps"]?.toInt() ?: 15
    val warmup = o["warmup"]?.toInt() ?: 2
    val port = o["port"]?.toInt() ?: 4433
    val relayPort = o["relay-port"]?.toInt() ?: 4443
    val controlPort = o["control-port"]?.toInt() ?: 4480
    val timeout = (o["timeout"]?.toInt() ?: 600).seconds
    val factory = ClientFactory(client, protocol)
    val cpu = ManagementFactory.getOperatingSystemMXBean() as com.sun.management.OperatingSystemMXBean

    // one run: (completed, seconds, bytes, requests); the 0-RTT client lives across runs (it keeps the session tickets)
    val resumed: BenchClient? = if (protocol == "h3-0rtt") factory.create() else null

    suspend fun once(): Run =
        when (scenario) {
            "download" -> {
                fresh(factory) { c -> timed { c.get("/bytes/${10L shl 20}", progress = it) } }
            }

            "hol" -> {
                fresh(factory) { c ->
                    c.get("/bytes/1")
                    val total = Progress()
                    timed {
                        coroutineScope {
                            (1..20)
                                .map {
                                    async {
                                        val p = Progress()
                                        c.get("/bytes/${50L shl 10}", progress = p)
                                        synchronized(total) { total.bytes += p.bytes }
                                    }
                                }.awaitAll()
                        }
                        it.bytes = total.bytes
                    }
                }
            }

            "connect" -> {
                if (resumed != null) {
                    resumed.get("/bytes/1") // a session ticket, then each run a new connection that resumes with 0-RTT
                    (resumed as KuicksilverClient).http.closeHttp3Connections()
                    firstByte(resumed)
                } else {
                    fresh(factory) { c -> firstByte(c) }
                }
            }

            "rebind", "rebind-baseline" -> {
                fresh(factory) { c ->
                    if (scenario == "rebind") arm(controlPort)
                    resumable(c, "https://$HOST:$relayPort/bytes/${50L shl 20}", 50L shl 20)
                }
            }

            else -> {
                error("unknown scenario $scenario")
            }
        }

    runBlocking {
        factory.relayPort = relayPort
        factory.port = port
        repeat(warmup) { runCatching { withTimeout(timeout) { once() } } }
        o["after-warmup"]?.let { cmd ->
            val p =
                ProcessBuilder(
                    "sh",
                    "-c",
                    cmd,
                ).inheritIO().redirectOutput(ProcessBuilder.Redirect.to(java.io.File("/dev/stderr"))).start()
            check(p.waitFor() == 0) { "after-warmup command failed: $cmd" }
        }
        for (rep in 1..reps) {
            val c0 = cpu.processCpuTime
            val t0 = System.nanoTime()
            val run =
                try {
                    withTimeout(timeout) { once() }
                } catch (e: Exception) {
                    // a failed run: how long it took to fail, no bytes
                    System.err.println("why-quic: $client $protocol $scenario run $rep failed: $e")
                    Run(false, (System.nanoTime() - t0) / 1e9, 0, 1)
                }
            val c1 = cpu.processCpuTime
            println(
                listOf(
                    scenario,
                    client,
                    protocol,
                    o["rtt"] ?: "",
                    o["loss"] ?: "",
                    rep,
                    if (run.ok) 1 else 0,
                    "%.4f".format(run.seconds),
                    run.bytes,
                    run.requests,
                    "%.3f".format((c1 - c0) / 1e9),
                ).joinToString(","),
            )
            System.out.flush()
        }
        resumed?.close()
    }
}

internal class Run(
    val ok: Boolean,
    val seconds: Double,
    val bytes: Long,
    val requests: Int,
)

private suspend fun <T> fresh(
    factory: ClientFactory,
    block: suspend (BenchClient) -> T,
): T = factory.create().use { block(it) }

private suspend fun timed(block: suspend (Progress) -> Unit): Run {
    val p = Progress()
    val t0 = System.nanoTime()
    block(p)
    return Run(true, (System.nanoTime() - t0) / 1e9, p.bytes, 1)
}

/** Time to the response head of `GET /bytes/1` on a new connection. */
private suspend fun firstByte(c: BenchClient): Run {
    var head = 0L
    val t0 = System.nanoTime()
    val p = Progress()
    c.get("/bytes/1", progress = p) { head = System.nanoTime() }
    return Run(true, (head - t0) / 1e9, p.bytes, 1)
}

/**
 * The 50 MiB download through the relay. A transfer that fails is resumed with `Range` on a new connection (at most 3
 * times), as a download manager would: `ok` = finished in one request, `requests` = how many it took.
 */
private suspend fun resumable(
    c: BenchClient,
    url: String,
    size: Long,
): Run {
    val p = Progress()
    var requests = 0
    val t0 = System.nanoTime()
    while (p.bytes < size && requests < 4) {
        requests++
        val before = p.bytes
        val part = Progress()
        try {
            c.get(url, from = before, progress = part)
        } catch (e: Exception) {
            System.err.println("why-quic: request $requests ended after ${before + part.bytes} bytes: $e")
        }
        p.bytes = before + part.bytes
    }
    return Run(requests == 1 && p.bytes == size, (System.nanoTime() - t0) / 1e9, p.bytes, requests)
}

private fun arm(controlPort: Int) {
    Socket("127.0.0.1", controlPort).use { s ->
        s.getOutputStream().write("arm\n".toByteArray())
        check(s.getInputStream().bufferedReader().readLine() == "ok")
    }
}

private class ClientFactory(
    val client: String,
    val protocol: String,
) {
    var port = 4433
    var relayPort = 4443

    fun create(): BenchClient =
        when (client) {
            "kuicksilver" -> KuicksilverClient(protocol, port)
            "okhttp" -> OkHttpBench(protocol, port)
            else -> error("unknown client $client")
        }
}

private fun url(
    path: String,
    port: Int,
): String = if (path.startsWith("https://")) path else "https://$HOST:$port$path"

private class KuicksilverClient(
    protocol: String,
    private val port: Int,
) : BenchClient {
    private val expected =
        when (protocol) {
            "h1" -> HttpProtocolVersion.HTTP_1_1
            "h2" -> HttpProtocolVersion.HTTP_2_0
            else -> HttpProtocolVersion.HTTP_3_0
        }
    val http =
        HttpClient(Kuicksilver) {
            expectSuccess = false
            engine {
                trust = SoakPki.trust
                maxConnectionsPerRoute = H1_CONNECTIONS
                http2 { enabled = protocol == "h2" }
                http3 {
                    discovery = if (expected == HttpProtocolVersion.HTTP_3_0) Http3DiscoveryMode.H3Only else Http3DiscoveryMode.H1Only
                    earlyData = protocol == "h3-0rtt"
                    diagnosticsLogLevel = null
                }
            }
        }

    override suspend fun get(
        path: String,
        from: Long,
        progress: Progress,
        onHeaders: () -> Unit,
    ) {
        http.prepareGet(url(path, port)) { if (from > 0) header(HttpHeaders.Range, "bytes=$from-") }.execute { r ->
            onHeaders()
            check(r.status.value == 200 || r.status.value == 206) { "status ${r.status}" }
            check(r.version == expected) { "protocol ${r.version}, expected $expected" }
            val ch = r.bodyAsChannel()
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = ch.readAvailable(buf, 0, buf.size)
                if (n < 0) break
                progress.bytes += n
            }
        }
    }

    override fun close() = http.close()
}

private class OkHttpBench(
    protocol: String,
    private val port: Int,
) : BenchClient {
    private val expected = if (protocol == "h2") Protocol.HTTP_2 else Protocol.HTTP_1_1
    private val pool = ConnectionPool()
    private val http =
        newBuilder()
            .connectionPool(pool)
            .dispatcher(
                Dispatcher().apply {
                    maxRequests = 64
                    maxRequestsPerHost = if (expected == Protocol.HTTP_2) 64 else H1_CONNECTIONS
                },
            ).protocols(if (expected == Protocol.HTTP_2) listOf(Protocol.HTTP_2, Protocol.HTTP_1_1) else listOf(Protocol.HTTP_1_1))
            .build()

    override suspend fun get(
        path: String,
        from: Long,
        progress: Progress,
        onHeaders: () -> Unit,
    ) = withContext(Dispatchers.IO) {
        val req =
            Request
                .Builder()
                .url(url(path, port))
                .apply { if (from > 0) header("Range", "bytes=$from-") }
                .build()
        http.newCall(req).execute().use { r ->
            onHeaders()
            check(r.code == 200 || r.code == 206) { "status ${r.code}" }
            check(r.protocol == expected) { "protocol ${r.protocol}, expected $expected" }
            val src = r.body.byteStream()
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = src.read(buf)
                if (n < 0) break
                progress.bytes += n
            }
        }
    }

    override fun close() {
        pool.evictAll()
        http.dispatcher.executorService.shutdown()
    }

    private companion object {
        /**
         * Trusts the test CA only; TLS 1.3 (the JDK's default first choice); generous timeouts for the lossy runs. A new
         * SSLContext per client, so each client's first connection is a full handshake (the JDK caches sessions per context).
         */
        fun newBuilder(): OkHttpClient.Builder {
            val ca = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(TestCerts.testCa))
            val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
            ks.setCertificateEntry("ca", ca)
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
            val tm = tmf.trustManagers.single() as X509TrustManager
            val ctx = SSLContext.getInstance("TLSv1.3").apply { init(null, arrayOf(tm), null) }
            return OkHttpClient
                .Builder()
                .sslSocketFactory(ctx.socketFactory, tm)
                .connectTimeout(60, TimeUnit.SECONDS)
                .readTimeout(120, TimeUnit.SECONDS)
                .retryOnConnectionFailure(false)
        }
    }
}
