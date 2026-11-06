// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.http3Request
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.testing.MemoryNetwork
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyResult
import io.kuicksilver.tls.tlsConfig
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.discard
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeout
import kotlin.math.roundToLong
import kotlin.time.Duration.Companion.minutes

/**
 * The memory benchmark (P.5): idle footprint of the process, what an idle QUIC connection holds (core alone and through the
 * endpoints' runtimes, both sides and the server's side alone), and what moving data allocates per GB. Everything runs in
 * this process without sockets (virtual time for the cores, a `MemoryNetwork` for the endpoints), so it runs on a busy
 * host; the RSS figures are the noisiest (the JVM's heap grows and does not give memory back). Run it with
 * `bash tools/bench/memory.sh` (docs/benchmarks.md, "Memory").
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
public object MemoryBench {
    /** The parts [run] can be limited to; each one in its own process keeps one part's heap growth out of the next one's RSS. */
    public val sections: List<String> = listOf("core", "endpoint", "http3", "transfer")

    /**
     * Runs [only] the named [sections] (all by default), printing a line per figure to [out]: [connections] idle connections
     * each, [transferMiB] MiB per transfer.
     */
    public suspend fun run(connections: Int = 1000, transferMiB: Int = 256, only: Set<String> = sections.toSet(), out: (String) -> Unit = ::println) {
        val p = MemoryProbe
        out("memory benchmark (${p.runtime}): $connections idle connections, $transferMiB MiB per transfer, ${only.joinToString(" ")}")
        val start = snapshot()
        out("idle process (nothing loaded yet): rss ${mib(start.rss)}, live heap ${mib(start.heap)}, malloc ${mib(start.malloc)}")
        // one connection end to end first, so the crypto library, the classes and the runtime's pools are loaded
        CoreHandshakes().use { it.connection() }
        EndpointHandshakes.open().use { it.connection() }
        val warm = snapshot()
        out("idle process (after one connection, nothing open): rss ${mib(warm.rss)}, live heap ${mib(warm.heap)}, malloc ${mib(warm.malloc)}")

        if ("core" in only) coreIdle(connections, out)
        if ("endpoint" in only) endpointIdle(connections, h3 = false, out)
        if ("http3" in only) endpointIdle(connections, h3 = true, out)
        if ("transfer" in only) { coreTransfer(transferMiB, out); endpointTransfer(transferMiB, out) }
    }

    private class Snapshot(val rss: Long, val heap: Long, val malloc: Long, val classes: Map<String, LongArray>?)

    private fun snapshot(classes: Boolean = false): Snapshot {
        val heap = MemoryProbe.liveHeapBytes()
        return Snapshot(MemoryProbe.rssBytes(), heap, MemoryProbe.mallocInUseBytes(), if (classes) MemoryProbe.classHistogram() else null)
    }

    private fun perConnection(label: String, before: Snapshot, after: Snapshot, n: Int, out: (String) -> Unit) {
        fun per(a: Long, b: Long) = if (a < 0 || b < 0) "n/a" else "${((b - a).toDouble() / n).roundToLong()} B"
        out("$label: heap ${per(before.heap, after.heap)}, malloc ${per(before.malloc, after.malloc)}, rss ${per(before.rss, after.rss)} per connection" +
            " (rss ${mib(after.rss - before.rss)} per $n)")
    }

    private fun coreIdle(n: Int, out: (String) -> Unit) {
        IdleCores().use { cores ->
            val before = snapshot(classes = true)
            val pairs = MutableList<IdleCores.Pair?>(n) { checkNotNull(cores.open()) { "handshake $it did not finish" } }
            val both = snapshot()
            perConnection("core, idle, client and server", before, both, n, out)
            // the client cores close and are let go of; the server cores stay
            val servers = pairs.map { cores.closeClient(it!!); it.server }
            pairs.clear()
            val serverOnly = snapshot()
            perConnection("core, idle, server side", before, serverOnly, n, out)
            perConnection("core, idle, client side", serverOnly, both, n, out)
            histogramDiff("core, idle, server side", before, n, out)
            check(servers.size == n)
            // the inventory: two fresh idle connections, each walked with the other one's objects counted as shared
            val a = checkNotNull(cores.open()); val b = checkNotNull(cores.open())
            footprint(a, b, out)
        }
    }

    /**
     * [n] idle connections through two endpoints over a `MemoryNetwork`. With [h3], each is an HTTP/3 connection (control and
     * QPACK streams, SETTINGS both ways) that has carried one GET answered with 204, and the server side keeps an
     * `acceptRequest` loop per connection, as a server does.
     */
    private suspend fun endpointIdle(n: Int, h3: Boolean, out: (String) -> Unit) {
        val label = if (h3) "http3" else "endpoint"
        val alpn = if (h3) "h3" else "bench"
        val net = MemoryNetwork(receiveBuffer = 4096)
        val identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
        val quic = quicConfig { maxIdleTimeout = 10.minutes }
        val serverIo = net.open(InetSocketAddress("10.0.0.2", 443))
        val clientIo = net.open(InetSocketAddress("10.0.0.1", 40000))
        val serverTls = tlsConfig(TlsRole.Server) { this.alpn = listOf(alpn); this.identity = identity }
        val server = QuicEndpoint.bind(serverIo.localAddress, QuicEndpointConfig.Builder().apply {
            this.server = QuicServerConfig.Builder(serverTls).apply { this.quic = quic }.build(); io = { serverIo }; maxConnectionsPerIp = null; maxConnections = n + 10
        }.build())
        var client: QuicEndpoint? = QuicEndpoint.bind(clientIo.localAddress, QuicEndpointConfig.Builder().apply { io = { clientIo }; maxConnections = n + 10 }.build())
        val clientConfig = QuicClientConfig.Builder(tlsConfig(TlsRole.Client) { this.alpn = listOf(alpn); serverName = "server.test"; trust = TrustConfig.Custom { chain, _, _ -> VerifyResult.Accepted(chain) } })
            .apply { this.quic = quic }.build()
        val serving = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        try {
            val before = snapshot(classes = true)
            val held = ArrayList<QuicConnection?>(2 * n)
            val h3s = ArrayList<Http3Connection?>(2 * n)
            withTimeout(5.minutes) {
                repeat(n) {
                    coroutineScope {
                        val accepted = async { server.accept() }
                        val c = client!!.connect(server.localAddress, clientConfig)
                        val sc = accepted.await()
                        held += c
                        held += sc
                        if (h3) {
                            val sh = Http3Connection.server(sc)
                            serving.launch { while (true) sh.acceptRequest().respond(204).finish() }
                            val ch = Http3Connection.client(c)
                            ch.request(http3Request("GET", "server.test", "/")).body.discard()
                            h3s += ch
                            h3s += sh
                        }
                    }
                }
            }
            val both = snapshot()
            perConnection("$label, idle, client and server", before, both, n, out)
            // the client's side goes without a word to the server: its datagrams are cut, its endpoint closes its connections
            net.cut(clientIo.localAddress)
            withTimeout(1.minutes) { client!!.closeAndJoin() }
            client = null
            for (i in held.indices step 2) held[i] = null
            for (i in h3s.indices step 2) h3s[i] = null
            val serverOnly = snapshot()
            perConnection("$label, idle, server side", before, serverOnly, n, out)
            perConnection("$label, idle, client side", serverOnly, both, n, out)
            histogramDiff("$label, idle, server side", before, n, out)
            // the inventory: the last two server connections, each walked with the other one's objects counted as shared
            val last = if (h3) h3s[h3s.size - 1]!! else held[held.size - 1]!!
            val prev = if (h3) h3s[h3s.size - 3]!! else held[held.size - 3]!!
            inventory("$label server connection", last, prev, out)
            held.clear(); h3s.clear()
        } finally {
            serving.cancel(); client?.close(); server.close(); identity.close()
        }
    }

    private fun coreTransfer(mib: Int, out: (String) -> Unit) {
        CoreLoopback(streams = 1, payload = 1200, crypto = io.kuicksilver.tls.KslQuicCrypto).use { loop ->
            check(loop.handshake()) { "handshake" }
            while (loop.bytesReceived < minOf(WARMUP, mib.toLong() shl 20)) loop.step()
            val counter = MemoryProbe.allocationCounter()
            val start = loop.bytesReceived
            var nextTick = start + TICK
            while (loop.bytesReceived - start < mib.toLong() shl 20) { loop.step(); if (loop.bytesReceived >= nextTick) { counter.tick(); nextTick += TICK } }
            counter.tick()
            report("core, transfer (ksl crypto, one stream)", counter, loop.bytesReceived - start, out)
        }
    }

    private suspend fun endpointTransfer(mib: Int, out: (String) -> Unit) {
        EndpointHandshakes.open().use { pair ->
            val total = mib.toLong() shl 20
            pair.transfer(minOf(WARMUP, total)) {}
            val counter = MemoryProbe.allocationCounter()
            pair.transfer(total) { counter.tick() }
            counter.tick()
            report("endpoint, transfer (ksl crypto, one stream, MemoryNetwork)", counter, total, out)
        }
    }

    /** One stream from the client to the server carrying [bytes]; [tick] runs on the reading side after every [TICK] bytes. */
    private suspend fun EndpointHandshakes.transfer(bytes: Long, tick: () -> Unit) {
        coroutineScope {
            val reader = async {
                val c = server.accept()
                val s = c.acceptStream()
                val buf = ByteArray(64 * 1024)
                var got = 0L
                var nextTick = TICK
                while (true) {
                    val n = s.input.readAvailable(buf, 0, buf.size)
                    if (n < 0) break
                    got += n
                    if (got >= nextTick) { tick(); nextTick += TICK }
                }
                c.close()
                got
            }
            val c = client.connect(server.localAddress, clientConfig)
            val s = c.openBidi()
            val chunk = ByteArray(16 * 1024) { it.toByte() }
            var sent = 0L
            while (sent < bytes) { val n = minOf(chunk.size.toLong(), bytes - sent).toInt(); s.output.writeFully(chunk, 0, n); sent += n }
            s.output.flushAndClose()
            check(reader.await() == bytes) { "short transfer" }
            c.close()
        }
    }

    private fun report(label: String, counter: AllocationCounter, bytes: Long, out: (String) -> Unit) {
        val perGb = counter.allocated().toDouble() * (1L shl 30) / bytes
        out("$label: ${mib(counter.allocated())} allocated over ${mib(bytes)}, ${(perGb / (1 shl 20)).roundToLong()} MiB per GiB" +
            (counter.caveat()?.let { " ($it)" } ?: ""))
    }

    /** What the live classes grew by between [before] and now, per connection: the largest [HISTOGRAM_ROWS] by bytes (JVM only). */
    private fun histogramDiff(label: String, before: Snapshot, n: Int, out: (String) -> Unit) {
        val base = before.classes ?: return
        val after = MemoryProbe.classHistogram() ?: return
        val rows = after.mapNotNull { (k, v) ->
            val b = base[k]
            val bytes = v[1] - (b?.get(1) ?: 0)
            if (bytes <= 0) null else Triple(k, (v[0] - (b?.get(0) ?: 0)).toDouble() / n, bytes.toDouble() / n)
        }.sortedByDescending { it.third }.take(HISTOGRAM_ROWS)
        out("$label, classes per connection (bytes, instances, class):")
        for ((k, i, b) in rows) out("  ${b.roundToLong()} B  ${(i * 10).roundToLong() / 10.0}  $k")
    }

    private fun mib(b: Long): String = if (b < 0) "n/a" else "${(b * 10 / (1 shl 20)) / 10.0} MiB"

    private const val WARMUP = 64L shl 20
    private const val TICK = 256L shl 10 // Kotlin/Native: a forced collection this often leaves the collector little room for its own
    private const val HISTOGRAM_ROWS = 15
}

/** The per-connection inventory of the runtime object [a] (a connection), [b]'s objects counted as shared (JVM only). */
internal expect fun inventory(label: String, a: Any, b: Any, out: (String) -> Unit)

/** The per-connection inventory of [a]'s server and client cores, [b]'s objects counted as shared (JVM: a reflective walk; elsewhere nothing). */
internal expect fun footprint(a: IdleCores.Pair, b: IdleCores.Pair, out: (String) -> Unit)
