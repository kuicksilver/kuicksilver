// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)

package io.kuicksilver.bench

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyResult
import io.kuicksilver.tls.tlsConfig
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.BenchmarkMode
import kotlinx.benchmark.Mode
import kotlinx.benchmark.Param
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State
import kotlinx.benchmark.TearDown
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.time.TimeSource

/**
 * One server endpoint with [loops] endpoint loops on `127.0.0.1:0` and [CLIENTS] client endpoints (one loop each), all in
 * one process over loopback UDP through the accelerated socket. Where the kernel balances one port over several sockets
 * (Linux, Android: `SO_REUSEPORT`) each server loop has its own socket; elsewhere (Apple, Windows) the loops share one
 * socket and its receiver thread hands each datagram to the loop its connection ID names (docs/guide/quic.md, "Several
 * loops on one port"). The score is ops/s; what one operation is depends on [work]:
 *
 * - `handshake`: [HANDSHAKES] whole connections with ksl crypto (P-256 certificate), [LANES] at a time per client: the
 *   client connects (the handshake completes) and closes. Handshakes per second = ops/s × [HANDSHAKES].
 * - `bulk8`: [CLIENTS] connections, one per client, each moving [BULK_MIB] MiB from the client to the server with ksl
 *   crypto (AES-GCM). MiB/s = ops/s × [CLIENTS] × [BULK_MIB].
 * - `bulk8null`: the same with the Null crypto provider: no AEAD, so the upper bound the receive path leaves.
 *
 * Each trial prints the dispatcher's drops (`EndpointStats.datagramsDispatchDropped`) and, on the JVM in dispatched mode,
 * the share of one core the receiver thread used while the operations ran (on Kotlin/Native: `sample` the process).
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
@OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class) // the Null crypto provider
public class MultiLoopBenchmark {
    /** The server's endpoint loops. */
    @Param("1", "2", "4", "8") public var loops: Int = 1

    /** What one operation is: `handshake`, `bulk8` or `bulk8null` (see the class). */
    @Param("handshake", "bulk8", "bulk8null") public var work: String = "handshake"

    private lateinit var identity: TlsIdentity.InMemory
    private lateinit var server: QuicEndpoint
    private lateinit var clients: List<QuicEndpoint>
    private lateinit var clientConfig: QuicClientConfig
    private lateinit var acceptor: CoroutineScope
    private val connections = ArrayList<QuicConnection>()
    private val streams = ArrayList<Pair<QuicStream, QuicStream>>()
    private val chunk = ByteArray(16 * 1024) { (it * 7).toByte() }
    private var receiverCpu: ReceiverCpu? = null
    private var busyNanos = 0L
    private var receiverNanos = 0L

    @Setup public fun setup(): Unit = runBlocking {
        val nullCrypto = work == "bulk8null"
        identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
        val serverTls = tlsConfig(TlsRole.Server) { alpn = listOf("bench"); this.identity = this@MultiLoopBenchmark.identity }
        val clientTls = tlsConfig(TlsRole.Client) { alpn = listOf("bench"); serverName = "server.test"; trust = TrustConfig.Custom { chain, _, _ -> VerifyResult.Accepted(chain) } }
        clientConfig = QuicClientConfig.Builder(clientTls).build()
        val lo = InetSocketAddress("127.0.0.1", 0)
        server = QuicEndpoint.bind(lo, QuicEndpointConfig.Builder().apply {
            this.server = QuicServerConfig.Builder(serverTls).build()
            this.loops = this@MultiLoopBenchmark.loops
            if (nullCrypto) crypto = NullCryptoProvider
        }.build())
        clients = List(CLIENTS) { QuicEndpoint.bind(lo, QuicEndpointConfig.Builder().apply { if (nullCrypto) crypto = NullCryptoProvider }.build()) }
        acceptor = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        if (work == "handshake") {
            // the server's side of each connection ends on its own (the client closes); taking it keeps the accept queue free
            acceptor.launch { while (true) server.accept() }
            connectAll(1)
        } else {
            for (c in clients) {
                // one at a time, so the server's next accepted connection is this client's
                val accepted = acceptor.async { server.accept() }
                val conn = c.connect(server.localAddress, clientConfig)
                connections += conn
                val peer = accepted.await()
                val s = conn.openBidi()
                s.output.writeFully(chunk, 0, 1); s.output.flush()
                val p = peer.acceptStream()
                p.input.readAvailable(ByteArray(1), 0, 1)
                streams += s to p
            }
        }
        receiverCpu = ReceiverCpu.find()
    }

    @TearDown public fun tearDown(): Unit = runBlocking {
        val share = if (receiverCpu != null && busyNanos > 0) "${(receiverNanos * 1000 / busyNanos) / 10.0} %" else "n/a"
        val st = server.stats
        val lost = connections.sumOf { it.stats.lostPackets }
        println("MultiLoopBenchmark loops=$loops work=$work: datagramsDispatchDropped=${st.datagramsDispatchDropped}, " +
            "receiver thread CPU=$share of the time the operations ran (${ReceiverCpu.note(receiverCpu)}); server datagrams " +
            "received=${st.datagramsReceived} droppedSocket=${st.datagramsDroppedSocket} droppedQueue=${st.datagramsDroppedQueue}" +
            (if (connections.isEmpty()) "" else ", client packets lost=$lost"))
        for (c in connections) c.close(0, "done")
        acceptor.cancel()
        for (c in clients) c.close()
        server.close()
        identity.close()
    }

    @Benchmark public fun run(): Long = runBlocking {
        val start = TimeSource.Monotonic.markNow()
        val cpu0 = receiverCpu?.nanos() ?: 0L
        val done = if (work == "handshake") connectAll(HANDSHAKES / (CLIENTS * LANES)) else bulk()
        receiverNanos += (receiverCpu?.nanos() ?: 0L) - cpu0
        busyNanos += start.elapsedNow().inWholeNanoseconds
        done
    }

    /** [perLane] connections one after another on each of [LANES] lanes per client, all clients at once. */
    private suspend fun connectAll(perLane: Int): Long = coroutineScope {
        clients.flatMap { c ->
            List(LANES) {
                async {
                    repeat(perLane) { c.connect(server.localAddress, clientConfig).close() }
                    perLane.toLong()
                }
            }
        }.awaitAll().sum()
    }

    /** [BULK_MIB] MiB over every connection at once, until the server read it all. */
    private suspend fun bulk(): Long = coroutineScope {
        val total = BULK_MIB.toLong() shl 20
        streams.map { (out, inp) ->
            async {
                val writer = launch { var sent = 0L; while (sent < total) { out.output.writeFully(chunk, 0, chunk.size); sent += chunk.size }; out.output.flush() }
                val buf = ByteArray(64 * 1024)
                var received = 0L
                while (received < total) { val n = inp.input.readAvailable(buf, 0, buf.size); if (n < 0) break; received += n }
                writer.join(); received
            }
        }.awaitAll().sum()
    }

    public companion object {
        /** Client endpoints, each with its own loop and socket. */
        public const val CLIENTS: Int = 8

        /** Connections each client has in flight during `handshake`. */
        public const val LANES: Int = 4

        /** Handshakes per `handshake` operation. */
        public const val HANDSHAKES: Int = 128

        /** MiB per connection per `bulk8` operation. */
        public const val BULK_MIB: Int = 16
    }
}

/** The CPU time of the server's receiver thread (dispatched mode), where the platform tells it from the benchmark's process. */
internal expect class ReceiverCpu {
    /** The thread's CPU time so far, in nanoseconds. */
    fun nanos(): Long

    companion object {
        /** The receiver of the server's in-process dispatch, or null (one loop, kernel mode, or no per-thread view here). */
        fun find(): ReceiverCpu?

        /** Why there is no figure when [cpu] is null; what was measured otherwise. */
        fun note(cpu: ReceiverCpu?): String
    }
}
