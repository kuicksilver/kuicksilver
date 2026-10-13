// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.bench

import io.kuicksilver.quic.Bbr
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.IoPreference
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
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

/**
 * One operation moves one MiB of stream data over real UDP on loopback through the whole runtime (two endpoints, two
 * loops, the Null crypto provider so the transport, not AEAD, is measured): ops/s is MiB/s. [io] picks the socket: the
 * accelerated `ksl_udp` one where it exists (Linux, Android, Apple, Windows) or the portable one (NIO on the JVM, ktor-network on Native).
 * On a host without the accelerated socket the "accelerated" row measures the portable fallback; the numbers are a measurement, not a promise.
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
@OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
public class UdpThroughputBenchmark {
    @Param("accelerated", "portable") public var io: String = "accelerated"

    /** The congestion controller of both ends: the default CUBIC or the experimental BBR. */
    @Param("cubic", "bbr") public var cc: String = "cubic"
    private lateinit var server: QuicEndpoint
    private lateinit var client: QuicEndpoint
    private lateinit var connection: QuicConnection
    private lateinit var stream: QuicStream
    private lateinit var serverStream: QuicStream
    private val chunk = ByteArray(16 * 1024) { (it * 7).toByte() }
    private val readBuffer = ByteArray(64 * 1024)

    @Setup public fun setup(): Unit = runBlocking {
        val prefer = if (io == "accelerated") IoPreference.Accelerated else IoPreference.Portable
        val serverTls = tlsConfig(TlsRole.Server) { alpn = listOf("bench"); identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf()) }
        val clientTls = tlsConfig(TlsRole.Client) { alpn = listOf("bench"); serverName = "server.test"; trust = TrustConfig.Custom { chain, _, _ -> VerifyResult.Accepted(chain) } }
        val quic = quicConfig { if (cc == "bbr") congestionController = { Bbr() } }
        val lo = InetSocketAddress("127.0.0.1", 0)
        server = QuicEndpoint.bind(lo, QuicEndpointConfig.Builder().apply { this.server = QuicServerConfig.Builder(serverTls).apply { this.quic = quic }.build(); crypto = NullCryptoProvider; this.io = { DatagramIo.open(it, prefer) } }.build())
        client = QuicEndpoint.bind(lo, QuicEndpointConfig.Builder().apply { crypto = NullCryptoProvider; this.io = { DatagramIo.open(it, prefer) } }.build())
        val accepted = async { server.accept() }
        connection = client.connect(server.localAddress, QuicClientConfig.Builder(clientTls).apply { this.quic = quic }.build())
        val serverConnection = accepted.await()
        stream = connection.openBidi()
        val opened = async { serverConnection.acceptStream() }
        stream.output.writeFully(chunk, 0, 1); stream.output.flush()
        serverStream = opened.await(); serverStream.input.readAvailable(readBuffer, 0, 1)
    }
    @TearDown public fun tearDown(): Unit = runBlocking { connection.close(0, "done"); client.close(); server.close() }

    @Benchmark public fun transfer(): Long = runBlocking {
        val total = 1L shl 20
        val writer = launch { var sent = 0L; while (sent < total) { stream.output.writeFully(chunk, 0, chunk.size); sent += chunk.size }; stream.output.flush() }
        var received = 0L
        while (received < total) { val n = serverStream.input.readAvailable(readBuffer, 0, readBuffer.size); if (n < 0) break; received += n }
        writer.join(); received
    }
}
