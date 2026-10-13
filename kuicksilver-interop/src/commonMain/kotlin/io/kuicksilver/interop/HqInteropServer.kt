// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalAtomicApi::class, io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.interop

import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.CongestionController
import io.kuicksilver.quic.Cubic
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.tls.CipherSuites
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * HTTP/0.9 over QUIC (`hq-interop`): `GET /path\r\n` on a bidirectional stream, the file, FIN. Listens on IPv4 and, when
 * the host has it, on IPv6 as a second endpoint on the same port (the runner's `ipv6` case talks to `server6`).
 */
internal class HqInteropServer private constructor(private val endpoints: List<QuicEndpoint>, private val www: String) : AutoCloseable {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val accepted = AtomicInt(0)
    val port: Int get() = endpoints[0].localAddress.port
    /** The IPv6 endpoint's port, null when IPv6 could not be bound. */
    val port6: Int? get() = endpoints.getOrNull(1)?.localAddress?.port
    val connectionsAccepted: Int get() = accepted.load()
    private val connections = AtomicReference<List<QuicConnection>>(emptyList())
    /** Key updates observed over all accepted connections (the `keyupdate` interop case). */
    val keyUpdatesSeen: Long get() = connections.load().sumOf { it.stats.keyUpdates }

    private fun run() { for (ep in endpoints) scope.launch { while (true) { val c = ep.accept(); accepted.incrementAndFetch(); while (true) { val l = connections.load(); if (connections.compareAndSet(l, l + c)) break }; launch { serve(c) } } } }
    private suspend fun serve(c: QuicConnection) {
        try { while (true) { val st = c.acceptStream(); scope.launch { runCatching { handle(st) } } } } catch (_: Exception) { }
    }
    private suspend fun handle(st: QuicStream) {
        val line = StringBuilder(); val one = ByteArray(1)
        while (!line.endsWith("\n") && line.length < 4096) { if (st.input.readAvailable(one, 0, 1) < 0) break; line.append(one[0].toInt().toChar()) }
        val request = line.toString().trim(); val path = request.removePrefix("GET").trim().substringBefore(' ').trimStart('/')
        val file = "$www/$path"
        if (request.startsWith("GET") && path.isNotEmpty() && Files.inside(www, file)) { Files.read(file)?.let { st.output.writeFully(it, 0, it.size) } }
        st.output.flushAndClose()
    }
    override fun close() { scope.cancel(); for (ep in endpoints) ep.close() }

    companion object {
        suspend fun start(identity: TlsIdentity, port: Int, www: String, versions: List<VersionProfile>, host: String = "0.0.0.0", admission: ConnectionAdmission = ConnectionAdmission.default(), cipherSuites: CipherSuites = CipherSuites.Default, handshakeTimeout: Duration = 10.seconds, qlog: QlogSink? = null, ipv6: Boolean = true, congestionController: () -> CongestionController = { Cubic() }): HqInteropServer {
            val tls = tlsConfig(TlsRole.Server) { alpn = listOf("hq-interop"); this.identity = identity; this.cipherSuites = cipherSuites }
            val quic = quicConfig { this.versions = versions; maxBidiStreams = 1000; this.qlog = qlog; this.handshakeTimeout = handshakeTimeout; this.congestionController = congestionController }
            val config = QuicEndpointConfig.Builder().apply { server = QuicServerConfig.Builder(tls).apply { this.quic = quic }.build(); this.admission = admission }.build()
            val v4 = QuicEndpoint.bind(InetSocketAddress(host, port), config)
            val endpoints = ArrayList<QuicEndpoint>(2); endpoints += v4
            if (ipv6 && host == "0.0.0.0") try { endpoints += QuicEndpoint.bind(InetSocketAddress("::", port), config) } catch (e: Exception) { Files.log("IPv6 endpoint not bound: ${e.message}") }
            return HqInteropServer(endpoints, www).also { it.run() }
        }
    }
}
