// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.interop

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.Http3ServerRequest
import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.CongestionController
import io.kuicksilver.quic.Cubic
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.tls.CipherSuites
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.keylogFile
import io.kuicksilver.tls.tlsConfig
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * The runner's `http3` case on the server side (K5): `GET /path` over HTTP/3 answers 200 with the file from
 * `www` (`content-length` set), 404 otherwise; IPv4 and, when the host has it, IPv6 on the same port like [HqInteropServer].
 */
@OptIn(ExperimentalAtomicApi::class)
internal class H3InteropServer private constructor(private val endpoints: List<Http3Endpoint>, private val www: String) : AutoCloseable {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val accepted = AtomicInt(0)
    val port: Int get() = endpoints[0].localAddress.port
    val port6: Int? get() = endpoints.getOrNull(1)?.localAddress?.port
    val connectionsAccepted: Int get() = accepted.load()
    private val statuses = AtomicReference<Map<String, Int>>(emptyMap())
    /** The status last answered for the file [name] (tests). */
    fun lastStatusFor(name: String): Int? = statuses.load()[name]

    private fun run() { for (ep in endpoints) scope.launch { while (true) { val c = ep.accept(); accepted.incrementAndFetch(); launch { serve(c) } } } }
    private suspend fun serve(c: Http3Connection) {
        try { while (true) { val r = c.acceptRequest(); scope.launch { runCatching { handle(r) } } } } catch (_: Exception) { }
    }
    private suspend fun handle(r: Http3ServerRequest) {
        val path = (r.path ?: "/").substringBefore('?').trimStart('/'); val file = "$www/$path"
        val bytes = if (r.method == "GET" && path.isNotEmpty() && Files.inside(www, file)) Files.read(file) else null
        val status = if (bytes == null) 404 else 200
        while (true) { val m = statuses.load(); if (statuses.compareAndSet(m, m + (path.substringAfterLast('/') to status))) break }
        if (bytes == null) { r.respond(404, Http3Headers.of("content-length" to "0")).finish(); return }
        val w = r.respond(200, Http3Headers.of("content-type" to "application/octet-stream", "content-length" to bytes.size.toString()))
        w.output.writeFully(bytes, 0, bytes.size); w.finish()
    }
    override fun close() { scope.cancel(); for (ep in endpoints) ep.close() }

    companion object {
        suspend fun start(identity: TlsIdentity, port: Int, www: String, versions: List<VersionProfile>, host: String = "0.0.0.0", admission: ConnectionAdmission = ConnectionAdmission.default(), cipherSuites: CipherSuites = CipherSuites.Default, handshakeTimeout: Duration = 10.seconds, qlog: QlogSink? = null, ipv6: Boolean = true, congestionController: () -> CongestionController = { Cubic() }): H3InteropServer {
            val tls = tlsConfig(TlsRole.Server) { alpn = listOf(Http3Endpoint.H3); this.identity = identity; this.cipherSuites = cipherSuites }
            val quic = quicConfig { this.versions = versions; maxBidiStreams = 1000; this.qlog = qlog; this.handshakeTimeout = handshakeTimeout; this.congestionController = congestionController }
            val config = QuicEndpointConfig.Builder().apply { server = QuicServerConfig.Builder(tls).apply { this.quic = quic }.build(); this.admission = admission }.build()
            val endpoints = ArrayList<Http3Endpoint>(2); endpoints += Http3Endpoint.bind(InetSocketAddress(host, port), config)
            if (ipv6 && host == "0.0.0.0") try { endpoints += Http3Endpoint.bind(InetSocketAddress("::", port), config) } catch (e: Exception) { Files.log("IPv6 endpoint not bound: ${e.message}") }
            return H3InteropServer(endpoints, www).also { it.run() }
        }
    }
}

/** The runner's `http3` case on the client side: every request is a GET over one HTTP/3 connection; a non-200 answer fails the case. */
@OptIn(DelicateKuicksilverApi::class)
internal object H3InteropClient {
    suspend fun download(requests: List<String>, downloads: String, plan: Testcases.ClientPlan, trust: TrustConfig, keylog: String?, qlog: QlogSink?): Boolean {
        if (requests.isEmpty()) return false
        val first = Url.parse(requests[0])
        val tls = tlsConfig(TlsRole.Client) { alpn = listOf(Http3Endpoint.H3); serverName = first.host.takeUnless { it.contains(':') }; this.trust = trust; cipherSuites = plan.cipherSuites; keylog?.let { this.keylog = keylogFile(it) } }
        val quic = quicConfig { versions = plan.quic.versions; initialVersion = plan.quic.initialVersion; handshakeTimeout = plan.quic.handshakeTimeout; congestionController = plan.quic.congestionController; this.qlog = qlog }
        val remote = InetSocketAddress(first.host, first.port)
        val v6 = (remote.resolveAddress()?.size ?: 4) == 16
        val endpoint = Http3Endpoint.bind(InetSocketAddress(if (v6) "::" else "0.0.0.0", 0), QuicEndpointConfig.Builder().build())
        try {
            return withTimeout(600.seconds) {
                val conn = endpoint.connect(remote, tls, quic)
                val authority = if (first.host.contains(':')) "[${first.host}]:${first.port}" else "${first.host}:${first.port}"
                val ok = coroutineScope { requests.map { url -> async { fetch(conn, authority, Url.parse(url).path, downloads) } }.awaitAll().all { it } }
                conn.close(); ok
            }
        } finally { endpoint.close() }
    }
    private suspend fun fetch(conn: Http3Connection, authority: String, path: String, downloads: String): Boolean {
        val resp = conn.request(http3Request("GET", authority, path))
        val out = Buffer(); val buf = ByteArray(65536)
        while (true) { val n = resp.body.readAvailable(buf, 0, buf.size); if (n < 0) break; out.write(buf, 0, n) }
        // the library fails the read on a reset or a lost connection; -1 is only the message's end, and a cause with it is checked all the same
        resp.body.closedCause?.let { cause -> Files.log("GET $path: ended after ${out.size} bytes without FIN: $cause"); return false }
        if (resp.status != 200) { Files.log("GET $path: ${resp.status}"); return false }
        Files.write("$downloads/${path.substringAfterLast('/')}", out.readByteArray()); return true
    }
}
