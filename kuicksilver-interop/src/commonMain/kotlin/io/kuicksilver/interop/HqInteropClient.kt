// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.interop

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.keylogFile
import io.kuicksilver.tls.tlsConfig
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readAvailable
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeout
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlin.time.Duration.Companion.seconds

/** `https://host[:port]/path` for the runner's request lists; an IPv6 host is written in brackets. */
internal class Url(val host: String, val port: Int, val path: String) {
    companion object {
        fun parse(url: String): Url {
            val rest = url.substringAfter("://"); val authority = rest.substringBefore('/'); val path = "/" + rest.substringAfter('/', "")
            val host: String; val port: Int
            if (authority.startsWith("[")) { host = authority.substringAfter('[').substringBefore(']'); val p = authority.substringAfter("]:", ""); port = p.toIntOrNull() ?: 443 }
            else { host = authority.substringBefore(':'); port = authority.substringAfter(':', "").toIntOrNull() ?: 443 }
            return Url(host, port, path)
        }
    }
}

/**
 * Downloads every request (`hq-interop`), writing `<downloads>/<file name>`: over one connection, one per request
 * (`multiconnect`), or the first over one connection and the rest over a second that resumes its ticket (`resumption`;
 * `zerortt` sends them in 0-RTT through `connectEarly`).
 */
@OptIn(DelicateKuicksilverApi::class, ExperimentalKuicksilverApi::class, io.ktor.utils.io.InternalAPI::class)
internal object HqInteropClient {
    suspend fun download(requests: List<String>, downloads: String, plan: Testcases.ClientPlan, trust: TrustConfig, keylog: String?, qlog: QlogSink?): Boolean {
        if (requests.isEmpty()) return false
        val first = Url.parse(requests[0])
        val tls = tlsConfig(TlsRole.Client) { alpn = listOf("hq-interop"); serverName = first.host.takeUnless { it.contains(':') };   /* an IPv6 literal is no SNI name: the trust config names what to verify */ this.trust = trust; cipherSuites = plan.cipherSuites; keylog?.let { this.keylog = keylogFile(it) } }
        val quic = quicConfig { versions = plan.quic.versions; initialVersion = plan.quic.initialVersion; handshakeTimeout = plan.quic.handshakeTimeout; congestionController = plan.quic.congestionController; this.qlog = qlog }
        val client = QuicClientConfig.Builder(tls).apply { this.quic = quic; earlyData = plan.earlyData }.build()
        val remote = InetSocketAddress(first.host, first.port)
        val v6 = (remote.resolveAddress()?.size ?: 4) == 16   /* `server6` resolves to an IPv6 address: the local socket must be of that family */
        val endpoint = QuicEndpoint.bind(InetSocketAddress(if (v6) "::" else "0.0.0.0", 0), QuicEndpointConfig.Builder().build())
        try {
            return withTimeout(600.seconds) {
                if (plan.earlyData != EarlyDataState.Disabled) {
                    // the first connection's tickets stay in the endpoint's session cache (cleared only when the endpoint closes)
                    val first = endpoint.connect(remote, client); var ok = fetch(first, requests[0], downloads, null); first.close(0, "done")
                    val rest = requests.drop(1)
                    if (rest.isNotEmpty()) {
                        val second = if (plan.zeroRtt) endpoint.connectEarly(remote, client) else endpoint.connect(remote, client)
                        if (plan.zeroRtt) beforeZeroRttRequests(second)
                        // zerortt: connectEarly returned at the 0-RTT keys, so these requests leave in 0-RTT packets; the concurrent
                        // closes share packets (flushAndClose yields to the closes queued on the loop), so they fit the initial window
                        ok = coroutineScope { rest.map { url -> async { fetch(second, url, downloads, null) } }.awaitAll().all { it } } && ok
                        second.close(0, "done")
                    }
                    ok
                } else if (plan.connectionPerRequest) {
                    var ok = true
                    for (url in requests) { val conn = endpoint.connect(remote, client); ok = fetch(conn, url, downloads, null) && ok; conn.close(0, "done") }
                    ok
                } else {
                    val conn = endpoint.connect(remote, client)
                    val progress = if (plan.keyUpdateAfterBytes != null) KeyUpdateOnce(plan.keyUpdateAfterBytes) else null
                    val ok = coroutineScope { requests.map { url -> async { fetch(conn, url, downloads, progress) } }.awaitAll().all { it } }
                    conn.close(0, "done"); ok
                }
            }
        } finally { endpoint.close() }
    }
    /**
     * Runs between `connectEarly` and the `zerortt` case's 0-RTT requests (tests: force the client to write only after the
     * server has answered its ClientHello, the order that sends the requests in 1-RTT unless the answer is held back).
     */
    @kotlin.concurrent.Volatile var beforeZeroRttRequests: suspend (QuicConnection) -> Unit = {}
    /** Runs between `openBidi` and the request's write (tests: let the connection end there, a close the write path reports). */
    @kotlin.concurrent.Volatile var beforeRequest: suspend (QuicConnection) -> Unit = {}
    /** The `keyupdate` case: one key update once this many response bytes arrived (the runner wants it within the first MB). */
    private class KeyUpdateOnce(val after: Long) { var received = 0L; var done = false }
    /**
     * One request on a new stream. A stream opened before the handshake completed that the server's rejection of 0-RTT reset
     * (RFC 9001 section 4.6.2) is sent again on a new stream once the handshake completed.
     */
    private suspend fun fetch(conn: QuicConnection, url: String, downloads: String, progress: KeyUpdateOnce?): Boolean {
        val early = !conn.isHandshakeComplete
        val st = conn.openBidi(); beforeRequest(conn); request(st, url)
        val ok = try { st.output.flushAndClose(); receive(conn, st, url, downloads, progress) } catch (e: Exception) { if (e is kotlinx.coroutines.CancellationException || st.input.closedCause !is QuicException.StreamError.EarlyDataRejected) throw e; false }
        if (ok || !early || st.input.closedCause !is QuicException.StreamError.EarlyDataRejected) return ok
        conn.awaitHandshake(); return fetch(conn, url, downloads, progress)
    }
    /**
     * Writes the request into the channel's buffer, not through the auto-flushing writeFully, so flushAndClose sends it and
     * the FIN in one STREAM frame (quiche's hq server leaves 0-RTT requests whose FIN arrives in a frame of its own unanswered).
     */
    private fun request(st: QuicStream, url: String) { val req = "GET ${Url.parse(url).path}\r\n".encodeToByteArray(); st.output.writeBuffer.write(req, 0, req.size) }
    private suspend fun receive(conn: QuicConnection, st: QuicStream, url: String, downloads: String, progress: KeyUpdateOnce?): Boolean {
        val path = Url.parse(url).path
        val out = Buffer(); val buf = ByteArray(65536)
        while (true) {
            // the library fails the read on a reset or a lost connection; -1 is only a FIN, and a cause with it is checked all the same
            val n = st.input.readAvailable(buf, 0, buf.size); if (n < 0) break; out.write(buf, 0, n)
            if (progress != null && !progress.done) { progress.received += n; if (progress.received >= progress.after) { progress.done = true; conn.keyUpdate() } }
        }
        st.input.closedCause?.let { cause -> Files.log("$url: ended after ${out.size} bytes without FIN: $cause"); return false }
        Files.write("$downloads/${path.substringAfterLast('/')}", out.readByteArray()); return true
    }
}
