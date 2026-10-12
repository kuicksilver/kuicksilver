// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.interop

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.keylogFile
import io.kuicksilver.tls.tlsConfig
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
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
@OptIn(DelicateKuicksilverApi::class, ExperimentalKuicksilverApi::class)
internal object HqInteropClient {
    suspend fun download(requests: List<String>, downloads: String, plan: Testcases.ClientPlan, trust: TrustConfig, keylog: String?, qlog: QlogSink?): Boolean {
        if (requests.isEmpty()) return false
        val first = Url.parse(requests[0])
        val tls = tlsConfig(TlsRole.Client) { alpn = listOf("hq-interop"); serverName = first.host.takeUnless { it.contains(':') };   /* an IPv6 literal is no SNI name: the trust config names what to verify */ this.trust = trust; cipherSuites = plan.cipherSuites; keylog?.let { this.keylog = keylogFile(it) } }
        val quic = quicConfig { versions = plan.quic.versions; initialVersion = plan.quic.initialVersion; handshakeTimeout = plan.quic.handshakeTimeout; this.qlog = qlog }
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
                        // zerortt: connectEarly returned at the 0-RTT keys, so these requests leave in 0-RTT packets
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
    /** The `keyupdate` case: one key update once this many response bytes arrived (the runner wants it within the first MB). */
    private class KeyUpdateOnce(val after: Long) { var received = 0L; var done = false }
    private suspend fun fetch(conn: QuicConnection, url: String, downloads: String, progress: KeyUpdateOnce?): Boolean {
        val path = Url.parse(url).path
        val st = conn.openBidi(); val req = "GET $path\r\n".encodeToByteArray(); st.output.writeFully(req, 0, req.size); st.output.flushAndClose()
        val out = Buffer(); val buf = ByteArray(65536)
        while (true) {
            val n = st.input.readAvailable(buf, 0, buf.size); if (n < 0) break; out.write(buf, 0, n)
            if (progress != null && !progress.done) { progress.received += n; if (progress.received >= progress.after) { progress.done = true; conn.keyUpdate() } }
        }
        Files.write("$downloads/${path.substringAfterLast('/')}", out.readByteArray()); return true
    }
}
