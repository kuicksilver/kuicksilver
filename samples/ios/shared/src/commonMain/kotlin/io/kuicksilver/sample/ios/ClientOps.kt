// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.ios

import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Request
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.PathEvent
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.quicClientConfig
import io.kuicksilver.tls.TofuStore
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.time.Duration
import kotlin.time.DurationUnit
import kotlin.time.TimeSource

/** The outcome of an HTTP/3 GET. */
data class HttpResult(
    val status: Int,
    /** The address the request went to (the name resolved once, as the endpoint does). */
    val remote: String,
    /** Response fields, one `name: value` per line. */
    val headers: String,
    val bodyBytes: Long,
    /** The first 4 KiB of the body as UTF-8. */
    val bodyPreview: String,
    /** Wall time from the first datagram to the end of the body. */
    val elapsedMs: Long,
    /** QUIC's smoothed RTT at the end. */
    val smoothedRttMs: Double,
)

/** The outcome of an echo session. */
data class EchoResult(val rounds: Int, val minMs: Double, val avgMs: Double, val maxMs: Double, val smoothedRttMs: Double, val pathChanges: Int)

internal data class ParsedUrl(val host: String, val port: Int, val path: String) {
    val authority: String get() = (if (host.contains(':')) "[$host]" else host) + if (port == 443) "" else ":$port"
}

internal fun parseHttpsUrl(url: String): ParsedUrl {
    val rest = url.trim().let { if (it.startsWith("https://")) it.removePrefix("https://") else if (it.contains("://")) throw IllegalArgumentException("HTTP/3 needs https://") else it }
    val slash = rest.indexOf('/').let { if (it < 0) rest.length else it }
    val hostPort = rest.substring(0, slash); val path = rest.substring(slash).ifEmpty { "/" }
    val (host, port) = when {
        hostPort.startsWith("[") -> hostPort.substringAfter('[').substringBefore(']') to (hostPort.substringAfter("]:", "443").toIntOrNull() ?: 443)
        hostPort.count { it == ':' } == 1 -> hostPort.substringBefore(':') to (hostPort.substringAfter(':').toIntOrNull() ?: throw IllegalArgumentException("bad port"))
        else -> hostPort to 443
    }
    require(host.isNotEmpty()) { "no host in $url" }
    return ParsedUrl(host, port, path)
}

private fun Duration.ms(): Double = toDouble(DurationUnit.MILLISECONDS)

/** One HTTP/3 GET on a fresh endpoint (a dual-stack socket on `[::]:0`, which also works on an IPv6-only NAT64 network). */
internal suspend fun http3Get(url: String, mode: TrustMode, tofu: TofuStore): HttpResult {
    val u = parseHttpsUrl(url)
    val start = TimeSource.Monotonic.markNow()
    Http3Endpoint.bind(InetSocketAddress("::", 0)).use { endpoint ->
        val connection = endpoint.connect(InetSocketAddress(u.host, u.port), clientTls(u.host, "h3", mode, tofu))
        try {
            val response = connection.request(Http3Request("GET", authority = u.authority, path = u.path))
            val preview = ByteArray(4096); var kept = 0; var total = 0L
            val buf = ByteArray(16 * 1024)
            while (true) {
                val n = response.body.readAvailable(buf, 0, buf.size)
                if (n <= 0) break
                val take = minOf(n, preview.size - kept); buf.copyInto(preview, kept, 0, take); kept += take; total += n
            }
            return HttpResult(
                status = response.status,
                remote = connection.quic.paths.firstOrNull()?.remoteAddress.show(),
                headers = response.headers.fields.joinToString("\n") { (k, v) -> "$k: $v" },
                bodyBytes = total,
                bodyPreview = preview.decodeToString(0, kept),
                elapsedMs = start.elapsedNow().inWholeMilliseconds,
                smoothedRttMs = connection.quic.stats.smoothedRtt.ms(),
            )
        } finally {
            connection.close()
        }
    }
}

/**
 * A raw QUIC echo session: [rounds] round trips of [message] on fresh bidirectional streams, [intervalMs] apart, logging
 * each round's time, QUIC's RTT estimate and every path event. [onConnected] gets the live connection so the screen can
 * migrate it to a new socket or, once the library has it, let it follow the default network.
 */
internal suspend fun quicEcho(
    host: String,
    port: Int,
    message: String,
    rounds: Int,
    intervalMs: Long,
    mode: TrustMode,
    tofu: TofuStore,
    log: (String) -> Unit,
    onConnected: (QuicConnection) -> Unit = {},
): EchoResult = QuicEndpoint.bind(InetSocketAddress("::", 0)).use { endpoint ->
    val t0 = TimeSource.Monotonic.markNow()
    val connection = endpoint.connect(InetSocketAddress(host, port), quicClientConfig(clientTls(host, ECHO_ALPN, mode, tofu)))
    val path = connection.paths.firstOrNull()
    log("connected in ${t0.elapsedNow().inWholeMilliseconds} ms: ${path?.localAddress.show()} -> ${path?.remoteAddress.show()}, ALPN ${connection.negotiatedAlpn}")
    onConnected(connection)
    var changes = 0
    val times = ArrayList<Double>()
    coroutineScope {
        val events = launch {
            connection.pathEvents.collect { e ->
                when (e) {
                    is PathEvent.Changed -> { changes++; log("path changed (${e.reason}): ${e.old.localAddress.show()} -> ${e.new.localAddress.show()}") }
                    is PathEvent.Validated -> log("path validated: ${e.path.localAddress.show()} -> ${e.path.remoteAddress.show()}")
                    is PathEvent.Failed -> log("path failed: ${e.path.localAddress.show()} -> ${e.path.remoteAddress.show()}")
                }
            }
        }
        val payload = message.encodeToByteArray()
        repeat(rounds) { i ->
            val mark = TimeSource.Monotonic.markNow()
            val stream = connection.openBidi()
            stream.output.writeFully(payload); stream.output.flushAndClose()
            val back = ByteArray(payload.size); var got = 0
            while (got < back.size) { val n = stream.input.readAvailable(back, got, back.size - got); if (n <= 0) break; got += n }
            check(got == payload.size && back.contentEquals(payload)) { "echo mismatch in round ${i + 1}" }
            val ms = mark.elapsedNow().ms(); times += ms
            val s = connection.stats
            log("round ${i + 1}: ${fmt(ms)} ms (srtt ${fmt(s.smoothedRtt.ms())} ms, min ${fmt(s.minRtt.ms())} ms, path ${s.currentPath.value})")
            if (intervalMs > 0 && i + 1 < rounds) delay(intervalMs)
        }
        events.cancel()
    }
    val srtt = connection.stats.smoothedRtt.ms()
    connection.close(code = 0, reason = "done")
    EchoResult(times.size, times.min(), times.average(), times.max(), srtt, changes)
}

/** Moves [connection] to a new socket, as an app does on a network change it detected itself (RFC 9000 section 9.2). */
internal suspend fun rebind(connection: QuicConnection, log: (String) -> Unit) {
    val e = connection.migrate(DatagramIo.open(InetSocketAddress("::", 0)))
    log("migrated (${e.reason}): ${e.old.localAddress.show()} -> ${e.new.localAddress.show()}")
}

/** `host:port` (`[v6]:port`), without ktor's `InetSocketAddress(...)` wrapper. */
internal fun InetSocketAddress?.show(): String = if (this == null) "?" else (if (hostname.contains(':')) "[$hostname]" else hostname) + ":" + port

internal fun fmt(v: Double): String = ((v * 10).toLong() / 10.0).toString()
