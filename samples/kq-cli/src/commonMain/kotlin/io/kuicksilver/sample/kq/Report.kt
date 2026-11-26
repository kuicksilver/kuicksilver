// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.kq

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.ktor.client.ProtocolDiagnostics
import io.kuicksilver.ktor.client.QuicConnectionSnapshot
import io.kuicksilver.ktor.client.TcpConnectionSnapshot
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.ZeroRttOutcome
import kotlin.time.Duration

/** The request a report is about: [n] of [of] repeats. */
data class Request(
    val method: String,
    val url: String,
    val n: Int,
    val of: Int,
)

/** The status, the time to the response head and to the end of the body, and the body's length. */
data class Timing(
    val status: Int,
    val head: Duration,
    val total: Duration,
    val bytes: Long,
)

/**
 * The verbose lines (`-v`) of one response, from public API only: the engine's [ProtocolDiagnostics] of the response, the
 * [QuicObserver]'s facts about its QUIC connection (joined by `QuicConnectionSnapshot.connectionId`) and the QUIC versions
 * the engine offers ([offered], `KuicksilverEngineConfig.quic.versions`).
 */
fun report(
    req: Request,
    d: ProtocolDiagnostics?,
    observer: QuicObserver,
    offered: List<VersionProfile>,
    earlyData: Boolean,
    t: Timing,
): List<String> {
    val lines = mutableListOf<String>()
    lines += "* ${req.method} ${req.url}" + if (req.of > 1) " (${req.n} of ${req.of})" else ""
    if (d == null) {
        lines += "* no Kuicksilver diagnostics on this response"
    } else {
        when (val c = d.connection) {
            is QuicConnectionSnapshot -> {
                val facts = c.connectionId?.let { observer[it] }
                lines += "* ${protocolName(d.protocol)} over QUIC ${versionText(offered)}, ALPN ${facts?.alpn ?: "?"}, " +
                    (if (c.reused) "reused connection" else "new connection") + (c.remoteAddress?.let { " to ${addr(it)}" } ?: "")
                val hs = facts?.handshake?.let { "QUIC handshake ${ms(it)}" + if (c.reused) " (when the connection opened)" else "" }
                val zero =
                    when {
                        facts?.zeroRtt == ZeroRttOutcome.Accepted -> "0-RTT accepted"
                        facts?.zeroRtt == ZeroRttOutcome.Rejected -> "0-RTT rejected by the server"
                        !earlyData -> "0-RTT off (--0rtt)"
                        c.reused -> "0-RTT not in play (reused connection)"
                        else -> "0-RTT not used (no session ticket for this server yet)"
                    }
                lines += "* " + listOfNotNull(hs, "RTT ${ms(c.smoothedRtt)} smoothed, ${ms(c.minRtt)} min", zero).joinToString("; ")
                if (c.pathChanges > 0) lines += "* the connection moved to another path ${c.pathChanges} time(s) during the call"
            }

            is TcpConnectionSnapshot -> {
                lines += "* ${c.protocol?.let(::protocolName) ?: "no protocol"} over TCP" +
                    (if (c.secure) ", TLS" else ", cleartext") + (c.alpn?.let { ", ALPN $it" } ?: "") +
                    (if (c.reused) ", reused connection" else ", new connection") +
                    (c.remoteAddress?.let { " to ${addr(it)}" } ?: "") + (if (c.viaProxy) " (proxy)" else "")
            }

            null -> {
                lines += "* ${protocolName(d.protocol)}"
            }
        }
        lines += "* chosen because: ${d.reason}" +
            (d.alternative?.let { " (HTTP/3 alternative $it" + (d.alternativeSource?.let { s -> " from $s" } ?: "") + ")" } ?: "")
        d.fallback?.let { lines += "* not HTTP/3: $it" }
        d.h3Failure?.let { lines += "* HTTP/3 failed: ${it::class.simpleName}: ${it.message}" }
        if (d.raced) {
            val hs = d.headStart
            lines += "* HTTP/3 and TCP raced, HTTP/3 head start " + if (hs == null || hs.isInfinite()) "until it failed" else ms(hs)
        }
        d.connectFailures.forEach { lines += "* connect failure: $it" }
        if (d.attempts > 1) lines += "* attempts: ${d.attempts}"
    }
    lines += "* ${t.status}, head after ${ms(t.head)}, ${t.bytes} body bytes in ${ms(t.total)}"
    return lines
}

/**
 * The `Alt-Svc` field lines of a response, as received (RFC 7838 section 3): what the engine learns from, including
 * `clear`, which drops the origin's alternatives, and an empty value, which it ignores.
 */
fun altSvcLines(values: List<String>?): List<String> =
    values.orEmpty().map { v ->
        when {
            v.isBlank() -> "* Alt-Svc received: (empty, ignored)"
            v.trim() == "clear" -> "* Alt-Svc received: clear (the origin's alternatives are dropped)"
            else -> "* Alt-Svc received: $v"
        }
    }

/** Why a call failed, from the diagnostics its exception carries (`Throwable.kuicksilverDiagnostics`). */
fun failureLines(d: ProtocolDiagnostics?): List<String> {
    if (d == null) return emptyList()
    val lines = mutableListOf<String>()
    lines += "failed over ${d.transport ?: "no transport (before any attempt)"}, last tried ${protocolName(d.protocol)}" +
        (d.fallback?.let { ", not HTTP/3: $it" } ?: "")
    d.h3Failure?.let { lines += "HTTP/3 failed: ${it::class.simpleName}: ${it.message}" }
    d.connectFailures.forEach { lines += "connect failure: $it" }
    return lines
}

/** `v1` when the engine offers one version (the default), else the list: which one the server chose is not reported. */
fun versionText(offered: List<VersionProfile>): String =
    when (offered.size) {
        0 -> "(version unknown)"
        1 -> versionName(offered[0])
        else -> "(one of ${offered.joinToString(", ") { versionName(it) }})"
    }

private fun versionName(v: VersionProfile): String =
    when (v.version) {
        1 -> "v1"
        0x6b3343cf -> "v2"
        else -> "0x" + v.version.toUInt().toString(16).padStart(8, '0')
    }

/** `12.3ms`: one decimal, the same on every locale (Duration.toString formats with the JVM's). */
fun ms(d: Duration): String {
    if (d < Duration.ZERO || d.isInfinite()) return "?"
    val tenths = (d.inWholeMicroseconds + 50) / 100
    return "${tenths / 10}.${tenths % 10}ms"
}

/**
 * The address as numbers: never `InetSocketAddress.hostname`, which on the JVM is a reverse name lookup
 * (`java.net.InetSocketAddress.getHostName`) that can block for seconds on a slow resolver.
 */
private fun addr(a: InetSocketAddress): String {
    val b = a.resolveAddress() ?: return "?:${a.port}"
    return when (b.size) {
        4 -> b.joinToString(".") { (it.toInt() and 0xff).toString() } + ":${a.port}"
        16 -> "[" + (0 until 8).joinToString(":") { ((b[2 * it].toInt() and 0xff) shl 8 or (b[2 * it + 1].toInt() and 0xff)).toString(16) } + "]:${a.port}"
        else -> "?:${a.port}"
    }
}
