// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.compose

import io.kuicksilver.ktor.client.FallbackReason
import io.kuicksilver.ktor.client.ProtocolDiagnostics
import kotlin.math.ceil

/** What the Diagnostics screen shows of a response's [ProtocolDiagnostics], as plain values (the screen model's input). */
data class DiagnosticsView(
    val protocol: String,
    val reason: String?,
    val fallback: FallbackReason?,
    val alternative: String?,
    val alternativeSource: String?,
    val raced: Boolean,
    val attempts: Int,
    val h3Failure: String?,
)

/** The view of these diagnostics; the HTTP/3 failure by its type only, as the engine's log line has it. */
fun ProtocolDiagnostics.toView(): DiagnosticsView =
    DiagnosticsView(
        protocol = protocol.toString(),
        reason = reason.name,
        fallback = fallback,
        alternative = alternative,
        alternativeSource = alternativeSource?.name,
        raced = raced,
        attempts = attempts,
        h3Failure = h3Failure?.let { it::class.simpleName ?: "Error" },
    )

/** What to check for each [FallbackReason], after the table in its KDoc (docs/guide/ktor.md, "Why did this request not use HTTP/3?"). */
fun fallbackHint(reason: FallbackReason): String =
    when (reason) {
        FallbackReason.NotSecure -> "HTTP/3 needs https://"
        FallbackReason.Proxy -> "a proxy applies to the request; QUIC does not go through it"
        FallbackReason.Configuration -> "the discovery mode is H1Only"
        FallbackReason.Http3Disabled -> "the kill switch: http3Allowed returned false (the toggle above)"
        FallbackReason.NoAlternative -> "the origin announced no Alt-Svc yet: run the request again, it learned it from this response"
        FallbackReason.MisdirectedRequest -> "the alternative answered 421: its certificate and virtual hosts"
        FallbackReason.BrokenAlternative -> "HTTP/3 failed here lately on this network; it is tried again after a while or on another network"
        FallbackReason.WebSocket -> "expected for the first WebSocket to an origin"
        FallbackReason.HandshakeTimeout -> "no QUIC answer: UDP to the port blocked (firewall, VPN, network), or the server is down"
        FallbackReason.UdpUnreachable -> "the network reported the UDP port unreachable"
        FallbackReason.H3NotReady -> "nothing: HTTP/1.1 was ready first, a later request may use HTTP/3"
        FallbackReason.Refused -> "the server refused QUIC (draining, full, or no common version)"
        FallbackReason.TlsFailure -> "the certificate or the h3 ALPN of the UDP side"
        FallbackReason.Http3Error -> "the HTTP/3 connection failed as a whole; the HTTP/3 failure below"
        FallbackReason.ZeroRttRejected -> "nothing: the request went again"
        FallbackReason.GoAway -> "the server is shutting down"
        FallbackReason.StreamFailed -> "one request stream failed; the HTTP/3 failure below"
        FallbackReason.Other -> "the HTTP/3 failure below"
        FallbackReason.H2Refused -> "the server's HTTP/2 configuration (it answered HTTP_1_1_REQUIRED)"
    }

/** The Diagnostics screen's lines for a response: the protocol first; null when another engine served it. */
fun renderDiagnostics(view: DiagnosticsView?): List<String> {
    if (view == null) return listOf("No Kuicksilver diagnostics: another engine served this response")
    return buildList {
        add("Protocol: ${view.protocol}")
        view.reason?.let { add("Chosen because: $it") }
        view.fallback?.let {
            add("Not HTTP/3 because: ${it.name}")
            add("What to check: ${fallbackHint(it)}")
        }
        view.alternative?.let { add("Alternative: $it" + (view.alternativeSource?.let { s -> " ($s)" } ?: "")) }
        if (view.raced) add("HTTP/3 and TCP raced")
        if (view.attempts > 1) add("Attempts: ${view.attempts}")
        view.h3Failure?.let { add("HTTP/3 failure: $it") }
    }
}

/** The median and the 90th percentile of a series of [n] samples. */
data class SeriesStats(
    val n: Int,
    val median: Double,
    val p90: Double,
)

/** The median (the mean of the two middle samples for an even count) and the nearest-rank 90th percentile; null when empty. */
fun seriesStats(samples: List<Double>): SeriesStats? {
    if (samples.isEmpty()) return null
    val s = samples.sorted()
    val n = s.size
    val median = if (n % 2 == 1) s[n / 2] else (s[n / 2 - 1] + s[n / 2]) / 2
    val p90 = s[ceil(0.9 * n).toInt().coerceIn(1, n) - 1]
    return SeriesStats(n, median, p90)
}
