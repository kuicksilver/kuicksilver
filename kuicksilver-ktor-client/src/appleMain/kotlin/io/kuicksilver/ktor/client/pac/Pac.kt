// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.pac

import io.kuicksilver.ktor.client.CfProxy
import io.kuicksilver.ktor.client.PAC_TIMEOUT_MILLIS
import kotlinx.coroutines.withTimeoutOrNull

/** How long one run of `FindProxyForURL` may take. */
internal const val PAC_EVAL_TIMEOUT_MILLIS: Long = 2_000

/**
 * The engine's own PAC engine on Apple platforms: the script of a system setting's PAC entry ([CfProxy.pacUrl], a script
 * given inline, or WPAD's discovery when [CfProxy.wpad]) run on JavaScriptCore by [PacRunner] with the URI [target] and
 * [host], within [PAC_TIMEOUT_MILLIS] in all; the answer as [CfProxy] entries, or null when there is none.
 */
internal suspend fun evaluatePac(
    entry: CfProxy,
    target: String,
    host: String,
): List<CfProxy>? =
    withTimeoutOrNull(PAC_TIMEOUT_MILLIS) {
        val (key, script) =
            when {
                entry.pacScript != null -> {
                    "script:${entry.pacScript.hashCode()}:${entry.pacScript.length}" to entry.pacScript
                }

                entry.wpad -> {
                    wpadScript() ?: return@withTimeoutOrNull null
                }

                entry.pacUrl != null -> {
                    entry.pacUrl to
                        (PacScripts.script(entry.pacUrl, PAC_TIMEOUT_MILLIS) ?: return@withTimeoutOrNull null)
                }

                else -> {
                    return@withTimeoutOrNull null
                }
            }
        PacRunner.findProxy(key, script, target, host, PAC_EVAL_TIMEOUT_MILLIS)?.let { parsePacResult(it) }
    }

/** The first WPAD candidate whose script downloads ([wpadCandidates]), with its URL as the key. */
private suspend fun wpadScript(): Pair<String, String>? {
    for (url in wpadCandidates(dhcpWpadUrl(), dnsDomains())) {
        PacScripts.script(url, PAC_TIMEOUT_MILLIS)?.let { return url to it }
    }
    return null
}

/**
 * A `FindProxyForURL` answer as [CfProxy] entries, in order: `DIRECT`, `PROXY`/`HTTP host:port` (an HTTP proxy), `SOCKS`
 * and `SOCKS5 host:port` (SOCKS5, as CFNetwork reads `SOCKS`). `HTTPS` (TLS to the proxy) and `SOCKS4`, which the engine
 * does not speak, and anything it cannot read, are skipped.
 */
internal fun parsePacResult(answer: String): List<CfProxy> =
    answer.split(';').mapNotNull { raw ->
        val parts = raw.trim().split(Regex("\\s+"), limit = 2)
        val kind = parts[0].uppercase()
        if (kind == "DIRECT") return@mapNotNull CfProxy(CfProxy.Type.None, null, null)
        val hostPort = parts.getOrNull(1)?.trim() ?: return@mapNotNull null
        val (h, p) = splitPacHostPort(hostPort) ?: return@mapNotNull null
        when (kind) {
            "PROXY", "HTTP" -> CfProxy(CfProxy.Type.Http, h, p ?: 80)
            "SOCKS", "SOCKS5" -> CfProxy(CfProxy.Type.Socks, h, p ?: 1080)
            else -> null
        }
    }

/** `host:port`, `[v6]:port` or `host`; null when the port is not a number in 1..65535. */
private fun splitPacHostPort(s: String): Pair<String, Int?>? {
    val (host, port) =
        if (s.startsWith('[')) {
            val end = s.indexOf(']')
            if (end < 0) return null
            s.substring(1, end) to s.substring(end + 1).removePrefix(":").ifEmpty { null }
        } else if (s.count { it == ':' } == 1) {
            s.substringBefore(':') to s.substringAfter(':')
        } else {
            s to null
        }
    if (host.isEmpty()) return null
    val p = port?.let { it.toIntOrNull()?.takeIf { n -> n in 1..65535 } ?: return null }
    return host to p
}
