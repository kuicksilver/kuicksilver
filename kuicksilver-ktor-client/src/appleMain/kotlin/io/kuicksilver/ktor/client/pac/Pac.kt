// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.pac

import io.kuicksilver.ktor.client.CfProxy
import io.kuicksilver.ktor.client.PAC_TIMEOUT_MILLIS
import io.kuicksilver.ktor.client.PacOutcome
import kotlinx.coroutines.withTimeoutOrNull

/** How long one run of `FindProxyForURL` may take. */
internal const val PAC_EVAL_TIMEOUT_MILLIS: Long = 2_000

/**
 * The engine's own PAC engine on Apple platforms: the script of a system setting's PAC entry ([CfProxy.pacUrl], a script
 * given inline, or WPAD's discovery when [CfProxy.wpad]) run on JavaScriptCore by [PacRunner] with the URI [target] and
 * [host], within [PAC_TIMEOUT_MILLIS] in all. [PacOutcome.NoWpad] when WPAD found no script; [PacOutcome.Failed] when the
 * script could not be had or run, or its answer could not be read.
 */
internal suspend fun evaluatePac(
    entry: CfProxy,
    target: String,
    host: String,
): PacOutcome =
    withTimeoutOrNull(PAC_TIMEOUT_MILLIS) {
        val deadline = PacRunner.now() + PAC_TIMEOUT_MILLIS
        val (key, script) =
            when {
                entry.pacScript != null -> {
                    "script:${entry.pacScript.hashCode()}:${entry.pacScript.length}" to entry.pacScript
                }

                entry.wpad -> {
                    wpadScript(deadline) ?: return@withTimeoutOrNull PacOutcome.NoWpad
                }

                entry.pacUrl != null -> {
                    entry.pacUrl to (PacScripts.script(entry.pacUrl, PAC_TIMEOUT_MILLIS) ?: return@withTimeoutOrNull PacOutcome.Failed)
                }

                else -> {
                    return@withTimeoutOrNull PacOutcome.Failed
                }
            }
        val answer = PacRunner.findProxy(key, script, target, host, PAC_EVAL_TIMEOUT_MILLIS) ?: return@withTimeoutOrNull PacOutcome.Failed
        val proxies = parsePacResult(answer)
        if (proxies.isEmpty()) PacOutcome.Failed else PacOutcome.Answer(proxies)
    } ?: PacOutcome.Failed

/**
 * The first WPAD candidate whose script downloads ([wpadCandidates]), with its URL as the key. Each candidate gets an
 * equal share of what remains before [deadline] (a candidate that hangs cannot take the others' time), and a failed or
 * timed-out one is remembered by [PacScripts] for a minute. Discovered URLs are `http` or `https` only.
 */
private suspend fun wpadScript(deadline: Long): Pair<String, String>? {
    val candidates = wpadCandidates(dhcpWpadUrl(), dnsSearchDomains())
    for ((i, url) in candidates.withIndex()) {
        val share = (deadline - PacRunner.now()) / (candidates.size - i)
        if (share <= 0) return null
        PacScripts.script(url, share, allowFile = false)?.let { return url to it }
    }
    return null
}

/**
 * A `FindProxyForURL` answer as [CfProxy] entries, in order: `DIRECT`, `PROXY`/`HTTP host:port` (an HTTP proxy), `SOCKS`
 * and `SOCKS5 host:port` (SOCKS5, as CFNetwork reads `SOCKS`). `HTTPS` (TLS to the proxy) and `SOCKS4`, which the engine
 * does not speak, are [CfProxy.Type.Unsupported] (they fail closed, `pickCfProxyWithPac`); anything it cannot read is
 * skipped.
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
            "HTTPS" -> CfProxy(CfProxy.Type.Unsupported, h, p ?: 443)
            "SOCKS4" -> CfProxy(CfProxy.Type.Unsupported, h, p ?: 1080)
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
