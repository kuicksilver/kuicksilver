// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.http.Url

/**
 * One alternative service of an origin (RFC 7838 section 3): `protocol="host:port"`, valid until [expiresAtEpochMillis].
 *
 * @property protocol the ALPN protocol id of the alternative; the engine stores and uses only `h3`.
 * @property host the alternative's host; null when the header left it empty, meaning the origin's own host.
 * @property port the alternative's UDP port, 1..65535.
 * @property expiresAtEpochMillis the end of freshness in epoch milliseconds: receipt time plus `ma` (86400 s by default).
 * @property persist `persist=1`: the entry survives a network change even with [Http3ClientConfig.clearOnNetworkChange].
 */
public class AltSvcEntry(
    public val protocol: String,
    public val host: String?,
    public val port: Int,
    public val expiresAtEpochMillis: Long,
    public val persist: Boolean,
) {
    override fun toString(): String = "$protocol=\"${host ?: ""}:$port\" (expires $expiresAtEpochMillis${if (persist) ", persist" else ""})"
}

/**
 * Storage of Alt-Svc records by origin (`https://host:port`); implement it to keep them across restarts. The engine calls
 * it under its own lock, so an implementation used by one engine needs no locking of its own.
 */
public interface AltSvcStore {
    /** The entries stored for [origin], expired ones included (the engine skips those); empty when there are none. */
    public fun get(origin: String): List<AltSvcEntry>

    /** Replaces every entry of [origin] with [entries], as a new `Alt-Svc` header does (RFC 7838 section 3); empty removes them. */
    public fun put(
        origin: String,
        entries: List<AltSvcEntry>,
    )

    /** Forgets [origin]'s entries: after `Alt-Svc: clear` or a 421 response (RFC 7838 sections 3, 6). */
    public fun remove(origin: String)

    /** Drops every entry without `persist=1` (a network change, RFC 7838 section 2.2). */
    public fun clearNonPersistent()
}

/** The default [AltSvcStore]: in memory, thread-safe enough for one engine (all calls happen under the engine's lock). */
public class InMemoryAltSvcStore : AltSvcStore {
    private val map = HashMap<String, List<AltSvcEntry>>()

    override fun get(origin: String): List<AltSvcEntry> = map[origin].orEmpty()

    override fun put(
        origin: String,
        entries: List<AltSvcEntry>,
    ) {
        if (entries.isEmpty()) {
            map.remove(origin)
        } else {
            map[origin] =
                entries.toList()
        }
    }

    override fun remove(origin: String) {
        map.remove(origin)
    }

    override fun clearNonPersistent() {
        for (k in map.keys.toList()) {
            val kept = map[k]!!.filter { it.persist }
            if (kept.isEmpty()) {
                map.remove(k)
            } else {
                map[k] =
                    kept
            }
        }
    }
}

/** The `Alt-Svc` header (RFC 7838 section 3): a list of `protocol="host:port"; ma=..; persist=1`, or `clear`. */
internal object AltSvcParser {
    private const val DEFAULT_MA_SECONDS = 86_400L

    /** The `h3` entries of [value] (other protocols are ignored, malformed entries skipped); null for `clear`. */
    fun parse(
        value: String,
        nowMillis: Long,
    ): List<AltSvcEntry>? {
        if (value.trim() == "clear") return null
        val out = ArrayList<AltSvcEntry>()
        for (alt in splitTopLevel(value, ',')) {
            val parts = splitTopLevel(alt, ';').map { it.trim() }
            val head = parts.firstOrNull() ?: continue
            val eq = head.indexOf('=')
            if (eq <= 0) continue
            val protocol = head.substring(0, eq).trim()
            val authority = unquote(head.substring(eq + 1).trim()) ?: continue
            val colon = authority.lastIndexOf(':')
            if (colon < 0) continue
            val port = authority.substring(colon + 1).toIntOrNull()?.takeIf { it in 1..65_535 } ?: continue
            val host =
                authority
                    .substring(0, colon)
                    .removePrefix("[")
                    .removeSuffix("]")
                    .ifEmpty { null }
            var ma = DEFAULT_MA_SECONDS
            var persist = false
            var bad = false
            for (p in parts.drop(1)) {
                val k = p.substringBefore('=').trim().lowercase()
                val raw = p.substringAfter('=', "").trim()
                val v = unquote(raw) ?: raw
                when (k) {
                    "ma" -> {
                        ma = v.toLongOrNull()?.takeIf { it >= 0 } ?: run {
                            bad = true
                            0L
                        }
                    }

                    "persist" -> {
                        persist = v == "1"
                    }
                }
            }
            if (bad || protocol != "h3") continue
            out += AltSvcEntry(protocol, host, port, nowMillis + minOf(ma, Long.MAX_VALUE / 2000) * 1000, persist)
        }
        return out
    }

    private fun unquote(s: String): String? =
        when {
            s.length >= 2 && s.startsWith('"') && s.endsWith('"') -> s.substring(1, s.length - 1)
            else -> null // alt-authority is a quoted-string (RFC 7838 section 3)
        }

    private fun splitTopLevel(
        s: String,
        sep: Char,
    ): List<String> {
        val out = ArrayList<String>()
        val cur = StringBuilder()
        var quoted = false
        for (c in s) {
            if (c == '"') quoted = !quoted
            if (c == sep && !quoted) {
                out += cur.toString()
                cur.clear()
            } else {
                cur.append(c)
            }
        }
        if (cur.isNotBlank()) out += cur.toString()
        return out
    }
}

/**
 * The client's Alt-Svc knowledge by origin (RFC 7838): only from responses over verified TLS, a new header
 * replaces all entries of the origin, `clear` and 421 remove them, an unprivileged alternative port is refused for a
 * privileged origin port (as Chromium does), and expired entries are ignored.
 */
internal class AltSvcCache(
    private val store: AltSvcStore,
    private val clock: () -> Long,
) {
    fun originOf(url: Url): String = "${url.protocol.name}://${url.host}:${url.port}"

    fun onResponse(
        url: Url,
        status: Int,
        values: List<String>,
        verifiedTls: Boolean,
    ) {
        if (!verifiedTls) return // threat-model 3.18: never learn an alternative from an unauthenticated response
        val origin = originOf(url)
        if (status == 421) {
            store.remove(origin)
            return
        } // RFC 7838 section 6: the alternative misdirected us
        if (values.isEmpty()) return
        val now = clock()
        val entries = ArrayList<AltSvcEntry>()
        for (v in values) {
            val parsed =
                AltSvcParser.parse(v, now) ?: run {
                    store.remove(origin)
                    return
                }
            entries += parsed
        }
        val usable = entries.filter { !(url.port < 1024 && it.port >= 1024) }
        if (usable.isEmpty()) store.remove(origin) else store.put(origin, usable)
    }

    /** A live `h3` alternative of the origin of [url], or null. */
    fun h3For(url: Url): AltSvcEntry? {
        val now = clock()
        return store.get(originOf(url)).firstOrNull {
            it.protocol == "h3" &&
                it.expiresAtEpochMillis > now
        }
    }

    fun remove(url: Url) {
        store.remove(originOf(url))
    }

    fun onNetworkChanged(clearNonPersistent: Boolean) {
        if (clearNonPersistent) store.clearNonPersistent()
    }
}
