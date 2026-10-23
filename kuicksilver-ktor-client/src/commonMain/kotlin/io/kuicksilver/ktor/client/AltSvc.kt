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
 *
 * Two entries are equal when they name the same alternative ([protocol], [host], [port], [persist]); the expiry is left
 * out, so a repeated `Alt-Svc` header compares equal to the stored one.
 */
public class AltSvcEntry(
    public val protocol: String,
    public val host: String?,
    public val port: Int,
    public val expiresAtEpochMillis: Long,
    public val persist: Boolean,
) {
    override fun equals(other: Any?): Boolean =
        other is AltSvcEntry && protocol == other.protocol && host == other.host && port == other.port && persist == other.persist

    override fun hashCode(): Int = ((protocol.hashCode() * 31 + host.hashCode()) * 31 + port) * 31 + persist.hashCode()

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

    /** Forgets [origin]'s entries: after `Alt-Svc: clear` (RFC 7838 section 3). */
    public fun remove(origin: String)

    /** Drops every entry without `persist=1` (a network change, RFC 7838 section 2.2). */
    public fun clearNonPersistent()
}

/**
 * The default [AltSvcStore]: in memory, thread-safe enough for one engine (all calls happen under the engine's lock).
 * It keeps at most 1000 origins; the least recently used go first (threat-model 3.18).
 */
public class InMemoryAltSvcStore : AltSvcStore {
    private val map = LinkedHashMap<String, List<AltSvcEntry>>()

    override fun get(origin: String): List<AltSvcEntry> = map.touch(origin).orEmpty()

    override fun put(
        origin: String,
        entries: List<AltSvcEntry>,
    ) {
        map.remove(origin)
        if (entries.isNotEmpty()) {
            map[origin] = entries.take(AltSvcCache.MAX_ENTRIES_PER_ORIGIN)
            map.evictEldest(AltSvcCache.MAX_ORIGINS)
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

    /**
     * The content of the quoted-string [s] with its quoted-pairs resolved (RFC 9110 section 5.6.4, as RFC 7838 section 3
     * requires), or null when [s] is not one quoted-string (alt-authority must be quoted).
     */
    private fun unquote(s: String): String? {
        if (s.length < 2 || s[0] != '"') return null
        val out = StringBuilder()
        var i = 1
        while (i < s.length) {
            when (val c = s[i]) {
                '\\' -> {
                    if (i + 1 >= s.length) return null
                    out.append(s[i + 1])
                    i += 2
                }

                '"' -> {
                    return if (i == s.length - 1) out.toString() else null
                }

                else -> {
                    out.append(c)
                    i++
                }
            }
        }
        return null // no closing quote
    }

    private fun splitTopLevel(
        s: String,
        sep: Char,
    ): List<String> {
        val out = ArrayList<String>()
        val cur = StringBuilder()
        var quoted = false
        var escaped = false
        for (c in s) {
            // inside a quoted-string a backslash takes the next character as is: an escaped quote does not end it
            if (escaped) {
                cur.append(c)
                escaped = false
                continue
            }
            if (quoted && c == '\\') {
                cur.append(c)
                escaped = true
                continue
            }
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
 * replaces all entries of the origin and `clear` removes them, an unprivileged alternative port is refused for a
 * privileged origin port (as Chromium does), and expired entries are ignored. A 421 changes nothing here: it is not
 * authoritative for the origin (RFC 9110 section 15.5.20), so its `Alt-Svc` is not learned, and only a 421 from an
 * alternative removes that alternative (RFC 7838 section 6), which the engine does as it knows where the 421 came from.
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
        if (status == 421 || values.isEmpty()) return
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
        // RFC 9000 section 21.5: no alternative on the client's own networks unless the origin is there (AltSvcDestination)
        val usable =
            entries
                .filter { !(url.port < 1024 && it.port >= 1024) && AltSvcDestination.allowed(url.host, it.host) }
                .take(MAX_ENTRIES_PER_ORIGIN)
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

    /** Forgets [entry] of the origin of [url] and keeps its other alternatives: a 421 from [entry] (RFC 7838 section 6). */
    fun removeAlternative(
        url: Url,
        entry: AltSvcEntry,
    ) {
        val origin = originOf(url)
        val entries = store.get(origin)
        if (entry in entries) store.put(origin, entries - entry)
    }

    fun onNetworkChanged(clearNonPersistent: Boolean) {
        if (clearNonPersistent) store.clearNonPersistent()
    }

    init {
        (store as? FileAltSvcStore)?.deferWrites = true
    }

    /**
     * The file write left by the last change of a [FileAltSvcStore] (null for other stores or when nothing changed).
     * Taken under the engine's lock and run after it, so a slow disk never stalls requests (threat-model 3.18).
     */
    fun takePendingWrite(): (() -> Unit)? = (store as? FileAltSvcStore)?.takePendingWrite()

    companion object {
        /** Alternatives kept per origin; the first ones of the header win (RFC 7838 section 3: listed by preference). */
        const val MAX_ENTRIES_PER_ORIGIN: Int = 8

        /** Origins kept by the built-in stores and broken marks; the least recently used go first. */
        const val MAX_ORIGINS: Int = 1000
    }
}

/** Moves [key] to the most recently used end of this insertion-ordered map and returns its value. */
internal fun <K, V : Any> LinkedHashMap<K, V>.touch(key: K): V? = remove(key)?.also { put(key, it) }

/** Drops the eldest entries until at most [max] remain. */
internal fun <K, V> MutableMap<K, V>.evictEldest(max: Int) {
    val it = entries.iterator()
    while (size > max && it.hasNext()) {
        it.next()
        it.remove()
    }
}
