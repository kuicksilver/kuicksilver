// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.http.Url
import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/**
 * One alternative service of an origin (RFC 7838 section 3): `protocol="host:port"`, valid until [expiresAtEpochMillis][AltSvcEntry.expiresAtEpochMillis].
 *
 * @property protocol the ALPN protocol id of the alternative; the engine stores and uses only `h3`.
 * @property host the alternative's host; null when the header left it empty, meaning the origin's own host.
 * @property port the alternative's UDP port, 1..65535.
 * @property expiresAtEpochMillis the end of freshness in epoch milliseconds: the time the response was generated plus `ma`
 *   (86400 s by default), where the generation time is the receipt time minus the response's age (RFC 7838 section 3.1).
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
    /** Equal when the protocol, host, port and persist flag are. */
    override fun equals(other: Any?): Boolean =
        other is AltSvcEntry && protocol == other.protocol && host == other.host && port == other.port && persist == other.persist

    /** Consistent with [equals]. */
    override fun hashCode(): Int = ((protocol.hashCode() * 31 + host.hashCode()) * 31 + port) * 31 + persist.hashCode()

    /** For logs. */
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

    /**
     * Forgets every entry of every origin, persistent ones included: the engine's
     * [clearAlternativeServices][io.ktor.client.HttpClient.clearAlternativeServices] without an origin, so alternative
     * service information goes when origin-specific data is cleared (RFC 7838 section 9.4: it "MUST be removed when
     * origin-specific data is cleared"). A store kept across restarts removes them there too.
     */
    @ExperimentalKuicksilverApi
    public fun clear()

    /**
     * The network ([Http3ClientConfig.networkId]) the stored entries were learned on, as the engine last set it; null when
     * not known. A store kept across restarts keeps it with the entries: at its first request the engine compares it with
     * the current network and, when they differ, drops the entries without `persist=1` (RFC 7838 section 2.2: "clients
     * SHOULD remove from cache all alternative services that lack the "persist" flag with the value "1" when they detect
     * such a change"). The default keeps nothing and answers null, which never matches a network the engine knows: an
     * application's store that does not implement it loses its non-persistent entries at each start where the engine knows
     * the network. Used only while the engine knows the network (`networkId` set, or a `connectionMigration` that follows one).
     */
    @ExperimentalKuicksilverApi
    public var networkId: String?
        get() = null
        set(value) {
            // not kept
        }
}

/**
 * The default [AltSvcStore]: in memory, thread-safe enough for one engine (all calls happen under the engine's lock).
 * It keeps at most 1000 origins; the least recently used go first (threat-model 3.18).
 */
public class InMemoryAltSvcStore : AltSvcStore {
    private val map = LinkedHashMap<String, List<AltSvcEntry>>()

    @ExperimentalKuicksilverApi
    override var networkId: String? = null

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

    @ExperimentalKuicksilverApi
    override fun clear() {
        map.clear()
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

    /**
     * The `ma` of a delta-seconds value too large to represent: 2^31. RFC 7838 section 3.1 takes delta-seconds from the
     * HTTP caching specification (now RFC 9111 section 1.2.2), whose rule is addressed to a cache: "If a cache receives a
     * delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations
     * overflows, the cache MUST consider the value to be 2147483648 (2^31) or the greatest positive integer it can
     * conveniently represent." The Alt-Svc cache follows it.
     */
    private const val MA_OVERFLOW_SECONDS = 2_147_483_648L

    /**
     * Whether [h] is an RFC 3986 section 3.2.2 `host`: an IP-literal (`[` IPv6address `]`; IPvFuture and zone IDs are
     * not taken), or a reg-name / IPv4address (unreserved, pct-encoded and sub-delims characters; possibly empty).
     */
    internal fun isUriHost(h: String): Boolean {
        if (h.startsWith('[')) {
            if (!h.endsWith(']') || h.length < 4) return false
            val inner = h.substring(1, h.length - 1)
            return ':' in inner && inner.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }
        }
        var i = 0
        while (i < h.length) {
            val c = h[i]
            when {
                c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c in "-._~" || c in "!$&'()*+,;=" -> {
                    i++
                }

                c == '%' && i + 2 < h.length && h[i + 1].isHexDigit() && h[i + 2].isHexDigit() -> {
                    i += 3
                }

                else -> {
                    return false
                }
            }
        }
        return true
    }

    /**
     * Whether a uri-host can be a connection target: a bracketed IPv6 address, or a name or IPv4 address of letters, digits,
     * `-` and `.` (or empty: the origin's host). A reg-name with sub-delims or pct-encoding is a valid URI host that no DNS
     * name or address has; such an alternative cannot be used, and its text (`x),fallback=...`) never reaches the log.
     */
    internal fun isConnectionTarget(h: String): Boolean =
        h.startsWith('[') || h.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' || it == '.' }

    /**
     * Whether [h] is a host an alternative may name, as the parser takes it ([isUriHost] and [isConnectionTarget]): a DNS
     * name or IPv4 address of letters, digits, `-` and `.`, or an IPv6 address — in brackets when [bracketed] (an origin's
     * host), without them otherwise (an entry's [AltSvcEntry.host]). Never empty.
     */
    internal fun isAltHost(
        h: String,
        bracketed: Boolean,
    ): Boolean {
        if (h.isEmpty()) return false
        if (':' in h || h.startsWith('[')) return isUriHost(if (bracketed) h else "[$h]") && (!bracketed || h.startsWith('['))
        return isUriHost(h) && isConnectionTarget(h)
    }

    private fun Char.isHexDigit(): Boolean = this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

    /**
     * The `h3` entries of [value] (other protocols are ignored, malformed entries skipped), fresh for `ma` seconds from
     * [generatedAtMillis]; null when the value contains `clear`. RFC 7838 section 3: "A field value containing the special
     * value "clear" indicates that the origin requests all alternatives for that origin to be invalidated (including those
     * specified in the same response, in case of an invalid reply containing both "clear" and alternative services)": any
     * list element that is exactly `clear` (case-sensitive) clears, whatever else the value lists.
     */
    fun parse(
        value: String,
        generatedAtMillis: Long,
    ): List<AltSvcEntry>? {
        val elements = splitTopLevel(value, ',')
        if (elements.any { it.trim(' ', '\t') == "clear" }) return null
        val out = ArrayList<AltSvcEntry>()
        for (alt in elements) {
            val parts = splitTopLevel(alt, ';').map { it.trim() }
            val head = parts.firstOrNull() ?: continue
            val eq = head.indexOf('=')
            if (eq <= 0) continue
            val protocol = head.substring(0, eq).trim()
            val authority = unquote(head.substring(eq + 1).trim()) ?: continue
            val colon = authority.lastIndexOf(':')
            if (colon < 0) continue
            val port = portOf(authority.substring(colon + 1)) ?: continue
            // RFC 7838 section 3: alt-authority is uri-host ":" port, uri-host being RFC 3986's host; anything else (a
            // space, a control character, a bare IPv6 address) makes the alternative malformed. The host reaches
            // connection targets and the engine's diagnostics log line, so it is checked here, not trusted
            val rawHost = authority.substring(0, colon)
            if (!isUriHost(rawHost) || !isConnectionTarget(rawHost)) continue
            val host =
                rawHost
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
                    // delta-seconds is 1*DIGIT; one too large for a Long is 2147483648 (RFC 9111 section 1.2.2's rule for a
                    // cache, which RFC 7838 section 3.1 refers to), and the expiry below caps what would overflow its milliseconds
                    "ma" -> {
                        ma =
                            when {
                                v.isEmpty() || v.any { it !in '0'..'9' } -> {
                                    bad = true
                                    0L
                                }

                                else -> {
                                    v.toLongOrNull() ?: MA_OVERFLOW_SECONDS
                                }
                            }
                    }

                    "persist" -> {
                        persist = v == "1"
                    }
                }
            }
            if (bad || protocol != "h3") continue
            out += AltSvcEntry(protocol, host, port, generatedAtMillis + minOf(ma, Long.MAX_VALUE / 2000) * 1000, persist)
        }
        return out
    }

    /**
     * An alt-authority port (RFC 7838 section 3: RFC 3986's `port = *DIGIT`) that can be connected to, 1..65535, or null.
     * Only digits: `toIntOrNull` alone would take a sign (`+443`).
     */
    internal fun portOf(s: String): Int? =
        s.takeIf { it.isNotEmpty() && it.length <= 5 && it.all { c -> c in '0'..'9' } }?.toInt()?.takeIf { it in 1..65_535 }

    /**
     * The response's age in seconds from its `Age` field lines (RFC 9111 section 5.1, which RFC 7838 section 3.1 points to
     * for "determining the response age"): "a cache encountering a message with a list-based Age field value SHOULD use the
     * first member of the field value, discarding subsequent ones", and "If the field value ... is invalid (e.g., it
     * contains something other than a non-negative integer), a cache SHOULD ignore the field" (0 then, as `age_value` is
     * "0, if not available", section 4.2.3). A value too large to represent is 2147483648 (section 1.2.2).
     */
    fun ageSeconds(values: List<String>): Long {
        val first = values.firstOrNull()?.substringBefore(',')?.trim(' ', '\t') ?: return 0
        if (first.isEmpty() || first.any { it !in '0'..'9' }) return 0
        return first.toLongOrNull()?.coerceAtMost(MA_OVERFLOW_SECONDS) ?: MA_OVERFLOW_SECONDS
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
@OptIn(ExperimentalKuicksilverApi::class)
internal class AltSvcCache(
    private val store: AltSvcStore,
    private val clock: () -> Long,
) {
    fun originOf(url: Url): String = originKeyOf(url)

    /**
     * Learns the `Alt-Svc` field lines [values] of a response to [url]. Freshness counts from the response's generation
     * (RFC 7838 section 3.1): the receipt time minus `corrected_age_value = age_value + response_delay` (RFC 9111 section
     * 4.2.3, which "MAY be used as the corrected_initial_age"), [ageValues] being its `Age` field lines and
     * [responseDelayMillis] the time from sending the request to receiving the response.
     */
    fun onResponse(
        url: Url,
        status: Int,
        values: List<String>,
        verifiedTls: Boolean,
        ageValues: List<String> = emptyList(),
        responseDelayMillis: Long = 0,
    ) {
        if (!verifiedTls) return // threat-model 3.18: never learn an alternative from an unauthenticated response
        val origin = originOf(url)
        if (status == 421 || values.isEmpty()) return
        val generatedAt = clock() - AltSvcParser.ageSeconds(ageValues) * 1000 - responseDelayMillis.coerceAtLeast(0)
        val entries = ArrayList<AltSvcEntry>()
        // the field lines are one list (RFC 9110 section 5.3): a `clear` in any of them clears
        for (v in values) {
            val parsed =
                AltSvcParser.parse(v, generatedAt) ?: run {
                    store.remove(origin)
                    return
                }
            entries += parsed
        }
        val usable = entries.filter { admissible(url, it) }.take(MAX_ENTRIES_PER_ORIGIN)
        if (usable.isEmpty()) store.remove(origin) else store.put(origin, usable)
    }

    /**
     * The `h3` alternative of the origin of [url] to use, or null: the first fresh one (in the server's order of
     * preference, RFC 7838 section 3) that [usable] accepts, else the first fresh one. The engine passes "not marked
     * broken": RFC 7838 section 2.4 says a client "SHOULD use that alternative service for all requests to the associated
     * origin as soon as it is available, provided the alternative service information is fresh", and after a failure "MAY
     * fall back to using the origin or another alternative service"; when every fresh alternative is broken, the first one
     * comes back and its broken mark sends the request to TCP.
     */
    fun h3For(
        url: Url,
        usable: (AltSvcEntry) -> Boolean = { true },
    ): AltSvcEntry? {
        val now = clock()
        // a store kept elsewhere (a file, the application's own) is checked as the header was: what the parser and
        // [admissible] refuse is never used, whoever wrote it
        val fresh =
            store.get(originOf(url)).filter {
                it.protocol == "h3" &&
                    it.expiresAtEpochMillis > now &&
                    AltSvcParser.portOf(it.port.toString()) != null &&
                    (it.host == null || AltSvcParser.isAltHost(it.host, bracketed = false)) &&
                    admissible(url, it)
            }
        return fresh.firstOrNull(usable) ?: fresh.firstOrNull()
    }

    /**
     * Whether [entry] may serve the origin of [url]: an unprivileged alternative port is refused for a privileged origin
     * port (as Chromium does), and no alternative is on the client's own networks unless the origin is there (RFC 9000
     * section 21.5, [AltSvcDestination]).
     */
    private fun admissible(
        url: Url,
        entry: AltSvcEntry,
    ): Boolean = !(url.port < 1024 && entry.port >= 1024) && AltSvcDestination.allowed(url.host, entry.host)

    /**
     * An ALTSVC frame (RFC 7838 section 4) for the origin of [url] on an HTTP/2 connection over verified TLS: "Receiving an
     * ALTSVC frame is semantically equivalent to receiving an Alt-Svc header field", so [value] replaces the origin's
     * alternatives or clears them as a header does; freshness counts from receipt (a frame has no age).
     */
    fun onAltSvcFrame(
        url: Url,
        value: String,
    ) = onResponse(url, 200, listOf(value), verifiedTls = true)

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

    /** The network the store's entries were learned on ([AltSvcStore.networkId]). */
    var network: String?
        get() = store.networkId
        set(value) {
            if (store.networkId != value) store.networkId = value
        }

    /** Forgets the alternatives of [origin] (an [originOf] key), or of every origin when null (RFC 7838 section 9.4). */
    fun clear(origin: String?) {
        if (origin == null) store.clear() else store.remove(origin)
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

/**
 * Forgets what this client learned about the alternative services of [origin] (any URL of it: `https://host:port`), or of
 * every origin when [origin] is null: the cached `Alt-Svc` alternatives in [Http3ClientConfig.altSvcStore] (persistent ones
 * too, and from the store file of a [FileAltSvcStore] before this returns), the alternatives marked broken, and the RTTs
 * kept for the HTTP/3 head start; without an origin also the networks where QUIC was seen working. RFC 7838 section 9.4:
 * "In a user agent, any alternative service information MUST be removed when origin-specific data is cleared (typically,
 * when cookies [RFC6265] are cleared)": call it wherever the application clears cookies or other site data. Open HTTP/3
 * connections are not closed (`closeHttp3Connections()` does that); the next `Alt-Svc` the origin sends is learned again.
 * Does nothing when the client's engine is not Kuicksilver.
 */
@ExperimentalKuicksilverApi
public suspend fun HttpClient.clearAlternativeServices(origin: Url? = null) {
    (engine as? KuicksilverEngine)?.clearAlternativeServices(origin)
}

/**
 * Whether [origin], the Origin field of an ALTSVC frame on stream 0 (the ASCII serialization of an origin, RFC 6454 section
 * 6.2: scheme, `://`, host, and `:port` unless it is the scheme's default), names the origin of [url]: RFC 7838 section 4,
 * "An association with an origin that the client does not consider authoritative for the current connection MUST be
 * ignored". The client's HTTP/2 connections serve one origin each (no coalescing), so only that one is authoritative.
 * Scheme and host compare case-insensitively; an explicit default port is taken too.
 */
internal fun isAltSvcFrameOrigin(
    origin: String,
    url: Url,
): Boolean {
    val base = "${url.protocol.name}://${url.host}".lowercase()
    val o = origin.lowercase()
    return o == "$base:${url.port}" || (url.port == url.protocol.defaultPort && o == base)
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

/**
 * The origin of [url] as the client's per-origin state keys it (Alt-Svc, broken marks, RTTs): `scheme://host:port` with a
 * WebSocket scheme read as its HTTP one. A `wss` WebSocket goes to the `https` origin (RFC 8441 section 5, which RFC 9220
 * applies to HTTP/3: ":scheme MUST be https for wss-schemed WebSockets"), and an alternative serves all requests to its
 * origin (RFC 7838 section 2.4), so `wss://` and `https://` to one host and port share it.
 */
internal fun originKeyOf(url: Url): String {
    val scheme =
        when (url.protocol.name) {
            "wss" -> "https"
            "ws" -> "http"
            else -> url.protocol.name
        }
    return "$scheme://${url.host}:${url.port}"
}
