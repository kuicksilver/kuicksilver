// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.message

import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3Request
import io.kuicksilver.quic.StreamPriority

/** A malformed request or response (RFC 9114 section 4.1.2): a stream error H3_MESSAGE_ERROR, never a connection error. */
internal class MalformedMessage(
    val reason: String,
) : Exception(reason)

/** Field name and value rules (RFC 9114 section 4.2, RFC 9110 section 5): critical because engines map HTTP/3 into the HTTP/1.1 model (threat-model 3.17). */
internal object FieldValidator {
    /** Hop-by-hop fields that HTTP/3 forbids (RFC 9114 section 4.2). */
    val CONNECTION_SPECIFIC: Set<String> = setOf("connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade")
    private const val TCHAR_SYMBOLS = "!#$%&'*+-.^_`|~"

    /** A token (RFC 9110 section 5.6.2), any case: an HTTP method (section 9.1). */
    fun isToken(t: String): Boolean = t.isNotEmpty() && t.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it in TCHAR_SYMBOLS }

    /** null when [n] is a valid lowercase token, else the reason. */
    fun checkName(n: String): String? {
        if (n.isEmpty()) return "empty field name"
        for (c in n) {
            if (c in 'A'..'Z') return "uppercase in field name"
            // also anything above U+00FF: fields are octets
            if (!(c in 'a'..'z' || c in '0'..'9' || c in TCHAR_SYMBOLS)) return "invalid character 0x${c.code.toString(16)} in field name"
        }
        return null
    }

    /**
     * null when [v] has no NUL, CR or LF, no leading or trailing whitespace and no character above U+00FF, else the reason.
     * Field values are octets (ISO-8859-1 on the wire): a wider char would be truncated to its low byte, and U+010A would
     * become a raw LF.
     */
    fun checkValue(v: String): String? {
        for (c in v) {
            if (c == '\u0000' || c == '\r' ||
                c == '\n'
            ) {
                return "NUL, CR or LF in field value"
            }
            if (c.code >
                0xFF
            ) {
                return "character U+${c.code.toString(16).uppercase()} outside ISO-8859-1 in field value"
            }
        }
        if (v.isNotEmpty() &&
            (v.first() == ' ' || v.first() == '\t' || v.last() == ' ' || v.last() == '\t')
        ) {
            return "leading or trailing whitespace in field value"
        }
        return null
    }

    private const val SUB_DELIMS = "!$&'()*+,;="

    private fun isHex(c: Char): Boolean = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'

    private fun isUnreservedOrSubDelim(c: Char): Boolean = c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c in "-._~" || c in SUB_DELIMS

    /** `*( unreserved / pct-encoded / sub-delims )`, plus ":" when [colon] (RFC 3986 reg-name and userinfo). */
    private fun isRegName(
        s: String,
        colon: Boolean,
    ): Boolean {
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '%' -> {
                    if (i + 2 >= s.length || !isHex(s[i + 1]) || !isHex(s[i + 2])) return false
                    i += 3
                    continue
                }

                isUnreservedOrSubDelim(c) || (colon && c == ':') -> {}

                else -> {
                    return false
                }
            }
            i++
        }
        return true
    }

    /**
     * What is inside the brackets of an IP-literal (RFC 3986 section 3.2.2): IPvFuture (`v` 1*HEXDIG "." 1*(unreserved /
     * sub-delims / ":")), or IPv6 written with hex digits, ":" and "." (its finer grammar is left to whoever parses it),
     * with an optional RFC 6874 zone `%25` 1*(unreserved / pct-encoded).
     */
    private fun isIpLiteralBody(s: String): Boolean {
        if (s.startsWith('v') || s.startsWith('V')) {
            val dot = s.indexOf('.')
            if (dot < 2 || !s.substring(1, dot).all(::isHex)) return false
            val rest = s.substring(dot + 1)
            return rest.isNotEmpty() && rest.all { isUnreservedOrSubDelim(it) || it == ':' }
        }
        val zone = s.indexOf('%')
        val address = if (zone < 0) s else s.substring(0, zone)
        if (':' !in address || !address.all { isHex(it) || it == ':' || it == '.' }) return false
        if (zone < 0) return true
        val id = s.substring(zone)
        return id.startsWith("%25") && id.length > 3 && isRegName(id.substring(3), colon = false) &&
            id.substring(3).none { it in SUB_DELIMS }
    }

    /**
     * null when [a] is an RFC 3986 authority, `[ userinfo "@" ] host [ ":" port ]` (section 3.2), else the reason. This is
     * the syntax `:authority` and `host` carry (RFC 9114 section 4.3.1, RFC 9110 section 7.2): a path, query, fragment,
     * whitespace or quote in them is malformed, and engines that map them to an HTTP/1.1 `Host` see only values HTTP/1.1
     * accepts. The port is at most five digits up to 65535; [userinfo] says whether the scheme allows userinfo, and
     * [hostRequired] whether the host may be empty (it may not for http and https, RFC 9110 section 4.2.1), and
     * [portRequired] whether a port from 1 to 65535 must follow it (the authority-form of CONNECT, RFC 9110 section 9.3.6).
     */
    fun checkAuthority(
        a: String,
        userinfo: Boolean,
        hostRequired: Boolean,
        portRequired: Boolean = false,
    ): String? {
        val at = a.lastIndexOf('@')
        if (at >= 0) {
            if (!userinfo) return "userinfo"
            if (!isRegName(a.substring(0, at), colon = true)) return "invalid userinfo"
        }
        val hostStart = at + 1
        val hostEnd: Int
        if (a.startsWith("[", hostStart)) {
            val close = a.indexOf(']', hostStart)
            if (close < 0 || !isIpLiteralBody(a.substring(hostStart + 1, close))) return "invalid IP literal"
            hostEnd = close + 1
        } else {
            hostEnd = a.indexOf(':', hostStart).let { if (it < 0) a.length else it }
            if (!isRegName(a.substring(hostStart, hostEnd), colon = false)) return "invalid host"
        }
        if (hostRequired && hostEnd == hostStart) return "empty host"
        if (hostEnd == a.length) return if (portRequired) "no port" else null
        if (a[hostEnd] != ':') return "invalid character after the host"
        val port = a.substring(hostEnd + 1)
        if (port.length > 5 || !port.all { it in '0'..'9' } || (port.isNotEmpty() && port.toInt() > 65_535)) return "invalid port"
        if (portRequired && (port.isEmpty() || port.toInt() == 0)) return "no port"
        return null
    }

    /**
     * `content-length` must be `1*DIGIT` and fit a Long (a larger value would read as "no length"); several values are allowed only when identical (RFC 9110 section 8.6, RFC 9114
     * section 4.1.2) and collapse to one field line for the application. Returns the fields with that collapse applied.
     */
    fun checkContentLength(fields: List<Pair<String, String>>): List<Pair<String, String>> {
        var seen: String? = null
        var repeated = false
        for ((n, v) in fields) {
            if (n != "content-length") continue
            if (v.isEmpty() || !v.all { it in '0'..'9' } || v.toLongOrNull() == null) throw MalformedMessage("invalid content-length '$v'")
            if (seen == null) {
                seen = v
            } else if (seen != v) {
                throw MalformedMessage("conflicting content-length values")
            } else {
                repeated = true
            }
        }
        if (!repeated) return fields
        var kept = false
        return fields.filter { (n, _) ->
            if (n != "content-length") {
                true
            } else if (kept) {
                false
            } else {
                kept = true
                true
            }
        }
    }

    /**
     * Validates one regular field of a message; throws [MalformedMessage]. `te` is a request field (RFC 9110 section
     * 10.1.4) and may only say `trailers` (RFC 9114 section 4.2); in a response or in trailers ([request] false) it is malformed.
     */
    fun checkRegular(
        name: String,
        value: String,
        request: Boolean,
    ) {
        checkName(name)?.let { throw MalformedMessage("$it: '$name'") }
        checkValue(value)?.let { throw MalformedMessage("$it in '$name'") }
        if (name in CONNECTION_SPECIFIC) throw MalformedMessage("connection-specific field '$name'")
        if (name == "te") {
            if (!request) throw MalformedMessage("te in a response")
            if (value != "trailers") throw MalformedMessage("te other than trailers")
        }
    }
}

/** Pseudo-header rules of RFC 9114 sections 4.3.1-4.3.2 and RFC 9220 section 3. */
internal object PseudoHeaders {
    class Request(
        val method: String,
        val scheme: String?,
        val authority: String?,
        val path: String?,
        val protocol: String?,
        val regular: Http3Headers,
    )

    private val REQUEST_PSEUDO = setOf(":method", ":scheme", ":authority", ":path", ":protocol")

    fun parseRequest(
        fields: List<Pair<String, String>>,
        connectProtocolEnabled: Boolean,
    ): Request {
        val pseudo = HashMap<String, String>()
        val regular = ArrayList<Pair<String, String>>()
        for ((n, v) in fields) {
            if (n.startsWith(':')) {
                if (regular.isNotEmpty()) throw MalformedMessage("pseudo-header $n after regular fields")
                if (n !in REQUEST_PSEUDO) throw MalformedMessage("pseudo-header $n not allowed in a request")
                if (n in pseudo) throw MalformedMessage("duplicate $n")
                FieldValidator.checkValue(v)?.let { throw MalformedMessage("$it in $n") }
                pseudo[n] = v
            } else {
                FieldValidator.checkRegular(n, v, request = true)
                regular += n to v
            }
        }
        val method = pseudo[":method"] ?: throw MalformedMessage(":method missing")
        if (method.isEmpty()) throw MalformedMessage("empty :method")
        if (!FieldValidator.isToken(method)) throw MalformedMessage(":method is not a token")
        val protocol = pseudo[":protocol"]
        val scheme = pseudo[":scheme"]
        val path = pseudo[":path"]
        // one host at most, equal to :authority when both are present (RFC 9114 section 4.3.1; quic-go rejects a second one)
        var host: String? = null
        for ((n, v) in regular) {
            if (n != "host") continue
            if (host != null) throw MalformedMessage("more than one host field")
            host = v
        }
        var authority = pseudo[":authority"]
        if (authority != null && host != null && authority != host) throw MalformedMessage(":authority and host differ")
        if (protocol != null) {
            if (!connectProtocolEnabled) throw MalformedMessage(":protocol without SETTINGS_ENABLE_CONNECT_PROTOCOL")
            if (method != "CONNECT") throw MalformedMessage(":protocol with $method")
            if (scheme.isNullOrEmpty() || path.isNullOrEmpty() ||
                authority.isNullOrEmpty()
            ) {
                throw MalformedMessage("Extended CONNECT needs :scheme, :path and :authority")
            }
        } else if (method == "CONNECT") {
            if (scheme != null || path != null) throw MalformedMessage("CONNECT with :scheme or :path")
            if (authority.isNullOrEmpty()) throw MalformedMessage("CONNECT without :authority")
            if ('@' in authority) throw MalformedMessage("userinfo in the CONNECT :authority")
        } else {
            if (scheme.isNullOrEmpty()) throw MalformedMessage(":scheme missing")
            if (path.isNullOrEmpty()) throw MalformedMessage(":path missing or empty")
            if (authority == null) authority = host
            if ((scheme == "https" || scheme == "http") &&
                authority.isNullOrEmpty()
            ) {
                throw MalformedMessage("no :authority or host for $scheme")
            }
        }
        if (method != "CONNECT" || protocol != null) {
            // path-absolute ["?" query], or "*" for OPTIONS (RFC 9114 section 4.3.1): never an absolute URI, a relative path or spaces
            val p = path!!
            if (!(p.startsWith('/') || (method == "OPTIONS" && p == "*"))) throw MalformedMessage(":path is not absolute")
            if (p.any { it == ' ' || it == '\t' }) throw MalformedMessage("whitespace in :path")
            if ((scheme == "http" || scheme == "https") && authority != null && '@' in authority) {
                throw MalformedMessage("userinfo in :authority") // deprecated for http and https URIs, RFC 9114 section 4.3.1
            }
        }
        // RFC 3986 syntax for both (RFC 9114 section 4.3.1); userinfo only where the scheme allows it (not http, https or
        // the authority-form of CONNECT, RFC 9110 section 9.3.6), a host for http, https and CONNECT, and a port for a
        // classic CONNECT (its authority-form is `uri-host ":" port`; Extended CONNECT carries a URI authority, RFC 9220)
        val classicConnect = method == "CONNECT" && protocol == null
        val userinfo = !classicConnect && scheme != "http" && scheme != "https"
        val hostRequired = classicConnect || scheme == "http" || scheme == "https"
        for ((what, v) in listOf(":authority" to pseudo[":authority"], "host" to host)) {
            if (v == null) continue
            FieldValidator
                .checkAuthority(
                    v,
                    userinfo,
                    hostRequired,
                    portRequired = classicConnect,
                )?.let { throw MalformedMessage("$it in $what") }
        }
        return Request(method, scheme, authority ?: host, path, protocol, Http3Headers(FieldValidator.checkContentLength(regular)))
    }

    fun parseResponse(fields: List<Pair<String, String>>): Pair<Int, Http3Headers> {
        var status: String? = null
        val regular = ArrayList<Pair<String, String>>()
        for ((n, v) in fields) {
            if (n.startsWith(':')) {
                if (regular.isNotEmpty()) throw MalformedMessage("pseudo-header $n after regular fields")
                if (n != ":status") throw MalformedMessage("pseudo-header $n not allowed in a response")
                if (status != null) throw MalformedMessage("duplicate :status")
                status = v
            } else {
                FieldValidator.checkRegular(n, v, request = false)
                regular += n to v
            }
        }
        val s = status ?: throw MalformedMessage(":status missing")
        if (s.length != 3 || !s.all { it in '0'..'9' }) throw MalformedMessage("invalid :status '$s'")
        val code = s.toInt()
        if (code !in 100..599) throw MalformedMessage(":status $code out of range")
        return code to Http3Headers(FieldValidator.checkContentLength(regular))
    }

    fun parseTrailers(fields: List<Pair<String, String>>): Http3Headers {
        for ((n, v) in fields) {
            if (n.startsWith(':')) throw MalformedMessage("pseudo-header $n in trailers")
            FieldValidator.checkRegular(n, v, request = false)
        }
        return Http3Headers(fields)
    }

    /**
     * Our own request [fields] (from [buildRequest]) must pass the checks the peer applies ([parseRequest]): the caller
     * gets IllegalArgumentException instead of a stream the peer resets with H3_MESSAGE_ERROR (RFC 9114 sections 4.2, 4.3.1).
     */
    fun requireValidRequest(fields: List<Pair<String, String>>) {
        try {
            parseRequest(fields, connectProtocolEnabled = true)
        } catch (e: MalformedMessage) {
            throw IllegalArgumentException("invalid request: ${e.reason}")
        }
    }

    /** Our own trailers: no pseudo-headers, no connection-specific fields, no `te` (RFC 9114 section 4.2); IllegalArgumentException otherwise. */
    fun requireValidTrailers(fields: List<Pair<String, String>>) {
        try {
            parseTrailers(fields)
        } catch (e: MalformedMessage) {
            throw IllegalArgumentException("invalid trailers: ${e.reason}")
        }
    }

    fun buildRequest(r: Http3Request): List<Pair<String, String>> {
        val out = ArrayList<Pair<String, String>>(4 + r.headers.size + 1)
        out += ":method" to r.method
        if (r.protocol != null) out += ":protocol" to r.protocol
        if (r.method != "CONNECT" || r.protocol != null) {
            out += ":scheme" to r.scheme
        }
        r.authority?.let { out += ":authority" to it }
        if (r.method != "CONNECT" || r.protocol != null) r.path?.let { out += ":path" to it }
        out += r.headers.fields
        r.priority?.let { p -> PriorityField.format(p)?.let { if (r.headers["priority"] == null) out += "priority" to it } }
        return out
    }

    fun buildResponse(
        status: Int,
        headers: Http3Headers,
    ): List<Pair<String, String>> = listOf(":status" to status.toString()) + headers.fields
}

/** The `Priority` field of RFC 9218 section 4 (a Structured Fields dictionary; only `u` and `i` matter). */
internal object PriorityField {
    fun parse(value: String?): StreamPriority {
        if (value.isNullOrBlank()) return StreamPriority.Default
        var u = 3
        var i = false
        for (member in value.split(',')) {
            val item = member.substringBefore(';').trim()
            if (item.isEmpty()) continue
            val key = item.substringBefore('=').trim()
            val v = if ('=' in item) item.substringAfter('=').trim() else null
            when (key) {
                "u" -> {
                    v?.toIntOrNull()?.let { if (it in 0..7) u = it }
                }

                "i" -> {
                    when (v) {
                        null, "?1" -> {
                            i = true
                        }

                        "?0" -> {
                            i = false
                        }

                        else -> {}
                    }
                }
            }
        }
        return StreamPriority(u, i)
    }

    /** null for the default (u=3, i=false): nothing to send. */
    fun format(p: StreamPriority): String? {
        val parts =
            buildList {
                if (p.urgency != 3) add("u=${p.urgency}")
                if (p.incremental) add("i")
            }
        return if (parts.isEmpty()) null else parts.joinToString(", ")
    }
}
