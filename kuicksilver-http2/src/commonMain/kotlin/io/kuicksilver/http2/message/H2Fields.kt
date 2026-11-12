// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.message

/**
 * A malformed request or response (RFC 9113 section 8.1.1): a stream error PROTOCOL_ERROR, never a connection error. The
 * receiver MUST NOT process it further.
 */
internal class MalformedMessage(
    val reason: String,
) : Exception(reason)

/**
 * The field rules of RFC 9113 section 8.2 and RFC 9110 section 5: ported from `kuicksilver-http3`'s `FieldValidator`
 * (`io.kuicksilver.http3.message`, RFC 9114 section 4.2, which has the same rules) under ADR-0017's "copies, not a shared
 * module"; `tools/vectors/http-fields.json` holds the cases both copies must agree on (`HttpFieldVectorsTest` in each
 * module). Critical because the engines map HTTP/2 into the HTTP/1.1 model (threat model 3.17, 3.23).
 */
internal object H2Fields {
    /** Connection-specific fields that HTTP/2 forbids (RFC 9113 section 8.2.2): a message with one is malformed. */
    val CONNECTION_SPECIFIC: Set<String> = setOf("connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade")
    private const val TCHAR_SYMBOLS = "!#$%&'*+-.^_`|~"

    /** RFC 3986 section 3.1: `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`. */
    fun isScheme(s: String): Boolean =
        s.isNotEmpty() && s[0].isAsciiLetter() && s.all { it.isAsciiLetter() || it in '0'..'9' || it == '+' || it == '-' || it == '.' }

    private fun Char.isAsciiLetter() = this in 'a'..'z' || this in 'A'..'Z'

    /** A token (RFC 9110 section 5.6.2), any case: an HTTP method (section 9.1). */
    fun isToken(t: String): Boolean = t.isNotEmpty() && t.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it in TCHAR_SYMBOLS }

    /**
     * null when [n] is a valid lowercase token, else the reason. RFC 9113 section 8.2.1: no character 0x00-0x20, 0x41-0x5A
     * (uppercase) or 0x7F-0xFF; section 8.2: field names MUST be lowercase; and RFC 9110 section 5.1 makes a name a token.
     */
    fun checkName(n: String): String? {
        if (n.isEmpty()) return "empty field name"
        for (c in n) {
            if (c in 'A'..'Z') return "uppercase in field name"
            if (!(c in 'a'..'z' || c in '0'..'9' || c in TCHAR_SYMBOLS)) return "invalid character 0x${c.code.toString(16)} in field name"
        }
        return null
    }

    /**
     * null when [v] is a valid field value, else the reason. RFC 9113 section 8.2.1 forbids NUL, LF and CR and leading or
     * trailing whitespace (SP, HTAB) and lets a recipient treat any other value outside RFC 9110 section 5.5's grammar as
     * malformed: as the HTTP/3 copy, every control character but HTAB, DEL and anything above U+00FF (field values are
     * octets; a wider char would be truncated to its low byte on the wire).
     */
    fun checkValue(v: String): String? {
        for (c in v) {
            if ((c < ' ' && c != '\t') || c == '\u007F') return "control character 0x${c.code.toString(16).padStart(2, '0')} in field value"
            if (c.code > 0xFF) return "character U+${c.code.toString(16).uppercase()} outside ISO-8859-1 in field value"
        }
        if (v.isNotEmpty() && (v.first() == ' ' || v.first() == '\t' || v.last() == ' ' || v.last() == '\t')) {
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

    /** What is inside the brackets of an IP-literal (RFC 3986 section 3.2.2, RFC 6874 zones): see the HTTP/3 copy. */
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
     * null when [a] is an RFC 3986 authority, `[ userinfo "@" ] host [ ":" port ]`, else the reason: the syntax `:authority`
     * and `host` carry (RFC 9113 section 8.3.1, RFC 9110 section 7.2). [userinfo]: the scheme allows userinfo;
     * [hostRequired]: the host may not be empty (http, https, CONNECT); [portRequired]: the authority-form of CONNECT.
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
     * `content-length` must be `1*DIGIT` and fit a Long; several values only when identical (RFC 9110 section 8.6), which
     * collapse to one field line. Returns the fields with that collapse applied and the length (-1 without one).
     */
    fun checkContentLength(fields: List<Pair<String, String>>): Pair<List<Pair<String, String>>, Long> {
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
        val length = seen?.toLong() ?: -1L
        if (!repeated) return fields to length
        var kept = false
        return fields.filter { (n, _) ->
            when {
                n != "content-length" -> {
                    true
                }

                kept -> {
                    false
                }

                else -> {
                    kept = true
                    true
                }
            }
        } to length
    }

    /**
     * One regular field; throws [MalformedMessage]. `te` may only say `trailers` and only in a request (RFC 9113 section
     * 8.2.2; it is a request field, RFC 9110 section 10.1.4).
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
            // RFC 5234 section 2.3: ABNF strings are case-insensitive; edge whitespace was refused by checkValue
            if (!value.equals("trailers", ignoreCase = true)) throw MalformedMessage("te other than trailers")
        }
    }
}

/** A request's control data (RFC 9113 section 8.3.1) and its regular fields. */
internal class H2Request(
    val method: String,
    val scheme: String?,
    val authority: String?,
    val path: String?,
    /** `:protocol` of an Extended CONNECT (RFC 8441 section 4). */
    val protocol: String?,
    val fields: List<Pair<String, String>>,
    /** The `content-length`, -1 without one. */
    val contentLength: Long,
)

/** A response's status (RFC 9113 section 8.3.2) and its regular fields. */
internal class H2Response(
    val status: Int,
    val fields: List<Pair<String, String>>,
    /** The `content-length`, -1 without one. */
    val contentLength: Long,
)

/** Pseudo-header rules of RFC 9113 sections 8.3.1-8.3.2, 8.5 (CONNECT) and RFC 8441 section 4 (Extended CONNECT). */
internal object H2Messages {
    private val REQUEST_PSEUDO = setOf(":method", ":scheme", ":authority", ":path", ":protocol")

    /** A request field section (a server's view); [connectProtocolEnabled]: we sent SETTINGS_ENABLE_CONNECT_PROTOCOL = 1. */
    fun parseRequest(
        fields: List<Pair<String, String>>,
        connectProtocolEnabled: Boolean,
    ): H2Request {
        val pseudo = HashMap<String, String>()
        val regular = ArrayList<Pair<String, String>>()
        for ((n, v) in fields) {
            if (n.startsWith(':')) {
                // section 8.3: pseudo-header fields precede regular ones; unknown or repeated ones are malformed
                if (regular.isNotEmpty()) throw MalformedMessage("pseudo-header $n after regular fields")
                if (n !in REQUEST_PSEUDO) throw MalformedMessage("pseudo-header $n not allowed in a request")
                if (n in pseudo) throw MalformedMessage("duplicate $n")
                H2Fields.checkValue(v)?.let { throw MalformedMessage("$it in $n") }
                pseudo[n] = v
            } else {
                H2Fields.checkRegular(n, v, request = true)
                regular += n to v
            }
        }
        val method = pseudo[":method"] ?: throw MalformedMessage(":method missing")
        if (!H2Fields.isToken(method)) throw MalformedMessage(":method is not a token")
        val protocol = pseudo[":protocol"]
        val scheme = pseudo[":scheme"]
        // section 8.3.1: the scheme portion of the target URI, so RFC 3986 section 3.1's syntax
        if (!scheme.isNullOrEmpty() && !H2Fields.isScheme(scheme)) throw MalformedMessage(":scheme is not a URI scheme")
        val path = pseudo[":path"]
        var host: String? = null
        for ((n, v) in regular) {
            if (n != "host") continue
            if (host != null) throw MalformedMessage("more than one host field")
            host = v
        }
        var authority = pseudo[":authority"]
        // section 8.3.1: a host field that identifies another entity than :authority makes the request malformed; RFC 9110
        // section 4.2.3: the host compares case-insensitively and a missing port is the scheme's default
        if (authority != null && host != null && !sameEntity(authority, host, scheme)) throw MalformedMessage(":authority and host differ")
        if (protocol != null) {
            // RFC 8441 section 4: only with the setting, only on CONNECT, and with :scheme and :path
            if (!connectProtocolEnabled) throw MalformedMessage(":protocol without SETTINGS_ENABLE_CONNECT_PROTOCOL")
            if (method != "CONNECT") throw MalformedMessage(":protocol with $method")
            // "a value from the 'Hypertext Transfer Protocol (HTTP) Upgrade Token Registry'": a token (RFC 9110 section 16.7)
            if (!H2Fields.isToken(protocol)) throw MalformedMessage(":protocol is not a token")
            if (scheme.isNullOrEmpty() || path.isNullOrEmpty() || authority.isNullOrEmpty()) {
                throw MalformedMessage("Extended CONNECT needs :scheme, :path and :authority")
            }
        } else if (method == "CONNECT") {
            // section 8.5: :scheme and :path omitted, :authority the host and port to connect to
            if (scheme != null || path != null) throw MalformedMessage("CONNECT with :scheme or :path")
            if (authority.isNullOrEmpty()) throw MalformedMessage("CONNECT without :authority")
        } else {
            if (scheme.isNullOrEmpty()) throw MalformedMessage(":scheme missing")
            // section 8.3.1: :path must not be empty for http or https URIs
            if (path.isNullOrEmpty()) throw MalformedMessage(":path missing or empty")
            if (authority == null) authority = host
            if ((scheme == "https" || scheme == "http") &&
                authority.isNullOrEmpty()
            ) {
                throw MalformedMessage("no :authority or host for $scheme")
            }
        }
        if (method != "CONNECT" || protocol != null) {
            val p = path!!
            if (!(p.startsWith('/') || (method == "OPTIONS" && p == "*"))) throw MalformedMessage(":path is not absolute")
            if (p.any { it == ' ' || it == '\t' }) throw MalformedMessage("whitespace in :path")
            // section 8.3.1: :authority MUST NOT include the deprecated userinfo subcomponent for http or https URIs
            if ((scheme == "http" || scheme == "https") && authority != null &&
                '@' in authority
            ) {
                throw MalformedMessage("userinfo in :authority")
            }
        }
        val classicConnect = method == "CONNECT" && protocol == null
        val userinfo = !classicConnect && scheme != "http" && scheme != "https"
        val hostRequired = classicConnect || scheme == "http" || scheme == "https"
        for ((what, v) in listOf(":authority" to pseudo[":authority"], "host" to host)) {
            if (v == null) continue
            H2Fields
                .checkAuthority(
                    v,
                    userinfo,
                    hostRequired,
                    portRequired = classicConnect,
                )?.let { throw MalformedMessage("$it in $what") }
        }
        val (checked, length) = H2Fields.checkContentLength(regular)
        return H2Request(method, scheme, authority ?: host, path, protocol, checked, length)
    }

    /** Whether two authorities name the same host and port (RFC 9110 section 4.2.3), the default port of [scheme] filled in. */
    private fun sameEntity(
        a: String,
        b: String,
        scheme: String?,
    ): Boolean {
        val default =
            when (scheme) {
                "https" -> "443"
                "http" -> "80"
                else -> null
            }

        fun norm(x: String): String {
            val v = x.lowercase()
            val hostEnd = if (v.startsWith("[")) v.indexOf(']') + 1 else v.indexOf(':').let { if (it < 0) v.length else it }
            if (hostEnd <= 0) return v
            val port = v.substring(hostEnd).removePrefix(":")
            return v.substring(0, hostEnd) + ":" + port.ifEmpty { default ?: "" }
        }
        return a == b || norm(a) == norm(b)
    }

    /** A response field section (a client's view): `:status` only (section 8.3.2), three digits 100..599. */
    fun parseResponse(fields: List<Pair<String, String>>): H2Response {
        var status: String? = null
        val regular = ArrayList<Pair<String, String>>()
        for ((n, v) in fields) {
            if (n.startsWith(':')) {
                if (regular.isNotEmpty()) throw MalformedMessage("pseudo-header $n after regular fields")
                if (n != ":status") throw MalformedMessage("pseudo-header $n not allowed in a response")
                if (status != null) throw MalformedMessage("duplicate :status")
                status = v
            } else {
                H2Fields.checkRegular(n, v, request = false)
                regular += n to v
            }
        }
        val s = status ?: throw MalformedMessage(":status missing")
        if (s.length != 3 || !s.all { it in '0'..'9' }) throw MalformedMessage("invalid :status '$s'")
        val code = s.toInt()
        if (code !in 100..599) throw MalformedMessage(":status $code out of range")
        val (checked, length) = H2Fields.checkContentLength(regular)
        return H2Response(code, checked, length)
    }

    /** A trailer section: no pseudo-header fields (section 8.1), regular fields under the same rules. */
    fun parseTrailers(fields: List<Pair<String, String>>): List<Pair<String, String>> {
        for ((n, v) in fields) {
            if (n.startsWith(':')) throw MalformedMessage("pseudo-header $n in trailers")
            H2Fields.checkRegular(n, v, request = false)
        }
        return fields
    }

    /**
     * Our own request [fields] must pass the checks the peer applies ([parseRequest]): the caller gets
     * IllegalArgumentException instead of a stream the peer resets with PROTOCOL_ERROR. [connectProtocolEnabled]: the peer
     * sent SETTINGS_ENABLE_CONNECT_PROTOCOL = 1, without which `:protocol` MUST NOT be used (RFC 8441 section 4).
     */
    fun requireValidRequest(
        fields: List<Pair<String, String>>,
        connectProtocolEnabled: Boolean = false,
    ) {
        try {
            parseRequest(fields, connectProtocolEnabled)
        } catch (e: MalformedMessage) {
            throw IllegalArgumentException("invalid request: ${e.reason}")
        }
    }

    /**
     * A request's field section (section 8.3.1): `:method`, `:scheme`, `:authority` (clients use it instead of `host`), then
     * `:path` and the regular [fields], which must already be lowercase and free of connection-specific fields.
     */
    fun buildRequest(
        method: String,
        scheme: String,
        authority: String,
        path: String,
        fields: List<Pair<String, String>>,
    ): List<Pair<String, String>> {
        val out = ArrayList<Pair<String, String>>(4 + fields.size)
        out += ":method" to method
        out += ":scheme" to scheme
        out += ":authority" to authority
        out += ":path" to path
        out += fields
        return out
    }
}
