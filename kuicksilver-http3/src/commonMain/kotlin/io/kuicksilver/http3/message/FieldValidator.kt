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
        val protocol = pseudo[":protocol"]
        val scheme = pseudo[":scheme"]
        val path = pseudo[":path"]
        val host = regular.firstOrNull { it.first == "host" }?.second
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
