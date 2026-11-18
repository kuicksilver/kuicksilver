// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.message

/** What a request's path and query say against a server's template (RFC 9298 section 3.1). */
internal sealed class TemplateMatch {
    /** The path has another shape than the template: the request is for another resource. */
    object NoMatch : TemplateMatch() {
        override fun toString(): String = "NoMatch"
    }

    /** The path fits the template, but a variable's value breaks RFC 9298 section 3 (empty, out of range, not encoded). */
    class Invalid(
        val reason: String,
    ) : TemplateMatch() {
        override fun toString(): String = "Invalid($reason)"
    }

    class Target(
        val host: UdpHost,
        val port: Int,
    ) : TemplateMatch() {
        override fun toString(): String = "Target(${host.text}, $port)"
    }
}

/** The pieces of an expanded template for an HTTP request: `:scheme`, `:authority` and `:path` (RFC 9298 section 3.4). */
internal class ExpandedTarget(
    val scheme: String,
    val authority: String,
    val pathAndQuery: String,
)

/**
 * The URI Template of a UDP proxy (RFC 9298 section 2), a subset of RFC 6570: levels 1 to 3, and of their operators only
 * simple string expansion and form-style query expansion and continuation (`{?...}`, `{&...}`), since section 2 forbids
 * `+`, `#`, `.`, `/` and `;`. Both of its variables are expanded with RFC 6570's unreserved set, so an IPv6 literal's colons
 * come out percent-encoded as section 3 requires.
 *
 * A client parses the absolute template it was configured with ([parseAbsolute]) and expands it. A server parses its path
 * and query template ([parsePath]) and matches requests against it, which needs a template a path can be read back from
 * without guessing: each variable once, a simple expression with one variable, and after an expression either the end, a
 * `{&...}` expression or a literal whose first character no expanded value can contain.
 */
internal class UdpUriTemplate private constructor(
    /** The template as configured. */
    val text: String,
    /** The scheme of an absolute template; null for a server's path template. */
    val scheme: String?,
    /** The authority of an absolute template; null for a server's path template. */
    val authority: String?,
    /** The path and query part, from its leading `/`. */
    private val parts: List<Part>,
) {
    private sealed class Part {
        class Literal(
            val text: String,
        ) : Part()

        /** [op] is null (simple string expansion), `?` or `&` (RFC 6570 sections 3.2.2, 3.2.8, 3.2.9). */
        class Expression(
            val op: Char?,
            val vars: List<String>,
        ) : Part()
    }

    /**
     * Expands the template for [host] (an IPv4 or IPv6 literal, an IPv6 one with or without brackets, or a DNS name) and
     * [port] (1..65535). Throws [IllegalArgumentException] for an invalid target (section 3) or a path template.
     */
    fun expand(
        host: String,
        port: Int,
    ): ExpandedTarget {
        require(scheme != null && authority != null) { "a server's path template cannot be expanded for a request" }
        require(port in 1..MAX_PORT) { "target_port must be 1..65535 (RFC 9298 section 3), was $port" }
        val bare = if (host.length >= 2 && host.first() == '[' && host.last() == ']') host.substring(1, host.length - 1) else host
        require('%' !in bare) { "target_host: IPv6 zone identifiers are not supported (RFC 9298 section 3)" }
        val h = UdpHost.parse(bare) ?: throw IllegalArgumentException("target_host must be an IP address or a DNS host name, was '$host'")
        val values = mapOf(TARGET_HOST to h.text, TARGET_PORT to port.toString())
        val out = StringBuilder()
        for (p in parts) {
            when (p) {
                is Part.Literal -> out.append(p.text)
                is Part.Expression -> expandExpression(p, values, out)
            }
        }
        return ExpandedTarget(scheme, authority, out.toString())
    }

    private fun expandExpression(
        e: Part.Expression,
        values: Map<String, String>,
        out: StringBuilder,
    ) {
        var first = true
        for (v in e.vars) {
            val value = values[v] ?: continue // RFC 6570 section 3.2.1: undefined variables are skipped
            when (e.op) {
                null -> if (!first) out.append(',')
                '?' -> out.append(if (first) '?' else '&').append(v).append('=')
                else -> out.append('&').append(v).append('=')
            }
            encodeUnreserved(value, out)
            first = false
        }
    }

    /** Reads the target out of a request's `:path` (path and query); see [TemplateMatch]. Bounded work: one pass over the path. */
    fun match(pathAndQuery: String): TemplateMatch {
        val raw = HashMap<String, String>()
        var pos = 0
        for ((i, p) in parts.withIndex()) {
            when (p) {
                is Part.Literal -> {
                    if (!pathAndQuery.startsWith(p.text, pos)) return TemplateMatch.NoMatch
                    pos += p.text.length
                }

                is Part.Expression -> {
                    val stop = stopChar(i)
                    pos =
                        if (p.op == null) {
                            val end = valueEnd(pathAndQuery, pos, stop)
                            raw[p.vars.single()] = pathAndQuery.substring(pos, end)
                            end
                        } else {
                            matchQuery(p, pathAndQuery, pos, stop, raw) ?: return TemplateMatch.NoMatch
                        }
                }
            }
        }
        if (pos != pathAndQuery.length) return TemplateMatch.NoMatch
        return target(raw)
    }

    /** The first character of the literal after part [i], or null when an expression or the end follows. */
    private fun stopChar(i: Int): Char? = (parts.getOrNull(i + 1) as? Part.Literal)?.text?.first()

    /** Where a value starting at [from] ends: at [stop], at a query or form separator, or at the end. */
    private fun valueEnd(
        s: String,
        from: Int,
        stop: Char?,
    ): Int {
        var j = from
        while (j < s.length) {
            val c = s[j]
            if (c == stop || c == '/' || c == '?' || c == '&' || c == '#') break
            j++
        }
        return j
    }

    /**
     * A form-style query expression at [from]: its variables in order, each at most once, as `name=value` pairs; a pair
     * whose name is not the expression's ends it (a literal or a `{&...}` that follows takes over). Null when the shape is
     * not the template's.
     */
    private fun matchQuery(
        e: Part.Expression,
        s: String,
        from: Int,
        stop: Char?,
        raw: MutableMap<String, String>,
    ): Int? {
        var pos = from
        var next = 0 // the expression's variables come in their order
        var first = true
        while (pos < s.length) {
            val sep = if (first && e.op == '?') '?' else '&'
            if (s[pos] != sep) break
            val eq = s.indexOf('=', pos + 1)
            if (eq < 0) break
            val name = s.substring(pos + 1, eq)
            val at = e.vars.subList(next, e.vars.size).indexOf(name)
            if (at < 0) break
            next += at + 1
            val end = valueEnd(s, eq + 1, stop)
            raw[name] = s.substring(eq + 1, end)
            pos = end
            first = false
        }
        if (first && e.op == '?' && e.vars.any { it == TARGET_HOST || it == TARGET_PORT }) return null
        return pos
    }

    private fun target(raw: Map<String, String>): TemplateMatch {
        val host = raw[TARGET_HOST] ?: return TemplateMatch.Invalid("target_host is missing")
        val port = raw[TARGET_PORT] ?: return TemplateMatch.Invalid("target_port is missing")
        for ((name, v) in raw) {
            if (!isEncodedValue(v)) return TemplateMatch.Invalid("$name is not percent-encoded as RFC 6570 expands it")
        }
        if (host.isEmpty()) return TemplateMatch.Invalid("target_host is empty")
        if (port.isEmpty()) return TemplateMatch.Invalid("target_port is empty")
        // section 3: target_port "MUST represent an integer between 1 and 65535 inclusive"
        if (port.length > MAX_PORT_DIGITS || port.any { it !in '0'..'9' }) return TemplateMatch.Invalid("target_port is not a port number")
        val portValue = port.toInt()
        if (portValue !in 1..MAX_PORT) return TemplateMatch.Invalid("target_port $portValue is outside 1..65535")
        val decoded = percentDecodeAscii(host) ?: return TemplateMatch.Invalid("target_host is not an ASCII host")
        val h = UdpHost.parse(decoded) ?: return TemplateMatch.Invalid("target_host is not an IP address or a DNS host name")
        return TemplateMatch.Target(h, portValue)
    }

    companion object {
        const val TARGET_HOST = "target_host"
        const val TARGET_PORT = "target_port"

        /** The path of the default template (RFC 9298 section 2), for clients configured with a proxy's host and port only. */
        const val WELL_KNOWN_PATH = "/.well-known/masque/udp/{target_host}/{target_port}/"

        private const val MAX_PORT = 65535
        private const val MAX_PORT_DIGITS = 5

        /** Longest template accepted: a configuration value, bounded so a parse is cheap whatever it is given. */
        const val MAX_TEMPLATE = 8192

        /** `https://[authority]/.well-known/masque/udp/{target_host}/{target_port}/`, the default template of section 2. */
        fun wellKnown(authority: String): UdpUriTemplate = parseAbsolute("https://$authority$WELL_KNOWN_PATH")

        /**
         * A client's template, checked against every requirement of RFC 9298 section 2 ("the client MUST reject its
         * configuration"): level 3 or lower; absolute with a non-empty scheme, authority and path; a path that starts with
         * `/`; variables only in the path and query; both `target_host` and `target_port`; ASCII 0x21-0x7E only; none of the
         * `+`, `#`, `.`, `/` and `;` operators. Also refused: a userinfo in the authority (HTTP/3 must not send one, RFC 9114
         * section 4.3.1) and a fragment, which no request carries. Throws [IllegalArgumentException] naming the broken rule.
         */
        fun parseAbsolute(text: String): UdpUriTemplate {
            checkCharacters(text)
            val schemeEnd = text.indexOf("://")
            require(schemeEnd > 0) { "the URI Template must be absolute, with a scheme and an authority (RFC 9298 section 2)" }
            val scheme = text.substring(0, schemeEnd)
            require(scheme[0].isAsciiLetter() && scheme.all { it.isAsciiLetter() || it in '0'..'9' || it in "+-." }) {
                "the URI Template's scheme is not a scheme (RFC 3986 section 3.1)"
            }
            val authStart = schemeEnd + 3
            var authEnd = authStart
            while (authEnd < text.length && text[authEnd] != '/') {
                val c = text[authEnd]
                require(c != '{') { "template variables must be in the path or query (RFC 9298 section 2)" }
                require(c != '?' && c != '#') { "the URI Template must have a non-empty path that starts with '/' (RFC 9298 section 2)" }
                authEnd++
            }
            val authority = text.substring(authStart, authEnd)
            require(authority.isNotEmpty()) { "the URI Template must have a non-empty authority (RFC 9298 section 2)" }
            require('@' !in authority) { "the URI Template's authority must not carry userinfo (RFC 9114 section 4.3.1)" }
            require(authEnd < text.length) { "the URI Template must have a non-empty path that starts with '/' (RFC 9298 section 2)" }
            val parts = tokenize(text.substring(authEnd))
            requireTargets(parts, exactlyOnce = false)
            return UdpUriTemplate(text, scheme, authority, parts)
        }

        /**
         * A server's path and query template (`/...`), with the rules of [parseAbsolute] that apply to a path, plus the
         * ones that let [match] read a request back without guessing (see [UdpUriTemplate]).
         */
        fun parsePath(text: String): UdpUriTemplate {
            checkCharacters(text)
            require(text.startsWith('/')) { "the path template must start with '/' (RFC 9298 section 2)" }
            val parts = tokenize(text)
            requireTargets(parts, exactlyOnce = true)
            for ((i, p) in parts.withIndex()) {
                if (p !is Part.Expression) continue
                require(p.op != null || p.vars.size == 1) {
                    "a server's simple expression must have one variable, or a request cannot be read back: {${p.vars.joinToString(",")}}"
                }
                when (val next = parts.getOrNull(i + 1)) {
                    null -> {}

                    is Part.Expression -> {
                        require(p.op != null && next.op == '&') {
                            "two expressions in a row cannot be read back from a request, except a query one and a {&...}"
                        }
                    }

                    is Part.Literal -> {
                        val c = next.text.first()
                        require(!isUnreserved(c) && c != '%' && c != '=') {
                            "the literal after an expression must start with a character no value can contain, not '$c'"
                        }
                    }
                }
            }
            return UdpUriTemplate(text, null, null, parts)
        }

        private fun checkCharacters(text: String) {
            require(text.isNotEmpty()) { "the URI Template is empty" }
            require(text.length <= MAX_TEMPLATE) { "the URI Template is longer than $MAX_TEMPLATE characters" }
            for (c in text) {
                require(c.code in 0x21..0x7e) {
                    "the URI Template must only contain ASCII characters in the range 0x21-0x7E (RFC 9298 section 2)"
                }
            }
        }

        private fun requireTargets(
            parts: List<Part>,
            exactlyOnce: Boolean,
        ) {
            for (v in listOf(TARGET_HOST, TARGET_PORT)) {
                val n = parts.sumOf { p -> if (p is Part.Expression) p.vars.count { it == v } else 0 }
                require(n >= 1) { "the URI Template must contain the variable $v (RFC 9298 section 2)" }
                require(!exactlyOnce || n == 1) { "a server's template must name $v once" }
            }
        }

        /** RFC 6570 section 2: literals and expressions; levels above 3 and the operators RFC 9298 forbids are refused. */
        private fun tokenize(t: String): List<Part> {
            val parts = ArrayList<Part>()
            val lit = StringBuilder()
            var i = 0
            while (i < t.length) {
                val c = t[i]
                when {
                    c == '{' -> {
                        val end = t.indexOf('}', i + 1)
                        require(end > 0) { "an expression is not closed with '}'" }
                        if (lit.isNotEmpty()) parts += Part.Literal(lit.toString())
                        lit.clear()
                        parts += expression(t.substring(i + 1, end))
                        i = end + 1
                    }

                    c == '}' -> {
                        throw IllegalArgumentException("'}' without an expression")
                    }

                    c == '%' -> {
                        require(i + 2 < t.length && hexValue(t[i + 1]) >= 0 && hexValue(t[i + 2]) >= 0) {
                            "'%' in a literal must start a percent-encoded octet (RFC 6570 section 2.1)"
                        }
                        lit.append(t, i, i + 3)
                        i += 3
                    }

                    else -> {
                        require(c !in "\"'<>\\^`|") { "'$c' is not allowed in a URI Template literal (RFC 6570 section 2.1)" }
                        require(c != '#') { "a URI Template for a request has no fragment" }
                        lit.append(c)
                        i++
                    }
                }
            }
            if (lit.isNotEmpty()) parts += Part.Literal(lit.toString())
            return parts
        }

        private fun expression(body: String): Part.Expression {
            require(body.isNotEmpty()) { "an empty expression '{}'" }
            val op =
                when (val c = body[0]) {
                    '+', '#', '.', '/', ';' -> {
                        throw IllegalArgumentException("the '$c' operator is not allowed in a UDP proxy template (RFC 9298 section 2)")
                    }

                    '=', ',', '!', '@', '|' -> {
                        throw IllegalArgumentException("'$c' is a reserved operator (RFC 6570 section 2.2)")
                    }

                    '?', '&' -> {
                        c
                    }

                    else -> {
                        null
                    }
                }
            val list = if (op == null) body else body.substring(1)
            val vars = list.split(',')
            for (v in vars) {
                require(v.isNotEmpty()) { "an empty variable name in {$body}" }
                require(!v.endsWith('*') && ':' !in v) {
                    "'$v': value modifiers are level 4; the template must be level 3 or lower (RFC 9298 section 2)"
                }
                require(isVarName(v)) { "'$v' is not a variable name (RFC 6570 section 2.3)" }
            }
            return Part.Expression(op, vars)
        }

        /** RFC 6570 section 2.3: varchar *( ["."] varchar ), varchar = ALPHA / DIGIT / "_" / pct-encoded. */
        private fun isVarName(v: String): Boolean {
            var i = 0
            var afterDot = true
            while (i < v.length) {
                val c = v[i]
                when {
                    c == '.' -> {
                        if (afterDot) return false
                        afterDot = true
                        i++
                        continue
                    }

                    c == '%' -> {
                        if (i + 2 >= v.length || hexValue(v[i + 1]) < 0 || hexValue(v[i + 2]) < 0) return false
                        i += 3
                    }

                    c.isAsciiLetter() || c in '0'..'9' || c == '_' -> {
                        i++
                    }

                    else -> {
                        return false
                    }
                }
                afterDot = false
            }
            return !afterDot
        }

        private fun Char.isAsciiLetter(): Boolean = this in 'a'..'z' || this in 'A'..'Z'

        /** RFC 3986 section 2.3. */
        fun isUnreserved(c: Char): Boolean = c.isAsciiLetter() || c in '0'..'9' || c == '-' || c == '.' || c == '_' || c == '~'

        /** RFC 6570 section 3.2.1 with the unreserved set: every UTF-8 octet outside it as `%XX`. */
        private fun encodeUnreserved(
            value: String,
            out: StringBuilder,
        ) {
            for (b in value.encodeToByteArray()) {
                val c = (b.toInt() and 0xff).toChar()
                if (c.code < 0x80 && isUnreserved(c)) {
                    out.append(c)
                } else {
                    out.append('%').append(HEX[(b.toInt() shr 4) and 0xf]).append(HEX[b.toInt() and 0xf])
                }
            }
        }

        private const val HEX = "0123456789ABCDEF"

        /** Only unreserved characters and percent-encoded octets: what the expansion of a value can produce. */
        private fun isEncodedValue(v: String): Boolean {
            var i = 0
            while (i < v.length) {
                val c = v[i]
                if (c == '%') {
                    if (i + 2 >= v.length || hexValue(v[i + 1]) < 0 || hexValue(v[i + 2]) < 0) return false
                    i += 3
                } else {
                    if (!isUnreserved(c)) return false
                    i++
                }
            }
            return true
        }

        /** Decodes `%XX` (already checked); null when an octet is outside printable ASCII 0x21-0x7E. */
        private fun percentDecodeAscii(v: String): String? {
            val out = StringBuilder(v.length)
            var i = 0
            while (i < v.length) {
                val c = v[i]
                val code =
                    if (c == '%') {
                        (hexValue(v[i + 1]) shl 4 or hexValue(v[i + 2])).also { i += 3 }
                    } else {
                        c.code.also { i++ }
                    }
                if (code !in 0x21..0x7e) return null
                out.append(code.toChar())
            }
            return out.toString()
        }
    }
}
