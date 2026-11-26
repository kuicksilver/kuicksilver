// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.kq

import io.ktor.http.Url
import io.ktor.http.URLProtocol
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/** Which protocols kq may use, after curl's flags of the same names. */
enum class Mode(
    val flag: String?,
) {
    /** HTTP/2 or HTTP/1.1 first, HTTP/3 once the origin announced it with `Alt-Svc` (`Http3Discovery.Auto`). */
    Auto(null),

    /** HTTP/3 by prior knowledge, raced against TCP and falling back to it (`Http3Discovery.Preferred`). */
    Http3("--http3"),

    /** HTTP/3 only, no fallback (`Http3Discovery.H3Only`). */
    Http3Only("--http3-only"),

    /** TCP only: HTTP/2 when the server offers `h2` in ALPN, else HTTP/1.1 (`null`). */
    Http2("--http2"),

    /** TCP only, HTTP/1.1 only (`H1Only` with `http2 { enabled = false }`). */
    Http11("--http1.1"),
}

/** One run of kq, as the command line asked for it. */
data class Options(
    val method: String,
    val url: Url,
    val mode: Mode = Mode.Auto,
    val verbose: Boolean = false,
    val includeHeaders: Boolean = false,
    val headers: List<Pair<String, String>> = emptyList(),
    val output: String? = null,
    val qlogDir: String? = null,
    val caCert: String? = null,
    val altSvcFile: String? = null,
    val repeat: Int = 1,
    val zeroRtt: Boolean = false,
    val connectTimeout: Duration? = null,
)

/** What the command line asks for: a run, the help text, or a usage error (exit 2). */
sealed class Parsed {
    data class Run(
        val options: Options,
    ) : Parsed()

    data object Help : Parsed()

    data object Version : Parsed()

    data class Error(
        val message: String,
    ) : Parsed()
}

const val USAGE: String = """usage: kq [options] <get|head> [options] [--] <url>

  --http3          HTTP/3 first (prior knowledge), raced against TCP, falling back to it
  --http3-only     HTTP/3 only, no fallback
  --http2          TCP only: HTTP/2 when the server offers it, else HTTP/1.1
  --http1.1        TCP only, HTTP/1.1
                   (none of these: HTTP/2 or HTTP/1.1 first, HTTP/3 once the server announces it with Alt-Svc)
  -v, --verbose    print to stderr how each request went: protocol, ALPN, the QUIC version offered, handshake
                   time, RTT, 0-RTT, the HTTP/3 alternative and where it came from, the Alt-Svc received,
                   fallback reasons, qlog records lost
  -i, --include    print the status line and the response headers before the body
  -H <name: value> add a request header (repeatable). The name must be an RFC 9110 token, the value must hold no
                   control character but HTAB nor any character above U+00FF; an empty value sends the field
                   empty (curl would remove it instead).
                   Ktor refuses Transfer-Encoding and Upgrade (the engine frames the message itself)
  -o <file>        write the body to <file> instead of stdout ('-': stdout); the file is truncated first, and a failed request
                   leaves what arrived before the failure in it
  --repeat <n>     send the request n times on one client (1..100)
  --0rtt           allow 0-RTT (early data) for GET and HEAD over HTTP/3 (https only; not with --http2 or
                   --http1.1); with --repeat each repeat opens a new HTTP/3 connection, which resumes the session
                   and sends the request in 0-RTT if the server agrees
  --qlog <dir>     write a qlog trace of each QUIC connection into <dir>
  --cacert <file>  trust the CA certificates of this PEM file instead of the system's
  --alt-svc <file> keep the Alt-Svc cache in <file> across runs (as curl --alt-svc)
  --connect-timeout <seconds>
  -h, --help       this text
  --version        what kq is
  --               the next argument is the URL, even if it starts with '-'

An option's value is the next argument and, except for -H and a lone '-' (stdout), never starts with '-'. Exit codes: 0 done (any status),
1 a request, a write to stdout or to -o failed, 2 a usage error (also an unreadable --cacert)."""

/** RFC 9110 section 5.6.2: tchar. */
private fun Char.isTchar(): Boolean = this in 'a'..'z' || this in 'A'..'Z' || this in '0'..'9' || this in "!#$%&'*+-.^_`|~"

/**
 * Checks one `-H name: value`: the name a token (RFC 9110 section 5.6.2), the value a field-value without surrounding
 * whitespace (section 5.5): no control character but HTAB (no CR, LF or NUL). Returns the pair or the problem.
 */
fun parseHeader(h: String): Pair<Pair<String, String>?, String?> {
    val colon = h.indexOf(':')
    if (colon < 0) return null to "header '$h' is not 'name: value'"
    val name = h.substring(0, colon).trim(' ', '\t')
    if (name.isEmpty()) return null to "header '$h' has an empty name"
    if (!name.all { it.isTchar() }) return null to "header name '$name' is not a token (RFC 9110 section 5.6.2)"
    val value = h.substring(colon + 1).trim(' ', '\t')
    if (value.any { (it < ' ' && it != '\t') || it == '\u007f' }) {
        return null to "header '$name' has a control character in its value (RFC 9110 section 5.5)"
    }
    // field values are octets (VCHAR, obs-text, SP, HTAB): a character above U+00FF has no single octet to go as
    if (value.any { it > '\u00ff' }) {
        return null to "header '$name' has a character above U+00FF in its value (RFC 9110 section 5.5: octets only)"
    }
    return (name to value) to null
}

/** Parses kq's command line (without the program name): options may come before and after the command. */
fun parseArgs(args: List<String>): Parsed {
    var command: String? = null
    var mode = Mode.Auto
    var verbose = false
    var include = false
    val headers = mutableListOf<Pair<String, String>>()
    var output: String? = null
    var qlog: String? = null
    var caCert: String? = null
    var altSvc: String? = null
    var repeat = 1
    var zeroRtt = false
    var connectTimeout: Duration? = null
    var url: String? = null
    var help = false
    var version = false
    var i = 0

    fun positional(a: String): String? {
        val first = url
        when {
            command == null -> command = a
            first == null -> url = a
            else -> return "more than one URL ('${redact(first)}', '${redact(a)}')"
        }
        return null
    }
    while (i < args.size) {
        val a = args[i++]

        fun value(): String? = args.getOrNull(i)?.takeUnless { it.startsWith("-") && it != "-" }?.also { i++ }
        when (a) {
            "-h", "--help" -> help = true

            "--version" -> version = true

            "--" -> {
                for (rest in args.drop(i)) positional(rest)?.let { return Parsed.Error(it) }
                i = args.size
            }

            "--http3", "--http3-only", "--http2", "--http1.1" -> {
                val m = Mode.entries.first { it.flag == a }
                if (mode != Mode.Auto && mode != m) return Parsed.Error("$a and ${mode.flag} exclude each other")
                mode = m
            }

            "-v", "--verbose" -> verbose = true

            "-i", "--include" -> include = true

            "-H", "--header" -> {
                val h = args.getOrNull(i++) ?: return Parsed.Error("$a needs a value")
                val (pair, problem) = parseHeader(h)
                headers += pair ?: return Parsed.Error(problem!!)
            }

            "-o", "--output" -> output = value() ?: return Parsed.Error("$a needs a file")

            "--qlog" -> qlog = value() ?: return Parsed.Error("--qlog needs a directory")

            "--cacert" -> caCert = value() ?: return Parsed.Error("--cacert needs a file")

            "--alt-svc" -> altSvc = value() ?: return Parsed.Error("--alt-svc needs a file")

            "--repeat" -> {
                val n = value()?.toIntOrNull() ?: return Parsed.Error("--repeat needs a number")
                if (n !in 1..100) return Parsed.Error("--repeat must be 1..100")
                repeat = n
            }

            "--0rtt" -> zeroRtt = true

            "--connect-timeout" -> {
                val s = value()?.toDoubleOrNull() ?: return Parsed.Error("--connect-timeout needs seconds")
                if (!(s > 0 && s <= 3600)) return Parsed.Error("--connect-timeout must be in (0, 3600] seconds")
                connectTimeout = (s * 1000).toLong().coerceAtLeast(1).milliseconds
            }

            else -> {
                if (a.startsWith("-") && a.length > 1) return Parsed.Error("unknown option '$a'")
                positional(a)?.let { return Parsed.Error(it) }
            }
        }
    }
    if (help) return Parsed.Help
    if (version) return Parsed.Version
    val method =
        when (command) {
            null -> return Parsed.Error("no command")
            "get" -> "GET"
            "head" -> "HEAD"
            else -> return Parsed.Error("unknown command '$command' (get or head)")
        }
    val u = url ?: return Parsed.Error("no URL")
    val parsed =
        runCatching { Url(u) }.getOrNull()?.takeIf { it.protocol == URLProtocol.HTTPS || it.protocol == URLProtocol.HTTP }
            ?: return Parsed.Error("'${redact(u)}' is not an http:// or https:// URL")
    if (parsed.host.isEmpty() || "://" !in u) return Parsed.Error("'${redact(u)}' is not an http:// or https:// URL")
    if (parsed.protocol == URLProtocol.HTTP && (mode == Mode.Http3 || mode == Mode.Http3Only)) {
        return Parsed.Error("${mode.flag} needs an https:// URL (HTTP/3 is always encrypted)")
    }
    if (zeroRtt && (mode == Mode.Http2 || mode == Mode.Http11)) return Parsed.Error("--0rtt is HTTP/3 only, not with ${mode.flag}")
    if (zeroRtt && parsed.protocol == URLProtocol.HTTP) return Parsed.Error("--0rtt needs an https:// URL (it is HTTP/3 only)")
    return Parsed.Run(
        Options(method, parsed, mode, verbose, include, headers, output, qlog, caCert, altSvc, repeat, zeroRtt, connectTimeout),
    )
}

private val USERINFO = Regex("([A-Za-z][A-Za-z0-9+.-]*://)[^/?#@\\s]*@")

/**
 * [text] with the userinfo (`user:password@`) of every URL in it removed: a URL on its own, or one inside a message (Ktor's
 * exceptions name the request's URL with its userinfo). Every line kq prints goes through it.
 */
fun redact(text: String): String = USERINFO.replace(text, "$1")
