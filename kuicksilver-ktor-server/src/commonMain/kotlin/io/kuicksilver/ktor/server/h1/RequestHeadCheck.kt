// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h1

import io.ktor.http.HttpProtocolVersion
import io.ktor.utils.io.InternalAPI
import kotlinx.io.InternalIoApi
import kotlinx.io.indexOf
import kotlinx.io.readByteArray

/**
 * A field value as the client sent it, for the [occurrence]-th field line (from 0) named [name] (lower case): one that
 * Ktor's parser would hand on changed.
 */
internal class KeptFieldValue(
    val name: String,
    val occurrence: Int,
    val value: String,
)

/**
 * The longest request line (without its line end) the server parses: Ktor's `parseRequest` limit for one line
 * (`HTTP_LINE_LIMIT`, 8 KiB).
 */
internal const val MAX_REQUEST_LINE_BYTES: Int = 8_192

/**
 * A request head the server refuses before Ktor's parser sees it: [status] with [reason], then the connection closes; a
 * 301 carries the [location] to send.
 */
internal class RequestHeadRefused(
    val status: Int,
    val reason: String,
    message: String,
    val location: String? = null,
) : Exception(message)

/**
 * Checks the request head at the start of [this] input (empty lines before it already skipped) before Ktor's parser reads
 * it, and throws [RequestHeadRefused] for one the server refuses. A request line longer than [MAX_REQUEST_LINE_BYTES]
 * is a request-target longer than the server parses: 414 (RFC 9112 section 3: the server MUST respond with 414), or a
 * method longer than any the server implements (501), see [refuseLongLine]. The request line itself is checked by
 * [checkRequestLine] as soon as it is there, the field lines by [checkFieldSection] once the whole head is. A 301 the
 * target earned goes out only after that, and only when the head's Host and framing fields are valid too (their
 * refusal wins, see [RequestFraming.of]). Returns without a verdict when the input ends or the head limit is reached
 * before the head's end: the parser then reports that as it did (a head that earned a 301 and ended early gets 400).
 */
@OptIn(InternalAPI::class, InternalIoApi::class)
internal suspend fun HeadLimitedInput.checkRequestHead() {
    val buffer = readBuffer.buffer
    var scanned = 0L
    var lineStart = 0L
    var fieldsStart = -1L
    // the Location of a 301 the request line earned, sent once the field section is checked too
    var redirect: String? = null
    var http10 = false
    val headScan = HeadMethodScan()
    while (true) {
        if (fieldsStart < 0 && !headScan.decided) {
            headScan.update(buffer)
            headMethod = headScan.head
        }
        val limit = if (fieldsStart < 0) minOf(buffer.size, MAX_REQUEST_LINE_BYTES + 2L) else buffer.size
        val lf = if (scanned < limit) buffer.indexOf(LF_BYTE, scanned, limit) else -1L
        if (lf < 0) {
            if (fieldsStart < 0 && buffer.size >= MAX_REQUEST_LINE_BYTES + 2L) refuseLongLine(buffer)
            scanned = limit
            if (!awaitContent((buffer.size + 1).toInt())) {
                // the head ended or outgrew its limit before its end: the parser reports that, but never gets a target
                // the redirect was for
                if (redirect != null && !exceeded) refuse("The request head ended before its empty line")
                return
            }
            continue
        }
        val end = if (lf > lineStart && buffer[lf - 1] == CR_BYTE) lf - 1 else lf
        if (fieldsStart < 0) {
            if (end > MAX_REQUEST_LINE_BYTES) refuseLongLine(buffer)
            val line = buffer.peek().readByteArray(end.toInt())
            val checkedLine = checkRequestLine(line)
            val minor = checkedLine.minor
            redirect = checkedLine.redirect
            http10 = line[minor] == '0'.code.toByte()
            if (redirect == null && line[minor] > '1'.code.toByte()) replaceBufferedByte(minor.toLong(), '1'.code.toByte())
            fieldsStart = lf + 1
        } else if (end == lineStart) {
            val fields = buffer.peek()
            fields.skip(fieldsStart)
            val checked = checkFieldSection(fields.readByteArray((lineStart - fieldsStart).toInt()))
            redirect?.let { location ->
                // RFC 9112 section 3.2 (Host) and section 6.3 (framing) come first: the redirect is for a head that is
                // valid but for its target's characters
                val framing =
                    RequestFraming.of(
                        if (http10) HttpProtocolVersion.HTTP_1_0 else HttpProtocolVersion.HTTP_1_1,
                        target = "/",
                        hosts = checked.values("host"),
                        te = checked.values("transfer-encoding"),
                        cl = checked.values("content-length"),
                    )
                framing.fault?.let { fault ->
                    if (framing.faultStatus == 501) throw RequestHeadRefused(501, "Not Implemented", fault)
                    refuse(fault)
                }
                throw RequestHeadRefused(301, "Moved Permanently", "An origin-form request-target with invalid characters", location)
            }
            for (colon in checked.emptyPortColons) replaceBufferedByte(fieldsStart + colon, SP_BYTE)
            keptFieldValues = checked.keptValues
            return
        }
        lineStart = lf + 1
        scanned = lf + 1
    }
}

/** What [checkFieldSection] found besides refusals. */
internal class FieldSectionCheck(
    /** Offsets of the colons that end a Host value (an empty port), which the caller turns into SP. */
    val emptyPortColons: List<Int>,
    /** Values that start with obs-text Ktor's parser takes for whitespace, as sent. */
    val keptValues: List<KeptFieldValue>,
    /** The values of the Host, Transfer-Encoding and Content-Length lines, as sent (without OWS), by lower-case name. */
    private val framingValues: Map<String, List<String>>,
) {
    /** The values of the field [name] (lower case, one of the framing fields), in order. */
    fun values(name: String): List<String> = framingValues[name].orEmpty()
}

/**
 * Checks the field lines of a request head ([fields]: each line with its line end, without the empty line that ends the
 * section); 400 for:
 * - a field name that is not a token (RFC 9110 section 5.1; DEL and bytes above 0x7F, which Ktor's parser passed), also
 *   an empty one, whitespace before the colon (RFC 9112 section 5.1), a line without a colon and an obs-fold line
 *   (section 5.2), which the parser refuses too;
 * - a control character other than HTAB in a value. RFC 9110 section 5.5: a recipient of CR, LF or NUL within a field
 *   value MUST either reject the message or replace each of them with SP; field-content is VCHAR, obs-text, SP and
 *   HTAB, so the others (DEL among them) are invalid too, as Go's net/http holds. Ktor's parser refuses only CR and LF.
 *
 * And it finds what Ktor's parser would get wrong in a valid head:
 * - a value that starts with obs-text decoding to a Unicode space (U+00A0, ...): OWS is only SP and HTAB (RFC 9110
 *   section 5.6.3), obs-text is field content a recipient SHOULD treat as opaque data (section 5.5), but the parser
 *   skips any Unicode whitespace before a value. Such values are returned as sent, for [requestFields]; a framing field
 *   with one is then invalid, as it is;
 * - a Host value that ends with a colon: `port = *DIGIT` (RFC 3986 section 3.2.3) makes the empty port valid (the
 *   default port), but the parser refuses it, so the caller turns that colon into SP, trailing OWS the parser drops: the
 *   same authority.
 */
internal fun checkFieldSection(fields: ByteArray): FieldSectionCheck {
    val emptyPortColons = ArrayList<Int>(0)
    val kept = ArrayList<KeptFieldValue>(0)
    val occurrences = HashMap<String, Int>()
    val framingValues = HashMap<String, MutableList<String>>()
    var start = 0
    while (start < fields.size) {
        var lf = start
        while (lf < fields.size && fields[lf] != LF_BYTE) lf++
        val end = if (lf > start && fields[lf - 1] == CR_BYTE) lf - 1 else lf
        var colon = start
        while (colon < end && isTcharByte(fields[colon])) colon++
        if (colon == start || colon == end || fields[colon] != ':'.code.toByte()) refuse("The field name is not a token")
        val name = fields.decodeToString(start, colon).lowercase()
        val occurrence = occurrences[name] ?: 0
        occurrences[name] = occurrence + 1
        var value = colon + 1
        while (value < end && (fields[value] == SP_BYTE || fields[value] == HTAB_BYTE)) value++
        for (i in value until end) {
            val c = fields[i].toInt() and 0xFF
            if ((c < 0x20 && c != 0x09) || c == 0x7F) refuse("A control character in a field value")
        }
        var last = end - 1
        while (last >= value && (fields[last] == SP_BYTE || fields[last] == HTAB_BYTE)) last--
        if (value < end && unicodeSpaceLength(fields, value) > 0) {
            kept += KeptFieldValue(name, occurrence, fields.decodeToString(value, last + 1))
        }
        if (name == "host" && last >= value && fields[last] == ':'.code.toByte()) emptyPortColons += last
        if (name == "host" || name == "transfer-encoding" || name == "content-length") {
            framingValues.getOrPut(name) { ArrayList(1) } += fields.decodeToString(value, last + 1)
        }
        start = lf + 1
    }
    return FieldSectionCheck(emptyPortColons, kept, framingValues)
}

/** What [checkRequestLine] found: the index of the minor version digit, and the Location of a 301 the target earned. */
internal class RequestLineCheck(
    val minor: Int,
    val redirect: String?,
)

/**
 * Checks a request line (without its line end) against `method SP request-target SP HTTP-version` (RFC 9112 section 3)
 * and returns the index of the minor version digit with the 301 the target earned (see [checkRequestTarget]; the
 * caller sends it only for an otherwise valid head), or throws [RequestHeadRefused]. Ktor's parser is lenient where this
 * is not: it takes any run of non-whitespace as the method (section 3.1: method = token), any Unicode whitespace (U+00A0
 * among them) as a separator, and passes control characters in the target. Here:
 * - the separators are the whitespace section 3 lets a recipient take as SP (SP, HTAB, VT, FF, a bare CR), also before
 *   the method and after the version; any other control character (NUL, DEL, ...) or a Unicode space anywhere: 400;
 * - the method is a token (RFC 9110 section 5.6.2), else 400;
 * - the version is `"HTTP/" DIGIT "." DIGIT`, case-sensitive (section 2.3), else 400; a major version other than 1 gets
 *   505 (RFC 9110 section 15.6.6); a higher minor version is processed as HTTP/1.1, the highest minor version the
 *   server conforms to (RFC 9110 section 6.2: a recipient SHOULD), so the caller rewrites the digit before Ktor's parser,
 *   which knows only 1.0 and 1.1, sees it. Go's net/http does the same (505 for a major other than 1).
 */
internal fun checkRequestLine(line: ByteArray): RequestLineCheck {
    for (i in line.indices) {
        val b = line[i]
        val c = b.toInt() and 0xFF
        if ((c < 0x20 && !isRequestLineWhitespace(b)) || c == 0x7F) refuse("A control character in the request line")
        if (c >= 0x80 && unicodeSpaceLength(line, i) > 0) refuse("A Unicode space in the request line")
    }
    var i = 0
    val n = line.size

    fun skipWhitespace() {
        while (i < n && isRequestLineWhitespace(line[i])) i++
    }

    skipWhitespace()
    val methodStart = i
    while (i < n && isTcharByte(line[i])) i++
    val methodEnd = i
    if (i == methodStart || i == n || !isRequestLineWhitespace(line[i])) refuse("The method is not a token")
    skipWhitespace()
    val targetStart = i
    while (i < n && !isRequestLineWhitespace(line[i])) i++
    if (i == targetStart || i == n) refuse("No request-target or no version")
    val targetEnd = i
    skipWhitespace()
    val version = i
    while (i < n && !isRequestLineWhitespace(line[i])) i++
    val ok =
        i - version == 8 &&
            line.decodeToString(version, version + 5) == "HTTP/" &&
            line[version + 5] in DIGITS &&
            line[version + 6] == '.'.code.toByte() &&
            line[version + 7] in DIGITS
    if (!ok) refuse("Invalid HTTP-version")
    skipWhitespace()
    if (i != n) refuse("Extra characters in the request line")
    if (line[version + 5] != '1'.code.toByte()) {
        throw RequestHeadRefused(505, "HTTP Version Not Supported", "HTTP major version other than 1")
    }
    val redirect = checkRequestTarget(line.decodeToString(methodStart, methodEnd), line, targetStart, targetEnd)
    return RequestLineCheck(version + 7, redirect)
}

/**
 * Checks the request-target `line[start, end)` of a [method] request against its forms (RFC 9112 section 3.2): the
 * authority-form `uri-host ":" port` for CONNECT, and only there, with a non-empty host (the target consists "of only
 * the host and port number of the tunnel destination", RFC 9110 section 9.3.6) and a port from 1 to 65535 (the same
 * section: a server MUST reject a CONNECT to an empty or invalid port); the asterisk-form for OPTIONS only; else the origin-form
 * (`absolute-path [ "?" query ]`) or the absolute-form (an absolute-URI: no fragment). Characters follow RFC 3986:
 * path and query characters, `%` with two hex digits. Anything else is an invalid request line, which the server SHOULD
 * answer with 400 or with a 301 to the request-target properly encoded (RFC 9112 section 3.2): the 301 for an origin-form
 * target of a GET or HEAD whose only fault is characters (browsers send `|`, `{`, `^`, `[` unencoded: the WHATWG URL
 * standard leaves them) and whose Location stays on this server ([isSafeToRedirect]), 400 otherwise. Returns that
 * Location for a 301, null for a valid target.
 */
private fun checkRequestTarget(
    method: String,
    line: ByteArray,
    start: Int,
    end: Int,
): String? {
    val target = line.decodeToString(start, end)
    val ascii = (start until end).all { (line[it].toInt() and 0xFF) < 0x80 }
    if (method == "CONNECT") {
        val colon = if (target.startsWith("[")) target.indexOf("]:").let { if (it < 0) -1 else it + 1 } else target.lastIndexOf(':')
        val port =
            if (colon <
                0
            ) {
                null
            } else {
                target.substring(colon + 1).takeIf { p -> p.length in 1..5 && p.all { it in '0'..'9' } }?.toInt()
            }
        // the host and port of the tunnel destination (RFC 9110 section 9.3.6): an empty host names none
        if (!ascii || colon < 1 || port == null || port !in 1..65_535 || !isValidHostField(target)) {
            refuse("CONNECT needs a request-target of uri-host \":\" port")
        }
        return null
    }
    if (target == "*") {
        if (method != "OPTIONS") refuse("The asterisk-form is for OPTIONS only")
        return null
    }
    if (target.startsWith("/")) {
        if (ascii && isPathAndQuery(target)) return null
        if ((method == "GET" || method == "HEAD") && isSafeToRedirect(target)) return encodeOriginForm(line, start, end)
        refuse("Invalid characters in the request-target")
    }
    if (!ascii || !isAbsoluteUri(target)) refuse("The request-target is no origin-form and no absolute-URI")
    return null
}

/**
 * Whether the 301 for the invalid origin-form [target] may be sent: its Location (the target encoded, a relative
 * reference) must be an absolute-path reference that resolves against this server's own authority. A Location that
 * starts with `//` is a network-path reference (RFC 3986 section 4.2) that a browser resolves to another host:
 * `GET //evil.example/^` redirected to `//evil.example/%5E` would be an open redirect. So the target must not start
 * with `//`, also not once its percent-encoded `/`, `\` and `.` are decoded, `\` is read as `/` (the WHATWG URL
 * standard does so for http and https) and its dot segments are removed (section 5.2.4), as a lenient client or a proxy
 * in front may do. And it must not contain a raw `#`: encoded as `%23` it names another resource than the path before
 * the `#` with a fragment, which is what the client most likely meant (section 2.2: a reserved character and its
 * percent-encoding are not equivalent), so there is no proper encoding to redirect to. Such targets get 400.
 */
internal fun isSafeToRedirect(target: String): Boolean {
    if ('#' in target) return false
    val path = target.substringBefore('?')
    val decoded = StringBuilder(path.length)
    var i = 0
    while (i < path.length) {
        val c = path[i]
        if (c == '%' && i + 2 < path.length) {
            when (path.substring(i + 1, i + 3).uppercase()) {
                "2F", "5C" -> {
                    decoded.append('/')
                    i += 3
                    continue
                }

                "2E" -> {
                    decoded.append('.')
                    i += 3
                    continue
                }
            }
        }
        decoded.append(if (c == '\\') '/' else c)
        i++
    }
    return !removeDotSegments(decoded.toString()).startsWith("//")
}

/**
 * remove_dot_segments of RFC 3986 section 5.2.4 for a path that starts with `/`, in time linear in its length (the
 * check runs before any authentication, so it must not copy the rest of the path at every step): the segments go on a
 * stack, `.` is dropped, `..` drops the segment before it (none above the root), and a `.` or `..` at the end leaves
 * the path ending with `/`, as the algorithm's steps do. [copied] is told how many characters each copy takes (a test
 * hook: the work is bounded by twice the path's length).
 */
internal fun removeDotSegments(
    path: String,
    copied: ((Int) -> Unit)? = null,
): String {
    val kept = ArrayList<String>()
    var start = 1
    while (start <= path.length) {
        val slash = path.indexOf('/', start).let { if (it < 0) path.length else it }
        val segment = path.substring(start, slash)
        copied?.invoke(segment.length)
        val last = slash == path.length
        when (segment) {
            "." -> {
                if (last) kept += ""
            }

            ".." -> {
                if (kept.isNotEmpty()) kept.removeAt(kept.size - 1)
                if (last) kept += ""
            }

            else -> {
                kept += segment
            }
        }
        start = slash + 1
    }
    return kept.joinToString("/", prefix = "/").also { copied?.invoke(it.length) }
}

/** `absolute-path [ "?" query ]` (RFC 9112 section 3.2.1, RFC 3986 section 3.3, 3.4) of a target that starts with `/`. */
private fun isPathAndQuery(s: String): Boolean {
    var i = 0
    while (i < s.length) {
        val c = s[i]
        when {
            c == '%' -> {
                if (i + 2 >= s.length || !isHexDigitChar(s[i + 1]) || !isHexDigitChar(s[i + 2])) return false
                i += 3
                continue
            }

            !isPchar(c) && c != '/' && c != '?' -> {
                return false
            }
        }
        i++
    }
    return true
}

/**
 * absolute-URI = scheme ":" hier-part [ "?" query ] (RFC 3986 section 4.3): a scheme, then either `//` an authority
 * (userinfo, which RequestFraming refuses for http and https, `@` a Host-like `uri-host [ ":" port ]`) and a path, or
 * a path; then a query. No fragment.
 */
private fun isAbsoluteUri(s: String): Boolean {
    val colon = s.indexOf(':')
    if (colon < 1 || !s[0].isAsciiLetter() || !s.substring(1, colon).all { it.isAsciiLetter() || it in '0'..'9' || it in "+-." }) {
        return false
    }
    var rest = s.substring(colon + 1)
    if (rest.startsWith("//")) {
        val authorityEnd = rest.indexOfAny(charArrayOf('/', '?'), 2).let { if (it < 0) rest.length else it }
        val authority = rest.substring(2, authorityEnd)
        // userinfo = *( unreserved / pct-encoded / sub-delims / ":" ): path characters without "@"
        val at = authority.lastIndexOf('@')
        val userinfo = if (at < 0) "" else authority.substring(0, at)
        if ('@' in userinfo || !isPathAndQuery("/$userinfo") || !isValidHostField(authority.substring(at + 1))) return false
        rest = rest.substring(authorityEnd)
    }
    return isPathAndQuery("/$rest")
}

/** pchar without pct-encoded (RFC 3986 section 3.3): unreserved, sub-delims, `:` and `@`. */
private fun isPchar(c: Char) = c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c in "-._~" || c in "!$&'()*+,;=" || c == ':' || c == '@'

private fun isHexDigitChar(c: Char) = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'

private fun Char.isAsciiLetter() = this in 'a'..'z' || this in 'A'..'Z'

/**
 * The origin-form `line[start, end)` properly encoded (RFC 3986 section 2.1): every byte that is no path or query
 * character, and a `%` without two hex digits after it, as `%XX`.
 */
private fun encodeOriginForm(
    line: ByteArray,
    start: Int,
    end: Int,
): String {
    val out = StringBuilder()
    for (i in start until end) {
        val b = line[i].toInt() and 0xFF
        val c = b.toChar()
        val keep =
            if (c == '%') {
                i + 2 < end && isHexDigitChar(line[i + 1].toInt().toChar()) && isHexDigitChar(line[i + 2].toInt().toChar())
            } else {
                b < 0x80 && (isPchar(c) || c == '/' || c == '?')
            }
        if (keep) out.append(c) else out.append('%').append(HEX[b shr 4]).append(HEX[b and 0xF])
    }
    return out.toString()
}

private const val HEX = "0123456789ABCDEF"

private val DIGITS = '0'.code.toByte()..'9'.code.toByte()

private fun refuse(message: String): Nothing = throw RequestHeadRefused(400, "Bad Request", message)

/**
 * The length of the UTF-8 sequence at [i] when it encodes a character above U+007F that Kotlin's `Char.isWhitespace` takes
 * as whitespace (U+00A0, U+1680, U+2000 to U+200A, U+2028, U+2029, U+202F, U+205F, U+3000), else 0. Ktor's parser
 * decodes the head as UTF-8 and skips or splits on such characters; on the wire they are obs-text or invalid bytes.
 */
internal fun unicodeSpaceLength(
    bytes: ByteArray,
    i: Int,
): Int {
    fun at(k: Int) = if (i + k < bytes.size) bytes[i + k].toInt() and 0xFF else -1
    return when (at(0)) {
        0xC2 -> {
            if (at(1) == 0xA0) 2 else 0
        }

        0xE1 -> {
            if (at(1) == 0x9A && at(2) == 0x80) 3 else 0
        }

        0xE2 -> {
            val b1 = at(1)
            val b2 = at(2)
            when {
                b1 == 0x80 && (b2 in 0x80..0x8A || b2 == 0xA8 || b2 == 0xA9 || b2 == 0xAF) -> 3
                b1 == 0x81 && b2 == 0x9F -> 3
                else -> 0
            }
        }

        0xE3 -> {
            if (at(1) == 0x80 && at(2) == 0x80) 3 else 0
        }

        else -> {
            0
        }
    }
}

/**
 * The answer to a request line longer than [MAX_REQUEST_LINE_BYTES]: 501 when its method alone is that long (RFC 9112
 * section 3: a server that receives a method longer than any that it implements SHOULD respond with 501), 414 when a
 * method and a separator start it, so the request-target is what is too long (section 3: MUST respond with 414), else
 * 400 (not a request line).
 */
private fun refuseLongLine(buffer: kotlinx.io.Buffer): Nothing {
    var i = 0L
    while (i < buffer.size && isTcharByte(buffer[i])) i++
    val message = "The request line is longer than $MAX_REQUEST_LINE_BYTES bytes"
    if (i > MAX_REQUEST_LINE_BYTES) throw RequestHeadRefused(501, "Not Implemented", message)
    if (i > 0 && i < buffer.size && isRequestLineWhitespace(buffer[i])) throw RequestHeadRefused(414, "URI Too Long", message)
    throw RequestHeadRefused(400, "Bad Request", message)
}

/**
 * Whether a request head starts, after request-line whitespace, with the method `HEAD` and a separator, decided as its
 * bytes arrive: [update] is called after every read with the buffer that holds the head from its first byte, and looks
 * at each byte once (the request line may start with up to 8 KiB of whitespace, sent one byte per segment). [inspected]
 * counts the bytes looked at, for tests.
 */
internal class HeadMethodScan {
    /** The next byte of the buffer to look at. */
    private var next = 0L

    /** Where the method starts; -1 while only whitespace has been seen. */
    private var methodStart = -1L

    /** Whether the answer is known. */
    var decided: Boolean = false
        private set

    /** The method is HEAD (false until [decided]). */
    var head: Boolean = false
        private set

    var inspected: Long = 0
        private set

    fun update(buffer: kotlinx.io.Buffer) {
        while (!decided && next < buffer.size) {
            val b = buffer[next]
            inspected++
            if (methodStart < 0) {
                if (!isRequestLineWhitespace(b)) methodStart = next
            }
            if (methodStart >= 0) {
                val k = (next - methodStart).toInt()
                if (k < 4) {
                    if (b != "HEAD"[k].code.toByte()) decided = true
                } else {
                    head = isRequestLineWhitespace(b)
                    decided = true
                }
            }
            next++
        }
    }
}

/** tchar (RFC 9110 section 5.6.2) as a byte. */
internal fun isTcharByte(b: Byte): Boolean {
    val c = b.toInt() and 0xFF
    return c in 'a'.code..'z'.code ||
        c in 'A'.code..'Z'.code ||
        c in '0'.code..'9'.code ||
        c.toChar() in "!#$%&'*+-.^_`|~"
}

/** The whitespace RFC 9112 section 3 lets a recipient take as the SP separator of a request line: SP, HTAB, VT, FF, CR. */
internal fun isRequestLineWhitespace(b: Byte): Boolean = b == SP_BYTE || b == HTAB_BYTE || b == VT_BYTE || b == FF_BYTE || b == CR_BYTE

private const val SP_BYTE: Byte = 0x20
private const val HTAB_BYTE: Byte = 0x09
private const val VT_BYTE: Byte = 0x0B
private const val FF_BYTE: Byte = 0x0C
private const val CR_BYTE: Byte = 0x0D
private const val LF_BYTE: Byte = 0x0A
