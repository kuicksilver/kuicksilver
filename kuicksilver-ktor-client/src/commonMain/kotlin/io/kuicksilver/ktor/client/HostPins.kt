// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.annotations.KuicksilverDsl
import io.kuicksilver.annotations.SecuritySensitive
import io.kuicksilver.tls.HostName
import io.kuicksilver.tls.PinScope
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsException

/**
 * Certificate pins per host (RFC 7469 SPKI hashes), the form of OkHttp's `CertificatePinner`; change it with
 * `engine { tls { pins { } } }` ([ClientTlsConfig.pins]):
 *
 * ```
 * engine {
 *     tls {
 *         pins {
 *             add("api.example.com", "sha256/AAAA…=", "sha256/BBBB…=")   // the current key and a backup
 *             add("**.cdn.example.com", "sha256/CCCC…=")
 *         }
 *     }
 * }
 * ```
 *
 * **Patterns** are OkHttp's: a host name (`api.example.com`), `*.` and a name for exactly one more label in front
 * (`*.example.com` matches `www.example.com`, not `example.com` nor `a.b.example.com`), `**.` and a name for any number of
 * labels in front, none included (`**.example.com` matches `example.com`, `www.example.com` and `a.b.example.com`), or an
 * IP literal (`192.0.2.1`, `2001:db8::1` with or without brackets; an IPv4-mapped IPv6 address is its IPv4 address). A `*`
 * anywhere else, and in front of an IP literal, is refused. The name after the wildcard must be one the TLS layer takes
 * as a reference identifier (`io.kuicksilver.tls.HostName`: ASCII LDH labels, no `_`, no hyphen first or last, a last
 * label that is not all digits); an internationalized name is written as its A-labels (`xn--bcher-kva.example`, as IDNA's
 * ToASCII gives it: a non-ASCII pattern is refused, as the TLS layer refuses a non-ASCII host), and an `xn--` label must
 * be valid Punycode. Names are compared as `HostName` normalizes them: without case, without spaces or tabs around them,
 * one trailing dot changes nothing (`example.com.` is `example.com`; OkHttp would not pin a request to `example.com.`,
 * which this engine does).
 *
 * **Which pins a request meets.** The host of the request URL (the origin, never the SNI, an `Alt-Svc` alternative or an
 * `ExpectedName`) is matched against every pattern; the pins of all matching patterns together are its set, and one of them
 * must match the validated chain within [scope], on top of the engine's `trust` (`TrustConfig.Pinned(set, scope, base =
 * trust)` for that connection: the same check, the same [io.kuicksilver.tls.VerifyReason.PinMismatch] when it fails,
 * naming the host and the chain's pins). A host no pattern matches has no pins. The same set holds over HTTP/3, HTTP/2 and
 * HTTP/1.1, through a proxy's tunnel (the origin's pins, never the proxy's), for an `Alt-Svc` alternative (which must present
 * the origin's certificate, RFC 7838 section 2.1) and after a redirect (the new host's set). A connection carries requests of
 * another host (`pool { coalescing }`, RFC 9113 section 9.1.1, RFC 9114 section 3.3) only when both hosts have the same set.
 * Once any pin is configured, a request whose host is no reference identifier (a malformed IPv4 form such as `127.1`, an
 * IPv6 zone, a non-ASCII name) fails with `TlsException.Config` instead of going unpinned.
 *
 * **Refused** when the engine is created: pins together with `trust = TrustConfig.Pinned(…)` (two sources of pins: use
 * one), and with a `trust` pins cannot sit on (`Tofu`, `Custom`, `ExpectedName` over `Custom`, as for `Pinned`); in [add],
 * a bad pattern, a pin that is not `sha256/` and 32 bytes of base64 (OkHttp's `sha1/` pins included), and no pin at all.
 *
 * The block of `proxies { tls { } }` has its own pins, for the proxy's host; the engine's pins never apply to the proxy hop.
 */
@KuicksilverDsl
public class HostPinsConfig {
    private val entries = LinkedHashMap<String, MutableSet<SpkiSha256>>()

    /**
     * Which certificates of the validated chain a pin may match, for every pattern: [PinScope.Leaf] (the default, as
     * `TrustConfig.Pinned`: only the server's own key) or [PinScope.AnyInValidatedChain] (any certificate of the chain the
     * verifier built, as OkHttp's `CertificatePinner` and RFC 7469 do: pin your CA's key to survive leaf rotations).
     */
    @SecuritySensitive
    public var scope: PinScope = PinScope.Leaf

    /**
     * Pins [pins] (OkHttp's text form, `sha256/<base64 of 32 bytes>`) for the hosts [pattern] matches; one match is
     * enough, so list a backup key. Calls for the same pattern add up.
     *
     * @throws IllegalArgumentException for a bad pattern (the message says why: a non-ASCII name, a misplaced `*`, a name
     *   the TLS layer would refuse), a pin that is not `sha256/` with 32 bytes (a `sha1/` pin: use the `sha256/` pin of the
     *   same key) or no pin.
     */
    @SecuritySensitive
    public fun add(
        pattern: String,
        vararg pins: String,
    ) {
        add(pattern, pins.map { parsePin(pattern, it) })
    }

    /**
     * Pins [pins] for the hosts [pattern] matches; one match is enough, so list a backup key. Calls for the same pattern add
     * up.
     *
     * @throws IllegalArgumentException for a bad pattern or no pin.
     */
    @SecuritySensitive
    public fun add(
        pattern: String,
        vararg pins: SpkiSha256,
    ) {
        add(pattern, pins.toList())
    }

    private fun add(
        pattern: String,
        pins: List<SpkiSha256>,
    ) {
        require(pins.isNotEmpty()) { "tls { pins { add(\"$pattern\") } } needs at least one pin" }
        val canonical =
            try {
                PinHosts.canonicalPattern(pattern)
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("tls { pins { add(\"$pattern\", …) } }: not a host pattern: ${e.message}", e)
            }
        entries.getOrPut(canonical) { LinkedHashSet() } += pins
    }

    /** Whether no pattern was added. */
    internal val isEmpty: Boolean get() = entries.isEmpty()

    /**
     * The pins of every pattern that matches [host] (a request's host, as in its URL), empty when none matches. With any
     * pattern configured, a host that is no reference identifier fails closed: [io.kuicksilver.tls.TlsException.Config]
     * (the TLS layer would refuse it too; it must never be served unpinned because it matched no pattern).
     */
    internal fun pinsFor(host: String): Set<SpkiSha256> {
        if (entries.isEmpty()) return emptySet()
        val h = PinHosts.canonicalHost(host)
        val out = LinkedHashSet<SpkiSha256>()
        for ((pattern, pins) in entries) if (PinHosts.matches(pattern, h)) out += pins
        return out
    }

    /** Any one pattern's pins, for the checks when the engine is created; null when empty. */
    internal fun anyPins(): Set<SpkiSha256>? = entries.values.firstOrNull()

    private fun parsePin(
        pattern: String,
        pin: String,
    ): SpkiSha256 {
        val where = "tls { pins { add(\"$pattern\", …) } }"
        if (pin.startsWith("sha1/")) {
            throw IllegalArgumentException(
                "$where: $pin is a sha1/ pin, which is not supported (RFC 7469 pins are SHA-256): use the sha256/ pin of the same key",
            )
        }
        return try {
            SpkiSha256.parse(pin)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("$where: \"$pin\" is not a pin: expected sha256/ and the base64 of 32 bytes", e)
        }
    }
}

/**
 * OkHttp's `CertificatePinner` host patterns and their matching (its `Pin.matchesHostname`), on the TLS layer's reference
 * identifiers: a host is keyed exactly as [HostName.normalize] gives the name the certificate is checked against, so no
 * spelling of a host the handshake accepts can miss its pins.
 */
internal object PinHosts {
    /** A pattern's canonical form: its wildcard prefix and the canonical host after it; [IllegalArgumentException] says why not. */
    fun canonicalPattern(pattern: String): String {
        require(pattern.all { it.code < 0x80 }) {
            "a non-ASCII name; write its A-labels (xn--…, IDNA's ToASCII, RFC 5891), as the TLS layer takes only those"
        }
        val prefix =
            when {
                pattern.startsWith("**.") -> "**."
                pattern.startsWith("*.") -> "*."
                else -> ""
            }
        val rest = pattern.substring(prefix.length)
        require('*' !in rest) { "a * only as a leading *. (one label) or **. (any number)" }
        val name =
            try {
                HostName.normalize(rest)
            } catch (e: TlsException.Config) {
                throw IllegalArgumentException(e.message, e)
            }
        require(prefix.isEmpty() || !name.isIpLiteral) { "a wildcard in front of an IP literal" }
        if (name.isIpLiteral) return ipText(name.value)
        for (label in name.value.split('.')) {
            if (label.startsWith("xn--")) require(Punycode.roundTrips(label.substring(4))) { "$label is not a valid A-label" }
        }
        return prefix + name.value
    }

    /**
     * [host] as patterns are compared with it: [HostName.normalize]'s value (lower case, OWS and one trailing dot dropped,
     * brackets off an IPv6 literal), an IP literal as its address (RFC 5952 text, an IPv4-mapped one as IPv4).
     *
     * @throws TlsException.Config when [host] is no reference identifier, as the handshake would.
     */
    fun canonicalHost(host: String): String {
        val name = HostName.normalize(host)
        return if (name.isIpLiteral) ipText(name.value) else name.value
    }

    private fun ipText(literal: String): String {
        val b = parseIpLiteral(literal) ?: throw IllegalArgumentException("$literal is not an IP literal")
        if (b.size == 4) return b.joinToString(".") { (it.toInt() and 0xff).toString() }
        val mapped = (0 until 10).all { b[it].toInt() == 0 } && (b[10].toInt() and 0xff) == 0xff && (b[11].toInt() and 0xff) == 0xff
        if (mapped) return (12 until 16).joinToString(".") { (b[it].toInt() and 0xff).toString() }
        val w = IntArray(8) { ((b[2 * it].toInt() and 0xff) shl 8) or (b[2 * it + 1].toInt() and 0xff) }
        // RFC 5952 section 4.2: the longest run of two or more zero groups as `::`, the first on a tie
        var bestStart = -1
        var bestLen = 1
        var i = 0
        while (i < 8) {
            if (w[i] != 0) {
                i++
                continue
            }
            var j = i
            while (j < 8 && w[j] == 0) j++
            if (j - i > bestLen) {
                bestStart = i
                bestLen = j - i
            }
            i = j
        }
        if (bestStart < 0) return w.joinToString(":") { it.toString(16) }
        val left = (0 until bestStart).joinToString(":") { w[it].toString(16) }
        val right = (bestStart + bestLen until 8).joinToString(":") { w[it].toString(16) }
        return "$left::$right"
    }

    /** OkHttp's `Pin.matchesHostname`, on canonical forms. */
    fun matches(
        pattern: String,
        host: String,
    ): Boolean =
        when {
            pattern.startsWith("**.") -> {
                val suffix = pattern.substring(3)
                host == suffix || host.endsWith(".$suffix")
            }

            pattern.startsWith("*.") -> {
                val suffix = pattern.substring(1) // with its dot
                host.length > suffix.length && host.endsWith(suffix) && host.lastIndexOf('.', host.length - suffix.length - 1) == -1
            }

            else -> {
                host == pattern
            }
        }
}

/**
 * RFC 3492 Punycode, for one check only: that the part of an `xn--` label after the prefix decodes, to something that is
 * not all ASCII, and encodes back to itself (a valid A-label; pins are never converted from Unicode here).
 */
internal object Punycode {
    private const val BASE = 36
    private const val TMIN = 1
    private const val TMAX = 26
    private const val SKEW = 38
    private const val DAMP = 700
    private const val INITIAL_BIAS = 72
    private const val INITIAL_N = 128

    fun roundTrips(encoded: String): Boolean {
        val decoded = decode(encoded) ?: return false
        return decoded.any { it >= 0x80 } && allowed(decoded) && encode(decoded) == encoded
    }

    /**
     * A minimal form of IDNA's code point rules (RFC 5891 section 4.2.3, RFC 5892): only lower-case letters, digits, marks
     * and hyphens, no mark first (section 4.2.3.2), no surrogate, none of the half-width and full-width forms (DISALLOWED:
     * they are compatibility variants of other characters), and outside the Basic Multilingual Plane only the CJK
     * ideographs (extensions B to H), whose category common Kotlin cannot read. Stricter than RFC 5892, never looser.
     */
    private fun allowed(cps: IntArray): Boolean {
        for ((i, cp) in cps.withIndex()) {
            val ok =
                when {
                    cp < 0x80 -> {
                        cp.toChar().let { it in 'a'..'z' || it in '0'..'9' || it == '-' }
                    }

                    cp in 0xD800..0xDFFF || cp in 0xFF00..0xFFEF -> {
                        false
                    }

                    cp > 0xFFFF -> {
                        cp in 0x20000..0x323AF
                    }

                    else -> {
                        val c = cp.toChar()
                        val mark =
                            c.category == CharCategory.NON_SPACING_MARK || c.category == CharCategory.COMBINING_SPACING_MARK ||
                                c.category == CharCategory.ENCLOSING_MARK
                        (c.isLetter() && !c.isUpperCase() && !c.isTitleCase()) ||
                            c.category == CharCategory.DECIMAL_DIGIT_NUMBER ||
                            (mark && i > 0)
                    }
                }
            if (!ok) return false
        }
        return true
    }

    /** The code points of [input], or null when it is no Punycode. */
    fun decode(input: String): IntArray? {
        val d = input.lastIndexOf('-')
        val out = ArrayList<Int>()
        if (d > 0) {
            for (c in input.substring(0, d)) {
                if (c.code >= 0x80) return null
                out += c.code
            }
        }
        var n = INITIAL_N
        var i = 0L
        var bias = INITIAL_BIAS
        var pos = if (d > 0) d + 1 else 0
        while (pos < input.length) {
            val oldI = i
            var w = 1L
            var k = BASE
            while (true) {
                if (pos >= input.length) return null
                val digit = digitOf(input[pos++])
                if (digit < 0) return null
                i += digit * w
                if (i > Int.MAX_VALUE) return null
                val t =
                    if (k <= bias) {
                        TMIN
                    } else if (k >= bias + TMAX) {
                        TMAX
                    } else {
                        k - bias
                    }
                if (digit < t) break
                w *= (BASE - t)
                if (w > Int.MAX_VALUE) return null
                k += BASE
            }
            bias = adapt((i - oldI).toInt(), out.size + 1, oldI == 0L)
            n += (i / (out.size + 1)).toInt()
            if (n > 0x10FFFF) return null
            i %= (out.size + 1)
            out.add(i.toInt(), n)
            i++
        }
        return out.toIntArray()
    }

    /** The Punycode of [cps], or null on overflow. */
    fun encode(cps: IntArray): String? {
        val out = StringBuilder()
        for (cp in cps) if (cp < 0x80) out.append(cp.toChar())
        val basic = out.length
        var handled = basic
        if (basic > 0) out.append('-')
        var n = INITIAL_N
        var delta = 0L
        var bias = INITIAL_BIAS
        while (handled < cps.size) {
            val m = cps.filter { it >= n }.minOrNull() ?: return null
            delta += (m - n).toLong() * (handled + 1)
            if (delta > Int.MAX_VALUE) return null
            n = m
            for (cp in cps) {
                if (cp < n) {
                    delta++
                    if (delta > Int.MAX_VALUE) return null
                }
                if (cp == n) {
                    var q = delta.toInt()
                    var k = BASE
                    while (true) {
                        val t =
                            if (k <= bias) {
                                TMIN
                            } else if (k >= bias + TMAX) {
                                TMAX
                            } else {
                                k - bias
                            }
                        if (q < t) break
                        out.append(digit(t + (q - t) % (BASE - t)))
                        q = (q - t) / (BASE - t)
                        k += BASE
                    }
                    out.append(digit(q))
                    bias = adapt(delta.toInt(), handled + 1, handled == basic)
                    delta = 0
                    handled++
                }
            }
            delta++
            n++
        }
        return out.toString()
    }

    private fun digit(d: Int): Char = if (d < 26) 'a' + d else '0' + (d - 26)

    private fun digitOf(c: Char): Int =
        when (c) {
            in 'a'..'z' -> c - 'a'
            in '0'..'9' -> c - '0' + 26
            else -> -1 // lower case only: the label was normalized
        }

    private fun adapt(
        d: Int,
        numPoints: Int,
        first: Boolean,
    ): Int {
        var delta = if (first) d / DAMP else d / 2
        delta += delta / numPoints
        var k = 0
        while (delta > ((BASE - TMIN) * TMAX) / 2) {
            delta /= BASE - TMIN
            k += BASE
        }
        return k + (BASE - TMIN + 1) * delta / (delta + SKEW)
    }
}
