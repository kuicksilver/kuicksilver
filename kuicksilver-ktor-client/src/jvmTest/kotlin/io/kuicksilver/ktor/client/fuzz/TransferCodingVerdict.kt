// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.fuzz

// This file is the same in the fuzz packages of kuicksilver-ktor-client and kuicksilver-ktor-server but for its package
// line: tools/check/fuzz-case-sync.sh fails when a copy drifts. Change them together. It shares nothing with the engines'
// own reading of Transfer-Encoding (h1/FramingFields.kt), which the HTTP/1.1 targets compare with it.

/** What a Transfer-Encoding field says about the framing of a message. */
internal enum class TransferCodingVerdict {
    /** The value is not `#transfer-coding`, chunked is listed twice, or the final chunked has parameters. */
    INVALID,

    /** chunked is the final coding, once and without parameters. */
    CHUNKED_FINAL,

    /** No coding, or a final coding other than chunked. */
    OTHER,
}

/**
 * The verdict on the Transfer-Encoding field lines [values], read from the ABNF alone: RFC 9112 section 6.1
 * `Transfer-Encoding = #transfer-coding`, section 7.3 `transfer-coding = token *( OWS ";" OWS transfer-parameter )`,
 * `transfer-parameter = token BWS "=" BWS ( token / quoted-string )`; RFC 9110 section 5.6.1 lists (elements separated by
 * `OWS "," OWS`, empty elements ignored; each field line a list of its own, their elements in order), 5.6.2 token, 5.6.3
 * OWS and BWS (SP and HTAB only), 5.6.4 quoted-string with qdtext and quoted-pair (obs-text: any character above U+007F,
 * the bytes of a decoded field). Coding names are case-insensitive (RFC 9112 section 7). chunked twice is invalid
 * (section 6.1: a sender MUST NOT apply it more than once), and so are parameters on the final chunked (section 7.1
 * defines none).
 */
internal fun transferCodingVerdict(values: List<String>): TransferCodingVerdict {
    val codings = ArrayList<Pair<String, Boolean>>() // name, has parameters
    // each field line is a list of its own (a quoted-string never runs on into the next line); their codings add up
    for (s in values) {
        var at = 0
        while (true) {
            at = OWS.find(s, at)!!.range.last + 1
            if (at >= s.length) break
            if (s[at] == ',') {
                at++ // an empty element
                continue
            }
            val element = ELEMENT.find(s, at)?.takeIf { it.range.first == at } ?: return TransferCodingVerdict.INVALID
            codings += element.groupValues[1].lowercase() to element.groupValues[2].isNotEmpty()
            at = element.range.last + 1
            val end = SEPARATOR.find(s, at)?.takeIf { it.range.first == at } ?: return TransferCodingVerdict.INVALID
            at = end.range.last + 1
        }
    }
    if (codings.count { it.first == "chunked" } > 1) return TransferCodingVerdict.INVALID
    val last = codings.lastOrNull() ?: return TransferCodingVerdict.OTHER
    if (last.first != "chunked") return TransferCodingVerdict.OTHER
    return if (last.second) TransferCodingVerdict.INVALID else TransferCodingVerdict.CHUNKED_FINAL
}

private const val TOKEN = "[!#$%&'*+.^_`|~0-9A-Za-z-]+"
private const val QUOTED_STRING = "\"(?:[\\t \\x21\\x23-\\x5B\\x5D-\\x7E\\u0080-\\uFFFF]|\\\\[\\t \\x21-\\x7E\\u0080-\\uFFFF])*\""
private const val PARAMETER = "[ \\t]*;[ \\t]*$TOKEN[ \\t]*=[ \\t]*(?:$TOKEN|$QUOTED_STRING)"

private val OWS = Regex("\\G[ \\t]*")
private val ELEMENT = Regex("\\G($TOKEN)((?:$PARAMETER)*)")
private val SEPARATOR = Regex("\\G[ \\t]*(?:,|\\z)")
