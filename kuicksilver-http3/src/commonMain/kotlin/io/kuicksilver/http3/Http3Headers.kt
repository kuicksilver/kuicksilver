// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/**
 * Ordered HTTP fields without pseudo-headers; names are lowercase on the wire (RFC 9114 section 4.2). Equality and
 * [toString] look at [fields] only, not at the never-indexed marks.
 */
public class Http3Headers private constructor(
    fields: List<Pair<String, String>>,
    neverIndexed: List<Pair<String, String>>,
    neverIndexNames: Set<String>,
) {
    /** A section of [fields] (copied), without never-indexed marks. */
    public constructor(fields: List<Pair<String, String>>) : this(fields, emptyList(), emptySet())

    /** The fields as name/value pairs in wire order, repeats kept; a copy of the constructor's list. */
    public val fields: List<Pair<String, String>> = fields.toList()

    /**
     * Received: the field lines the peer sent as literals with QPACK's 'N' bit (RFC 9204 section 4.5.4), in wire order;
     * "an intermediary MUST use a literal representation to forward this field line" (section 7.1.3). Sent: fields of a
     * section with these names go with the bit too, so a received section forwarded as it is keeps it. Empty otherwise.
     */
    @ExperimentalKuicksilverApi
    public val neverIndexed: List<Pair<String, String>> = neverIndexed

    /** Names (lowercase) whose field lines this section sends as literals with the 'N' bit; see [withNeverIndexed]. */
    @ExperimentalKuicksilverApi
    public val neverIndexNames: Set<String> = neverIndexNames

    /**
     * A copy whose field lines named [names] (any case) are sent as literals with the 'N' bit (RFC 9204 sections 4.5.4,
     * 7.1.3): neither inserted into the encoder's dynamic table nor matched to an entry of it. For secrets that are short
     * or easy to guess, and for fields a proxy received so. The encoder does it on its own for `authorization`,
     * `proxy-authorization`, `cookie` and `set-cookie`.
     */
    @ExperimentalKuicksilverApi
    public fun withNeverIndexed(vararg names: String): Http3Headers =
        Http3Headers(fields, neverIndexed, neverIndexNames + names.map { n -> n.lowercase() })

    /** A copy with [lines] as the received never-indexed field lines. */
    internal fun withReceivedNeverIndexed(lines: List<Pair<String, String>>): Http3Headers =
        Http3Headers(fields, lines.toList(), neverIndexNames)

    /** The number of field lines, repeats counted. */
    public val size: Int get() = fields.size

    /** The first value of [name] (exact, lowercase), or null. */
    public operator fun get(name: String): String? = fields.firstOrNull { it.first == name }?.second

    /** Every value of [name] (exact, lowercase) in wire order; empty when absent. */
    public fun getAll(name: String): List<String> = fields.filter { it.first == name }.map { it.second }

    /** These fields followed by [other]'s; nothing is merged or replaced. */
    public operator fun plus(other: Http3Headers): Http3Headers =
        Http3Headers(fields + other.fields, neverIndexed + other.neverIndexed, neverIndexNames + other.neverIndexNames)

    /** Equal when the fields, in order, are. */
    override fun equals(other: Any?): Boolean = other is Http3Headers && other.fields == fields

    /** Consistent with [equals]. */
    override fun hashCode(): Int = fields.hashCode()

    /** For logs. */
    override fun toString(): String = fields.joinToString(prefix = "Http3Headers(", postfix = ")") { "${it.first}: ${it.second}" }

    /** Shorthands for building field sections. */
    public companion object {
        /** No fields: the default of optional header and trailer parameters. */
        public val Empty: Http3Headers = Http3Headers(emptyList())

        /** Fields from pairs, in the given order; names must be lowercase, a peer treats others as malformed (RFC 9114 section 4.2). */
        public fun of(vararg fields: Pair<String, String>): Http3Headers = Http3Headers(fields.toList())
    }
}
