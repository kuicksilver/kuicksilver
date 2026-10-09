// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

/** Ordered HTTP fields without pseudo-headers; names are lowercase on the wire (RFC 9114 section 4.2). */
public class Http3Headers(
    fields: List<Pair<String, String>>,
) {
    /** The fields as name/value pairs in wire order, repeats kept; a copy of the constructor's list. */
    public val fields: List<Pair<String, String>> = fields.toList()

    /** The number of field lines, repeats counted. */
    public val size: Int get() = fields.size

    /** The first value of [name] (exact, lowercase), or null. */
    public operator fun get(name: String): String? = fields.firstOrNull { it.first == name }?.second

    /** Every value of [name] (exact, lowercase) in wire order; empty when absent. */
    public fun getAll(name: String): List<String> = fields.filter { it.first == name }.map { it.second }

    /** These fields followed by [other]'s; nothing is merged or replaced. */
    public operator fun plus(other: Http3Headers): Http3Headers = Http3Headers(fields + other.fields)

    override fun equals(other: Any?): Boolean = other is Http3Headers && other.fields == fields

    override fun hashCode(): Int = fields.hashCode()

    override fun toString(): String = fields.joinToString(prefix = "Http3Headers(", postfix = ")") { "${it.first}: ${it.second}" }

    /** Shorthands for building field sections. */
    public companion object {
        /** No fields: the default of optional header and trailer parameters. */
        public val Empty: Http3Headers = Http3Headers(emptyList())

        /** Fields from pairs, in the given order; names must be lowercase, a peer treats others as malformed (RFC 9114 section 4.2). */
        public fun of(vararg fields: Pair<String, String>): Http3Headers = Http3Headers(fields.toList())
    }
}
