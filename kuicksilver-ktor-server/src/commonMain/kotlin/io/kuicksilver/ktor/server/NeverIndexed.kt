// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.request.ApplicationRequest
import io.ktor.server.response.ApplicationResponse
import io.ktor.util.AttributeKey
import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/** The lowercase names [neverIndex] marked on a response. */
internal val NeverIndexKey: AttributeKey<Set<String>> = AttributeKey("io.kuicksilver.ktor.server.NeverIndex")

/** The request fields the client sent as literals never indexed (HTTP/2). */
internal val NeverIndexedReceivedKey: AttributeKey<List<Pair<String, String>>> =
    AttributeKey("io.kuicksilver.ktor.server.NeverIndexedReceived")

/**
 * The request fields the client sent over HTTP/2 as literals never indexed (RFC 7541 section 6.2.3), with lowercase names,
 * in the order received; empty over HTTP/1.1, HTTP/3 and other engines. A proxy that forwards one of them MUST keep that
 * representation (section 7.1.3): pass its name to the Kuicksilver client's `neverIndex` on the request it sends on.
 */
@ExperimentalKuicksilverApi
public val ApplicationRequest.neverIndexedHeaders: List<Pair<String, String>>
    get() = call.attributes.getOrNull(NeverIndexedReceivedKey).orEmpty()

/**
 * Sends this response's fields named [names] (any case) as literals never indexed over HTTP/2 (RFC 7541 section 6.2.3):
 * the HPACK encoder neither adds them to the dynamic table nor refers to an entry for them, and an intermediary has to
 * keep that representation (section 7.1.3). For secrets that are short or easy to guess, and for a proxy that forwards a
 * field it received never indexed ([neverIndexedHeaders] of the request, or of the response it relays). The engine
 * already sends `set-cookie` so. Each call adds to the names; call it before the response starts. Over HTTP/1.1 and
 * HTTP/3 it changes nothing.
 */
@ExperimentalKuicksilverApi
public fun ApplicationResponse.neverIndex(vararg names: String) {
    val attributes = call.attributes
    attributes.put(NeverIndexKey, attributes.getOrNull(NeverIndexKey).orEmpty() + names.map { it.lowercase() })
}
