// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.statement.HttpResponse
import io.ktor.util.AttributeKey
import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/** The lowercase names [neverIndex] marked on a request. */
internal val NeverIndexKey: AttributeKey<Set<String>> = AttributeKey("io.kuicksilver.ktor.client.NeverIndex")

/** The response fields the server sent as literals never indexed (HTTP/2); set by the engine per response. */
internal val NeverIndexedReceivedKey: AttributeKey<List<Pair<String, String>>> =
    AttributeKey("io.kuicksilver.ktor.client.NeverIndexedReceived")

/**
 * Sends this request's fields named [names] (any case) as literals never indexed over HTTP/2 (RFC 7541 section 6.2.3): the
 * HPACK encoder neither adds them to the dynamic table nor refers to an entry for them, and an intermediary has to keep
 * that representation (section 7.1.3). For secrets that are short or easy to guess (section 7.1.3), and for a proxy
 * that forwards a field it received never indexed ([neverIndexedHeaders] of the response it relays). The engine already
 * sends `authorization`, `proxy-authorization` and short `cookie` values so. Each call adds to the names; over HTTP/1.1
 * and HTTP/3 the call changes nothing.
 */
@ExperimentalKuicksilverApi
public fun HttpRequestBuilder.neverIndex(vararg names: String) {
    val now = attributes.getOrNull(NeverIndexKey).orEmpty()
    attributes.put(NeverIndexKey, now + names.map { it.lowercase() })
}

/**
 * The response fields the server sent over HTTP/2 as literals never indexed (RFC 7541 section 6.2.3), with lowercase
 * names, in the order received; empty over HTTP/1.1 and HTTP/3. A proxy that forwards one of them MUST keep that
 * representation (section 7.1.3): pass its name to the server engine's `neverIndex` on the response it relays.
 */
@ExperimentalKuicksilverApi
public val HttpResponse.neverIndexedHeaders: List<Pair<String, String>>
    get() = call.attributes.getOrNull(NeverIndexedReceivedKey).orEmpty()
