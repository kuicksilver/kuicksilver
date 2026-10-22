// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.server.request.ApplicationRequest
import io.ktor.server.response.ApplicationResponse
import io.ktor.util.AttributeKey
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.message.PriorityField
import io.kuicksilver.quic.StreamPriority
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** The client's priority signal of a Kuicksilver call: live over HTTP/3, the parsed field over HTTP/1.1. */
internal val RequestPriorityKey: AttributeKey<StateFlow<StreamPriority>> = AttributeKey("io.kuicksilver.ktor.server.RequestPriority")

private const val PRIORITY_FIELD = "Priority"

private val DefaultPriority: StateFlow<StreamPriority> = MutableStateFlow(StreamPriority.Default).asStateFlow()

/** The constant signal of an HTTP/1.1 request: its `Priority` field lines, combined as one dictionary. */
internal fun h1Priority(values: List<String>?): StateFlow<StreamPriority> =
    if (values.isNullOrEmpty()) DefaultPriority else MutableStateFlow(PriorityField.parse(values.joinToString(", "))).asStateFlow()

/**
 * The client's current priority signal for this request (RFC 9218): over HTTP/3 the `priority` field and the
 * PRIORITY_UPDATE frames that followed it, over HTTP/1.1 the `Priority` field; urgency 3, not incremental, when the client
 * sent none or another engine serves the call. A malformed or out-of-range parameter reads as its default (section 4).
 * Over HTTP/3 the engine schedules the response by this signal; over HTTP/1.1 it is advisory, since one connection
 * carries one response at a time.
 */
@ExperimentalKuicksilverApi
public val ApplicationRequest.priority: StreamPriority get() = priorityUpdates.value

/**
 * [priority] as it changes: over HTTP/3 each PRIORITY_UPDATE from the client (RFC 9218 section 7) is a new value, also
 * while the response is sent; over HTTP/1.1 and other engines the value never changes. The engine keeps one value per
 * request whatever the client sends.
 */
@ExperimentalKuicksilverApi
public val ApplicationRequest.priorityUpdates: StateFlow<StreamPriority>
    get() = call.attributes.getOrNull(RequestPriorityKey) ?: DefaultPriority

/**
 * Sets the response's `Priority` field (RFC 9218 section 5) with only the given parameters: one left null keeps the
 * client's value (section 8, "disinterest to change"). Over HTTP/3 the engine also schedules the response by the client's
 * signal merged with these parameters, and later PRIORITY_UPDATEs from the client no longer change it; over HTTP/1.1 only
 * the field is sent. Call it before the response starts.
 *
 * @throws IllegalArgumentException when [urgency] is outside 0..7, or both parameters are null.
 * @throws IllegalStateException when the response already has a `Priority` field.
 */
@ExperimentalKuicksilverApi
public fun ApplicationResponse.priority(
    urgency: Int? = null,
    incremental: Boolean? = null,
) {
    require(urgency == null || urgency in 0..7) { "urgency must be 0..7, was $urgency" }
    require(urgency != null || incremental != null) { "give urgency, incremental or both" }
    check(headers[PRIORITY_FIELD] == null) { "the response already has a Priority field" }
    val value =
        buildList {
            urgency?.let { add("u=$it") }
            incremental?.let { add(if (it) "i" else "i=?0") }
        }.joinToString(", ")
    headers.append(PRIORITY_FIELD, value)
}
