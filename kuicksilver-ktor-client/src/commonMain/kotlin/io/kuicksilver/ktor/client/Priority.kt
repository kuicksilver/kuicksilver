// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.HttpRequestData
import io.ktor.client.statement.HttpResponse
import io.ktor.util.AttributeKey
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.Http3Response
import io.kuicksilver.quic.StreamPriority
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.isActive

/** The priority a request was given with [priority]. */
internal val PriorityKey: AttributeKey<StreamPriority> = AttributeKey("io.kuicksilver.ktor.client.Priority")

/** The HTTP/3 exchange of the call's latest attempt, for [updatePriority]; absent over HTTP/1.1. */
internal val H3ExchangeKey: AttributeKey<Http3Response> = AttributeKey("io.kuicksilver.ktor.client.H3Exchange")

/** The request's own priority, if [priority] gave one. */
internal val HttpRequestData.priority: StreamPriority? get() = attributes.getOrNull(PriorityKey)

/**
 * Gives this request an RFC 9218 priority: [urgency] 0 (most urgent) to 7, and whether its response may be [incremental]ly
 * interleaved with others of the same urgency. Over HTTP/3 the engine sends it as the `priority` field (none for the
 * default, u=3 non-incremental) and schedules the request's own stream with it; a WebSocket over HTTP/3 carries it too.
 * Over HTTP/1.1 only the `Priority` field is sent. A `Priority` header set on the request is dropped in its favour, so the
 * server sees one signal. Without this call a `Priority` header is sent as it is.
 *
 * @throws IllegalArgumentException when [urgency] is outside 0..7.
 */
@ExperimentalKuicksilverApi
public fun HttpRequestBuilder.priority(
    urgency: Int = 3,
    incremental: Boolean = false,
) {
    require(urgency in 0..7) { "urgency must be 0..7, was $urgency" }
    attributes.put(PriorityKey, StreamPriority(urgency, incremental))
}

/** The priority [priority] gave this request, or null. */
@ExperimentalKuicksilverApi
public val HttpRequestBuilder.priority: StreamPriority? get() = attributes.getOrNull(PriorityKey)

/**
 * Sends a new priority for this response (a PRIORITY_UPDATE frame, RFC 9218 section 7) and applies it to the request's
 * own stream; the server reschedules the rest of the response unless it set a priority of its own. True when the frame
 * was sent; false over HTTP/1.1, which has no such signal, once the call is over or its body was read to the end, and when
 * the connection is gone.
 *
 * @throws IllegalArgumentException when [urgency] is outside 0..7.
 */
@ExperimentalKuicksilverApi
public suspend fun HttpResponse.updatePriority(
    urgency: Int,
    incremental: Boolean,
): Boolean {
    require(urgency in 0..7) { "urgency must be 0..7, was $urgency" }
    val exchange = call.attributes.getOrNull(H3ExchangeKey) ?: return false
    if (!this.coroutineContext.isActive || exchange.trailers.isCompleted) return false
    return try {
        exchange.updatePriority(StreamPriority(urgency, incremental))
        true
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        false // the connection is gone (its control stream with it): nothing to update
    }
}
