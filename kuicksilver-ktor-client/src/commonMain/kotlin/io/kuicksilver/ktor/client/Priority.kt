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

/**
 * Sends a PRIORITY_UPDATE on the stream of the call's latest attempt, for [updatePriority]: true when it went. Absent over
 * HTTP/1.1, which has no such signal.
 */
internal fun interface PriorityUpdater {
    suspend fun update(p: StreamPriority): Boolean
}

/** The [PriorityUpdater] of the call's latest attempt (HTTP/3 or HTTP/2); removed when an attempt goes over HTTP/1.1. */
internal val PriorityUpdaterKey: AttributeKey<PriorityUpdater> = AttributeKey("io.kuicksilver.ktor.client.PriorityUpdater")

/** The [PriorityUpdater] of an HTTP/3 exchange: false once its response is complete. */
internal fun Http3Response.priorityUpdater(): PriorityUpdater =
    PriorityUpdater { p ->
        if (trailers.isCompleted) return@PriorityUpdater false
        updatePriority(p)
        true
    }

/** The request's own priority, if [priority] gave one. */
internal val HttpRequestData.priority: StreamPriority? get() = attributes.getOrNull(PriorityKey)

/**
 * Gives this request an RFC 9218 priority: [urgency] 0 (most urgent) to 7, and whether its response may be [incremental]ly
 * interleaved with others of the same urgency. Over HTTP/3 the engine sends it as the `priority` field (none for the
 * default, u=3 non-incremental) and schedules the request's own stream with it; a WebSocket over HTTP/3 carries it too.
 * Over HTTP/2 the same, and until the server's SETTINGS say it ignores them, the request's HEADERS also carry an RFC 7540
 * weight from the urgency (RFC 9218 section 2.1.1). Over HTTP/1.1 only the `Priority` field is sent. A `Priority` header set on the request is dropped in its favour, so the
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
 * own stream; the server reschedules the rest of the response unless it set a priority of its own. Over HTTP/2 the
 * signals follow section 2.1.1: PRIORITY_UPDATE unless the server's SETTINGS left SETTINGS_NO_RFC7540_PRIORITIES at 0, and
 * an RFC 7540 PRIORITY frame unless they said 1 (both before those SETTINGS). True when a signal was sent; false over
 * HTTP/1.1, which has no such signal, once the call is over or its body was read to the end, and when the connection is
 * gone.
 *
 * @throws IllegalArgumentException when [urgency] is outside 0..7.
 */
@ExperimentalKuicksilverApi
public suspend fun HttpResponse.updatePriority(
    urgency: Int,
    incremental: Boolean,
): Boolean {
    require(urgency in 0..7) { "urgency must be 0..7, was $urgency" }
    val updater = call.attributes.getOrNull(PriorityUpdaterKey) ?: return false
    if (!this.coroutineContext.isActive) return false
    return try {
        updater.update(StreamPriority(urgency, incremental))
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        false // the connection is gone (its control stream with it): nothing to update
    }
}
