// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.http.content.OutgoingContent
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.RouteSelector
import io.ktor.server.routing.RouteSelectorEvaluation
import io.ktor.server.routing.RoutingResolveContext
import io.ktor.util.AttributeKey
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.http3.Http3ServerRequest
import io.kuicksilver.http3.UdpProxy
import kotlinx.coroutines.Job
import kotlin.coroutines.CoroutineContext

/**
 * Serves CONNECT-UDP (RFC 9298) with [proxy] on an engine with `connectUdp = true`: an Extended CONNECT over HTTP/3 whose
 * `:protocol` is `connect-udp`, at any path (the proxy matches its own `pathTemplate` and answers 404 for another).
 * Nothing else matches the route: HTTP/1.1 and HTTP/2 requests and other CONNECTs go on to the routes that follow; a
 * CONNECT-UDP request no route takes gets Ktor's 404, and one another route answers with a 2xx gets 501 (no tunnel was
 * opened). Put it inside an `authenticate { }` block or behind your own check: "HTTP servers that support UDP proxying
 * ought to restrict its use to authenticated users" (RFC 9298 section 7); a refusal there (401, 407) goes out as it is.
 * The proxy answers and relays the tunnel ([UdpProxy.serve]); the call ends with the tunnel.
 *
 * [proxy] holds the target filter (`UdpTargetFilter.PublicOnly` by default) and the limits, shared by every tunnel the
 * route serves: one [UdpProxy] per route, not per request.
 */
@ExperimentalKuicksilverApi
public fun Route.connectUdp(proxy: UdpProxy = UdpProxy()): Route =
    createChild(ConnectUdpSelector).apply {
        handle {
            call.respond(ConnectUdpUpgrade(proxy))
        }
    }

/** Set by the engine on an HTTP/3 CONNECT-UDP request: the request the tunnel is served on. */
internal val ConnectUdpRequestKey = AttributeKey<Http3ServerRequest>("kuicksilver.ConnectUdpRequest")

/** Matches only calls the engine marked as CONNECT-UDP requests, at any path: the proxy's own template decides. */
private object ConnectUdpSelector : RouteSelector() {
    override suspend fun evaluate(
        context: RoutingResolveContext,
        segmentIndex: Int,
    ): RouteSelectorEvaluation =
        if (context.call.attributes.contains(ConnectUdpRequestKey)) {
            // consumes the rest of the path, which the proxy reads from the request itself
            RouteSelectorEvaluation.Success(
                RouteSelectorEvaluation.qualityTailcard,
                io.ktor.http.Parameters.Empty,
                segmentIncrement = context.segments.size - segmentIndex,
            )
        } else {
            RouteSelectorEvaluation.FailedParameter
        }

    override fun toString(): String = "(CONNECT-UDP)"
}

/** The route's answer: the engine's HTTP/3 response hands the request to [proxy]; [upgrade] is never called by this engine. */
internal class ConnectUdpUpgrade(
    private val proxy: UdpProxy,
) : OutgoingContent.ProtocolUpgrade() {
    override suspend fun upgrade(
        input: ByteReadChannel,
        output: ByteWriteChannel,
        engineContext: CoroutineContext,
        userContext: CoroutineContext,
    ): Job = throw UnsupportedOperationException("CONNECT-UDP is served by the Kuicksilver engine over HTTP/3 only")

    /** Serves [request]; [answered] hears the status that went out (200, or the proxy's refusal) as soon as it did. */
    @OptIn(InternalKuicksilverApi::class)
    suspend fun serve(
        request: Http3ServerRequest,
        answered: (status: Int) -> Unit,
    ) {
        proxy.serve(request, answered)
    }
}
