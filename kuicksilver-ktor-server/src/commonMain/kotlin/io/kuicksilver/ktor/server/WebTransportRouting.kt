// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.http.content.OutgoingContent
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.host
import io.ktor.server.request.port
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.RouteSelector
import io.ktor.server.routing.RouteSelectorEvaluation
import io.ktor.server.routing.RoutingResolveContext
import io.ktor.server.routing.route
import io.ktor.util.AttributeKey
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3ServerRequest
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.http3.acceptWebTransport
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlin.coroutines.CoroutineContext

/**
 * The application code a session ends with when its [webTransport] handler throws; the reason is empty, so nothing of
 * the exception reaches the client.
 */
@ExperimentalKuicksilverApi
public const val WEB_TRANSPORT_HANDLER_FAILED: Long = 1

/**
 * Serves WebTransport sessions (draft-ietf-webtrans-http3-16) on [path]: an Extended CONNECT whose `:protocol` is
 * `webtransport-h3` or `webtransport`, over HTTP/3, on an engine with `webTransport = true`. Nothing else matches the
 * route: HTTP/1.1 requests and other CONNECTs go on to the routes that follow, and a WebTransport request without a
 * matching route gets Ktor's 404.
 *
 * [checkOrigin] sees the request's `origin` field (null when absent) and refuses the session with 403 when it returns
 * false; the default, [sameHostOrigin], admits the server's own origin and clients that send none (browsers always
 * do). The server picks the first of [protocols] (its preference order) the client offers, if any. Then the session is
 * accepted (200) and [handler] runs; when it returns the session is closed with code 0, when it throws with
 * [WEB_TRANSPORT_HANDLER_FAILED] and an empty reason, and the exception goes on to Ktor as a failed call does.
 */
@ExperimentalKuicksilverApi
public fun Route.webTransport(
    path: String,
    protocols: List<String> = emptyList(),
    checkOrigin: (origin: String?, call: ApplicationCall) -> Boolean = ::sameHostOrigin,
    handler: suspend (WebTransportSession) -> Unit,
): Route =
    route(path, HttpMethod("CONNECT")) {
        createChild(WebTransportSelector).handle {
            val request = call.attributes[WebTransportRequestKey]
            if (!checkOrigin(request.headers["origin"], call)) {
                call.respond(HttpStatusCode.Forbidden)
                return@handle
            }
            val protocol = protocols.firstOrNull { it in request.availableProtocols }
            call.respond(WebTransportUpgrade(protocol, handler))
        }
    }

/**
 * The default origin check of [webTransport]: no `origin` field (a client that is no browser), or an origin whose host
 * and port are the request's (`:authority`, default ports filled in by scheme).
 */
@ExperimentalKuicksilverApi
public fun sameHostOrigin(
    origin: String?,
    call: ApplicationCall,
): Boolean {
    if (origin == null) return true
    val u =
        try {
            Url(origin)
        } catch (_: Exception) {
            return false
        }
    return u.host.equals(call.request.host(), ignoreCase = true) && u.port == call.request.port()
}

/** Set by the engine on an HTTP/3 WebTransport CONNECT: the request the session is accepted on. */
internal val WebTransportRequestKey = AttributeKey<Http3ServerRequest>("kuicksilver.WebTransportRequest")

/** Matches only calls the engine marked as WebTransport requests. */
private object WebTransportSelector : RouteSelector() {
    override suspend fun evaluate(
        context: RoutingResolveContext,
        segmentIndex: Int,
    ): RouteSelectorEvaluation =
        if (context.call.attributes.contains(WebTransportRequestKey)) {
            RouteSelectorEvaluation.Transparent
        } else {
            RouteSelectorEvaluation.FailedParameter
        }

    override fun toString(): String = "(WebTransport)"
}

/**
 * The route's answer: the engine's HTTP/3 response accepts the session with the headers Ktor gathered and runs
 * [handler] ([acceptAndRun]); [upgrade] is never called by this engine.
 */
internal class WebTransportUpgrade(
    private val protocol: String?,
    private val handler: suspend (WebTransportSession) -> Unit,
) : OutgoingContent.ProtocolUpgrade() {
    override suspend fun upgrade(
        input: ByteReadChannel,
        output: ByteWriteChannel,
        engineContext: CoroutineContext,
        userContext: CoroutineContext,
    ): Job = throw UnsupportedOperationException("a WebTransport session is accepted by the Kuicksilver engine over HTTP/3 only")

    suspend fun acceptAndRun(
        request: Http3ServerRequest,
        headers: Http3Headers,
    ) {
        val session = request.acceptWebTransport(headers, protocol)
        try {
            handler(session)
        } catch (e: Throwable) {
            val code = if (e is CancellationException) 0L else WEB_TRANSPORT_HANDLER_FAILED
            withContext(NonCancellable) { runCatching { session.close(code) } }
            throw e
        }
        session.close()
    }
}
