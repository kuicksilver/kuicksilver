// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.HttpRequestData
import io.ktor.http.HttpProtocolVersion
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import kotlin.time.Duration

/**
 * Hears what the client engine does with each call (docs/guide/ktor.md, "Observability"), in the manner of OkHttp's
 * `EventListener`: set it with `engine { eventListener = ... }`. Every method has an empty default; override the ones you
 * need. The order for one call is [callStart], then for each attempt the protocol decision ([protocolSelected], with
 * [raceEnded], [altSvcUsed], [fallback] and [retry] where they apply) and [connectionAcquired], and finally [callEnd] or
 * [callFailed]; [connectionReleased] follows when the call's response is done with.
 *
 * Callbacks run on the call's coroutine (or, for releases, where the response body ends) and must return quickly without
 * blocking; an exception out of one (a CancellationException included) is logged at [LogLevel.Warn] through the engine's
 * logger and otherwise ignored.
 */
@ExperimentalKuicksilverApi
public abstract class KuicksilverEventListener {
    /** The engine received [request]. */
    public open fun callStart(request: HttpRequestData) {}

    /** [request] got its response head ([status]) over [protocol]; the body may still be streaming. */
    public open fun callEnd(
        request: HttpRequestData,
        protocol: HttpProtocolVersion,
        status: Int,
    ) {}

    /** [request] failed with [cause] (after any fallback or retry). */
    public open fun callFailed(
        request: HttpRequestData,
        cause: Throwable,
    ) {}

    /** The engine sends [request] over [protocol] for [reason]. */
    public open fun protocolSelected(
        request: HttpRequestData,
        protocol: HttpProtocolVersion,
        reason: ProtocolReason,
    ) {}

    /**
     * HTTP/3 and HTTP/1.1 connection setups raced (docs/guide/ktor.md, "Racing and fallback"): [winner] won after HTTP/3's
     * [headStart]; [h3Failure] is why HTTP/3 lost when it failed rather than being slower.
     */
    public open fun raceEnded(
        request: HttpRequestData,
        winner: HttpProtocolVersion,
        headStart: Duration,
        h3Failure: Throwable?,
    ) {}

    /** [request] goes to the HTTP/3 alternative [alternative] (`host:port`) the origin announced with `Alt-Svc` (RFC 7838). */
    public open fun altSvcUsed(
        request: HttpRequestData,
        alternative: String,
    ) {}

    /** The engine marked [alternative] of [origin] broken: HTTP/3 failed there while HTTP/1.1 worked (RFC 7838 section 2.4). */
    public open fun altSvcMarkedBroken(
        origin: String,
        alternative: String,
    ) {}

    /** HTTP/3 failed for [request] with [cause] and the request goes again over HTTP/1.1. */
    public open fun fallback(
        request: HttpRequestData,
        cause: Throwable,
    ) {}

    /** [request] is sent again, attempt number [attempt] (2 and up), because of [cause]: a GOAWAY or a stale pooled connection. */
    public open fun retry(
        request: HttpRequestData,
        attempt: Int,
        cause: Throwable,
    ) {}

    /** [request] got a connection over [protocol]: an open or pooled one when [reused], else a new one. */
    public open fun connectionAcquired(
        request: HttpRequestData,
        protocol: HttpProtocolVersion,
        reused: Boolean,
    ) {}

    /** [request]'s exchange gave its connection back: [kept] when the connection stays open for the next request. */
    public open fun connectionReleased(
        request: HttpRequestData,
        protocol: HttpProtocolVersion,
        kept: Boolean,
    ) {}
}

/** Why the engine chose a protocol for a request ([KuicksilverEventListener.protocolSelected]). */
@ExperimentalKuicksilverApi
public enum class ProtocolReason {
    /** `Http3DiscoveryMode.H1Only` or `H3Only`. */
    Configuration,

    /** `http://`, or a proxy: HTTP/3 needs TLS and no proxy. */
    NotSecure,

    /** An HTTP/3 connection to the origin was already open. */
    ExistingConnection,

    /** The HTTP/3 and HTTP/1.1 connection setups raced and this one won. */
    Race,

    /** `Auto` without a known HTTP/3 alternative: HTTP/1.1, learning `Alt-Svc` from the response. */
    NoAlternative,

    /** The alternative is marked broken on this network. */
    BrokenAlternative,

    /** A WebSocket to an origin without an HTTP/3 connection that allows Extended CONNECT (RFC 9220) starts on HTTP/1.1. */
    WebSocket,

    /** HTTP/3 failed for this request; it is repeated on HTTP/1.1. */
    Fallback,
}

/** The engine's [KuicksilverEventListener], never failing the call (an exception is logged); a no-op without one. */
@OptIn(ExperimentalKuicksilverApi::class)
internal class EngineEvents(
    val listener: KuicksilverEventListener?,
    val logger: KuicksilverLogger,
) {
    val enabled: Boolean get() = listener != null

    inline fun emit(
        what: String,
        call: KuicksilverEventListener.() -> Unit,
    ) {
        val l = listener ?: return
        try {
            l.call()
        } catch (e: Throwable) {
            // a CancellationException too: the callbacks are not suspending, so it is the listener's bug, not the call's cancellation
            runCatching { if (logger.isEnabled(LogLevel.Warn)) logger.log(LogLevel.Warn, "event listener failed in $what", e) }
        }
    }
}
