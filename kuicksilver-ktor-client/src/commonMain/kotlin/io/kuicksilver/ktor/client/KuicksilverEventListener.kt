// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.HttpRequestData
import io.ktor.http.HttpProtocolVersion
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.MigrationEvent
import kotlin.time.Duration

/**
 * Hears what the client engine does with each call (docs/guide/ktor.md, "Observability"), in the manner of OkHttp's
 * `EventListener`: set it with `engine { eventListener = ... }`. Every method has an empty default; override the ones you
 * need. The order for one call is [callStart], then for each attempt the protocol decision ([protocolSelected], with
 * [raceEnded], [altSvcUsed], [fallback] and [retry] where they apply), the name lookups it makes ([dnsStart] and [dnsEnd],
 * before the connection they serve; usually none when the request reuses a pooled connection, except that a WebSocket's
 * keys are looked up before the pool is asked, and an HTTP/3 request whose origin has a connection under another name
 * (its host and an alternative) resolves first to decide whether to share it) and [connectionAcquired], and finally
 * [callEnd] or [callFailed]; [connectionReleased] follows when the call's response is done with.
 *
 * Callbacks run on the call's coroutine (or, for releases, where the response body ends) and must return quickly without
 * blocking. [dnsStart] and [dnsEnd] may run concurrently, on different threads, for one call: the two address families
 * are looked up at once, and the two sides of the HTTP/3 and TCP race too, so an implementation of them must be
 * thread-safe; an exception out of one (a CancellationException included) is logged at [LogLevel.Warn] through the engine's
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

    /**
     * [request] failed with [cause] (after any fallback or retry). The request's attributes still hold the call's
     * [ProtocolDiagnostics] here ([KuicksilverDiagnosticsKey]; the engine removes them once this returns), so
     * `request.attributes.getOrNull(KuicksilverDiagnosticsKey)` says which transport failed, as `cause.kuicksilverDiagnostics`
     * does where the exception is the call's own.
     */
    public open fun callFailed(
        request: HttpRequestData,
        cause: Throwable,
    ) {}

    /**
     * A connection setup for [request] failed ([ConnectFailure]): a TCP connect to one address, a proxy handshake, a TLS
     * handshake over TCP (`protocolSelected` only comes once a TCP connection is up, so this is where a failed one shows,
     * with its address), or a QUIC handshake with one address. Once per failed attempt, also when another attempt or the
     * other transport then served the call; never for an attempt the engine cancelled because another one won (the address
     * race, the HTTP/3 and TCP race). The connect timeout is reported: once per attempt it cut short, at its step, with the
     * call's `ConnectTimeoutException` as the cause, or once at what the time went to before any address was tried
     * ([ConnectStage.NameLookup], [ConnectStage.PoolWait], [ConnectStage.H2DialWait]). The same failures are in
     * [ProtocolDiagnostics.connectFailures]. May run concurrently with the call's other events, on another thread (the
     * address and transport races).
     *
     * With `http3 { earlyData }` a connection is handed out before its handshake completed; a handshake that fails after
     * that is reported when it fails, which can be after [callEnd] or [callFailed]: the request's attributes then no longer
     * hold the call's diagnostics, though the [ProtocolDiagnostics] object, where the application kept it (from the
     * response, or the exception), still gains the failure.
     */
    public open fun connectFailed(
        request: HttpRequestData,
        failure: ConnectFailure,
    ) {}

    /**
     * The engine sends [request] over [protocol] for [reason]. On the TCP path it comes once the connection is in hand,
     * with the protocol the server chose (`HTTP_2_0` when it picked `h2` in ALPN, else `HTTP_1_1`); before 0.3.0 it came
     * before connecting and always said `HTTP_1_1`. A repeat that changes the protocol (HTTP_1_1_REQUIRED) reports it again.
     */
    public open fun protocolSelected(
        request: HttpRequestData,
        protocol: HttpProtocolVersion,
        reason: ProtocolReason,
    ) {}

    /**
     * HTTP/3 and TCP connection setups raced (docs/guide/ktor.md, "Racing and fallback"): [winner] (`HTTP_3_0`, or the
     * TCP side's `HTTP_2_0` or `HTTP_1_1`) won after HTTP/3's
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

    /**
     * [request] connects to [alternative] (`host:port`), an endpoint of the origin's HTTPS resource record (RFC 9460,
     * [Http3ClientConfig.httpsRecords]), over the transports the record allows; once per endpoint tried. A QUIC failure
     * there marks it broken as for an `Alt-Svc` alternative ([altSvcMarkedBroken]).
     */
    public open fun httpsRecordUsed(
        request: HttpRequestData,
        alternative: String,
    ) {}

    /**
     * The engine marked [alternative] of [origin] broken (RFC 7838 section 2.4): HTTP/3 failed there while HTTP/1.1 worked,
     * or an HTTP/3 connection to it stalled (`FallbackReason.QuicStalled`, once per stalled connection).
     */
    public open fun altSvcMarkedBroken(
        origin: String,
        alternative: String,
    ) {}

    /** HTTP/3 failed for [request] with [cause] and the request goes again over TCP (HTTP/1.1, or HTTP/2 when the server offers it). */
    public open fun fallback(
        request: HttpRequestData,
        cause: Throwable,
    ) {}

    /**
     * [request] is sent again, attempt number [attempt] (2 and up), because of [cause]: a GOAWAY or REFUSED_STREAM (the
     * server did not process it), HTTP_1_1_REQUIRED over HTTP/2, a stale pooled connection, or a 417 to its
     * `Expect: 100-continue` (sent again without it).
     */
    public open fun retry(
        request: HttpRequestData,
        attempt: Int,
        cause: Throwable,
    ) {}

    /**
     * The engine starts a lookup of [host] for [request] (OkHttp's `dnsStart`): through the system's resolver or
     * `KuicksilverEngineConfig.dns`. [ipv6] is the address family asked for, IPv6 or IPv4: the system's resolver and a
     * [FamilyDns] are asked once per family (RFC 8305 section 3), often both at once; null when one lookup answers both (a
     * plain [Dns]). Each host and family is looked up once per request (again only after a lookup whose caller was cancelled),
     * so the h3/h1 race and a fallback share it.
     * No lookup, and no event, for an address literal, a host with the form of an IPv4 address, or the addresses an HTTPS
     * answer carried. [dnsEnd] follows once. May run concurrently with the call's other DNS events, on another thread.
     */
    public open fun dnsStart(
        request: HttpRequestData,
        host: String,
        ipv6: Boolean?,
    ) {}

    /**
     * The lookup [dnsStart] announced ended (OkHttp's `dnsEnd`, which has no failure; here also when it failed): [addresses]
     * are what the engine may connect to, after the destination check (no unspecified, multicast or broadcast address) and
     * before the RFC 6724 sort, empty when the name has none of that family; on a failure (a cancellation included)
     * [addresses] is empty and [failure] says why. On an IPv6-only network the IPv4 answers are synthesized later, so they
     * appear here as IPv4. May run concurrently with the call's other DNS events, on another thread.
     */
    public open fun dnsEnd(
        request: HttpRequestData,
        host: String,
        ipv6: Boolean?,
        addresses: List<IpAddress>,
        failure: Throwable?,
    ) {}

    /** [request] got a connection over [protocol]: an open or pooled one when [reused], else a new one. */
    public open fun connectionAcquired(
        request: HttpRequestData,
        protocol: HttpProtocolVersion,
        reused: Boolean,
    ) {}

    /**
     * [request]'s exchange gave its connection back: [kept] when the connection stays open for the next request. Follows
     * every [connectionAcquired] once, also when the exchange failed before a response (then usually not [kept]).
     */
    public open fun connectionReleased(
        request: HttpRequestData,
        protocol: HttpProtocolVersion,
        kept: Boolean,
    ) {}

    /**
     * A coroutine of [request]'s WebSocket session (the engine's or Ktor's reader or writer) failed with [cause]: the
     * session ends, and its connection (HTTP/1.1) or stream (HTTP/2, HTTP/3) is closed as for a failed call. The
     * application sees the end through the session's channels; this is where the failure itself is reported, also after
     * [callEnd] (the session may outlive its call while it writes its own Close). Runs on the session's coroutine.
     */
    public open fun webSocketFailed(
        request: HttpRequestData,
        cause: Throwable,
    ) {}

    /**
     * An HTTP/3 connection to [origin] (`https://host:port`) followed the network ([Http3ClientConfig.connectionMigration]):
     * [event] is what its [io.kuicksilver.quic.NetworkMigrator] did, a move to another network
     * ([MigrationEvent.Migrated]), a move that failed and left the connection where it was ([MigrationEvent.Failed]), a
     * lost network or a failed network source. Runs on the migrator's coroutine, not a call's.
     */
    public open fun connectionMigrated(
        origin: String,
        event: MigrationEvent<*>,
    ) {}
}

/** Why the engine chose a protocol for a request ([KuicksilverEventListener.protocolSelected]). */
@ExperimentalKuicksilverApi
public enum class ProtocolReason {
    /** `Http3DiscoveryMode.H1Only` or `H3Only`. */
    Configuration,

    /** `http://` (or `ws://`): HTTP/3 needs TLS. */
    NotSecure,

    /** An HTTP/3 connection to the origin was already open. */
    ExistingConnection,

    /** The HTTP/3 and TCP connection setups raced and this one won. */
    Race,

    /** `Auto` without a known HTTP/3 alternative: TCP (HTTP/1.1 or HTTP/2), learning `Alt-Svc` from the response. */
    NoAlternative,

    /** The alternative is marked broken on this network. */
    BrokenAlternative,

    /**
     * A WebSocket to an origin without an HTTP/3 connection that allows Extended CONNECT (RFC 9220) goes over TCP: on an
     * HTTP/2 connection there already that allows it (RFC 8441), else on HTTP/1.1.
     */
    WebSocket,

    /** HTTP/3 failed for this request; it is repeated over TCP. */
    Fallback,

    /** A proxy applies to the request: TCP through it (QUIC's UDP does not go through HTTP CONNECT or SOCKS5 CONNECT). */
    Proxy,

    /** `Http3ClientConfig.http3Allowed` returned false for this request: TCP (HTTP/1.1 or HTTP/2), as with `H1Only`. */
    Http3Disabled,

    /**
     * An endpoint of the origin's HTTPS record (RFC 9460) that offers one transport only: TCP, or HTTP/3 without TCP
     * (`no-default-alpn`), so there was no race.
     */
    HttpsRecord,
}

/** The engine's [KuicksilverEventListener], never failing the call (an exception is logged); a no-op without one. */
@OptIn(ExperimentalKuicksilverApi::class)
internal class EngineEvents(
    val listener: KuicksilverEventListener?,
    val logger: KuicksilverLogger,
) {
    val enabled: Boolean get() = listener != null

    /**
     * A connection setup of [request] failed: [f] goes into the call's diagnostics ([ProtocolDiagnostics.connectFailures])
     * and to the listener. A cancellation is no failure and is dropped here.
     */
    fun connectFailed(
        request: io.ktor.client.request.HttpRequestData,
        f: ConnectFailure,
    ) {
        if (f.cause is kotlin.coroutines.cancellation.CancellationException) return
        request.attributes.getOrNull(KuicksilverDiagnosticsKey)?.connectFailed(f)
        emit("connectFailed") { connectFailed(request, f) }
    }

    /** The DNS events of [request]'s lookups ([DnsObserver]); null without a listener. */
    fun dnsObserver(request: io.ktor.client.request.HttpRequestData): DnsObserver? = if (enabled) DnsObserver(this, request) else null

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
