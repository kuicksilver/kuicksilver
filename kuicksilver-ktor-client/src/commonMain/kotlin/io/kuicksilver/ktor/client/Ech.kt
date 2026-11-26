// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.KuicksilverDsl
import io.kuicksilver.ktor.client.dns.HttpsEndpoint
import io.kuicksilver.tls.EchConfigList
import io.kuicksilver.tls.TlsException
import kotlinx.coroutines.CancellationException
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * Encrypted Client Hello of the client engine (RFC 9849; docs/guide/ktor.md, "Encrypted Client Hello"); change it with
 * `tls { ech { } }` ([ClientTlsConfig.ech]). The configuration a connection offers comes from, in this order: the `ech` parameter of
 * the HTTPS record whose endpoint it goes to ([fromHttpsRecords], RFC 9848), the [configLists] entry of the request's host,
 * else none, and then GREASE ECH ([grease]). Over TCP and QUIC alike; a connection that offers a configuration is TLS 1.3
 * only, whatever `tls { versions }` says (RFC 9849 section 6.1), so a server with TLS 1.2 alone fails it.
 */
@KuicksilverDsl
@ExperimentalKuicksilverApi
public class EchClientConfig {
    /**
     * ECHConfigLists given out of band, by the request's host, compared as host names (without case, a trailing dot or the
     * brackets of an IPv6 literal; two keys for one host fail the engine's creation): every connection for that origin
     * offers it (directly, to an `Alt-Svc` alternative, and inside a proxy's CONNECT, SOCKS5 or CONNECT-UDP tunnel), unless
     * an HTTPS record's endpoint brings its own; those connections are TLS 1.3 only (ECH is TLS 1.3, RFC 9849
     * section 6.1), also under the default `tls { versions = Tls12And13 }`, so a server of the host that has TLS 1.2 alone fails
     * the request instead of getting the name in the clear. Empty by default. The engine refuses an entry when the list
     * holds no usable ECHConfig and in a build without ECH, with IllegalArgumentException when it is created (each with its
     * own message): a list
     * given here never turns into GREASE with the host's name in the clear. An HTTPS record's `ech` without a usable
     * ECHConfig is different: the connection sends GREASE then, as RFC 9849 section 6.1 allows.
     *
     * The engine builds each entry's client configuration when it is created, for the check: a `TlsException.Config` from
     * that build becomes the entry's IllegalArgumentException (its message names the host).
     */
    public var configLists: Map<String, EchConfigList> = emptyMap()

    /**
     * The [configLists] entry of [host], the keys compared as host names: without case, a trailing dot or the brackets of
     * an IPv6 literal.
     */
    internal fun listFor(host: String): EchConfigList? {
        val key = echHostKey(host)
        return configLists.entries.firstOrNull { echHostKey(it.key) == key }?.value
    }

    /**
     * Send a GREASE `encrypted_client_hello` extension on every TLS connection that offers no configuration (RFC 9849
     * section 6.2.1, SHOULD), so that connections with ECH do not stand out; default true. The server's answer to it is
     * checked and ignored.
     */
    public var grease: Boolean = true

    /**
     * Use the `ech` parameter of the origin's HTTPS records (RFC 9848; [ClientNetworkConfig.httpsRecords] must look them
     * up, which happens in [Http3Discovery.Auto]); default true. Then, as RFC 9848 requires of a client that supports ECH:
     * no ClientHello goes out before the origin's SVCB resolution completed (section 5.3, MUST; within the connect timeout,
     * a resolution that fails counting as no records), and when every endpoint of the records has an `ech` parameter the
     * request never falls back to a connection without them (section 5.1, SVCB-reliant), so a failure is reported instead.
     * A connection that offers a record's configuration is TLS 1.3 only, whatever `tls { versions }` says.
     */
    public var fromHttpsRecords: Boolean = true
}

/**
 * What one connection of a request offers for ECH, and the one retry RFC 9849 section 6.1.6 asks for after a rejection,
 * shared by every connection the request makes to the same endpoint (the QUIC and TCP sides of a race, a fallback):
 * a rejection with retry configurations makes them the offer of the next connection ("SHOULD retry the handshake with a
 * new transport connection using the retry configurations"), a rejection without usable ones disables ECH for it
 * ("securely disabled ... SHOULD retry the handshake with a new transport connection and ECH disabled"), and a connection
 * that already was such a retry is not retried again ("Clients SHOULD NOT accept "retry_config" in response to a
 * connection initiated in response to a "retry_config""). Nothing outlives the request (section 6.1.8 is a MAY).
 */
@OptIn(ExperimentalAtomicApi::class, ExperimentalKuicksilverApi::class)
internal class EchRoute(
    initial: EchConfigList?,
) {
    /** One offer: [list] (null: none, GREASE as configured), [retry] whether it answers a rejection. */
    class Offer(
        val list: EchConfigList?,
        val retry: Boolean,
    )

    private val state = AtomicReference(Offer(initial?.takeIf { it.isUsable }, retry = false))

    /** What the next connection offers. */
    val offer: Offer get() = state.load()

    /**
     * A connection that offered [used] ended with [rejected]: the offer of the retry, or null when no retry follows (that
     * connection was a retry already). A sibling connection rejected first has set the retry's offer: it is taken as is,
     * so the request makes one retry per connection, never a chain.
     */
    fun rejected(
        used: Offer,
        rejected: TlsException.EchRejected,
    ): Offer? {
        if (used.retry) return null
        val next = Offer(rejected.retryConfigs?.takeIf { it.isUsable }, retry = true)
        if (state.compareAndSet(used, next)) return next
        return state.load().takeIf { it !== used }
    }
}

/**
 * The ECH routes of one request's HTTPS record endpoints ([of]): one per target and `ech` value, so the QUIC and TCP sides
 * of one record share a route (one retry for both), while two records for the same host and port with different `ech`
 * values each offer their own configuration. Used by one request's coroutine only.
 */
internal class EchRoutesOfEndpoints {
    private val routes = HashMap<String, EchRoute>()

    /** The route of [e], made on first use; null for an endpoint without `ech`. */
    fun of(e: HttpsEndpoint?): EchRoute? {
        val bytes = e?.ech ?: return null
        val key = "${e.host}:${e.port}|${kotlin.io.encoding.Base64.encode(bytes)}"
        return routes.getOrPut(key) { EchRoute(parsedEch(bytes)) }
    }
}

/**
 * The ECH rejection in [e]'s causes (a QUIC connection closes with it as the cause, `CRYPTO_ERROR` 0x179), or null. One
 * under a [ProxyTlsException] is the proxy hop's, never the origin's: it is not looked for there.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal fun echRejectionIn(e: Throwable?): TlsException.EchRejected? {
    var c = e
    var depth = 0
    while (c != null && depth++ < 16) {
        if (c is TlsException.EchRejected) return c
        if (c is ProxyTlsException) return null
        c = c.cause
    }
    return null
}

/**
 * [connect] with [route]'s offer, and once more with the retry's offer when the server rejected ECH (RFC 9849 section
 * 6.1.6), to the addresses of the request's resolution, which the section allows ("clients can reuse the same server IP
 * address"), never to one a new lookup returned: over HTTP/3 [connect] goes to the address the rejected connection went
 * to, over TCP it races those addresses again. A second rejection, or one without a retry, is the failure.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal suspend fun <T> withEchRetry(
    route: EchRoute,
    connect: suspend (EchRoute.Offer) -> T,
): T {
    val first = route.offer
    try {
        return connect(first)
    } catch (e: CancellationException) {
        throw e
    } catch (e: Throwable) {
        val rejected = echRejectionIn(e) ?: throw e
        val retry = route.rejected(first, rejected) ?: throw e
        return connect(retry)
    }
}

/** [host] as [EchClientConfig.configLists] compares it. */
internal fun echHostKey(host: String): String =
    host
        .lowercase()
        .removeSuffix(".")
        .removePrefix("[")
        .removeSuffix("]")
