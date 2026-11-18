// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalAtomicApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * One QUIC server handshake's answer from [TlsConfig.sniSelector], made by [QuicTlsSession.selectSni] off the connection loop
 * and handed back to [QuicTlsSession.resumeSni] on it. It holds the native configuration built for the chosen identity:
 * [close] releases it when the selection is never resumed (the connection ended meanwhile); [QuicTlsSession.resumeSni] takes
 * it over, and closes it on every path.
 *
 * @property serverName the ClientHello's server name the selection was made for (RFC 6066 section 3; unverified input), null
 *   when it carried none.
 */
public class SniSelection internal constructor(
    internal val session: Any,
    public val serverName: String?,
    lease: KslContext.Lease?,
    internal val override: ServerTlsOverride?,
    /** The TLS alert that ends the handshake instead (`unrecognized_name`, `missing_extension`, `internal_error`), 0 for none. */
    internal val alert: Int,
    /**
     * Why the handshake ends with `alert`: its message is generic (a QUIC transport sends it to the client as the
     * CONNECTION_CLOSE reason phrase), the selector's own exception or the override's [TlsException.Config] is its cause.
     */
    internal val failure: TlsException?,
) : AutoCloseable {
    private val held = AtomicReference(lease)

    /** True once the chosen identity's configuration was released by [close] or taken over by [QuicTlsSession.resumeSni]. */
    @InternalKuicksilverApi
    public val isConsumed: Boolean get() = held.load() == null

    /** The configuration of the chosen identity, taken once (null afterwards, and for no override). */
    internal fun take(): KslContext.Lease? = held.exchange(null)

    /** Releases the chosen identity's native configuration unless [QuicTlsSession.resumeSni] took it; idempotent. */
    override fun close() {
        held.exchange(null)?.close()
    }
}

/**
 * Server: the server_name of the ClientHello the configuration's `sniSelector` chose this session's identity and settings
 * for (RFC 6066 section 3; unverified input), null when it carried none, no selector ran, or the session is not the
 * OpenSSL-backed one. The server engine holds requests on the connection to that name (RFC 9110 section 7.4), as over TCP
 * (`TlsConnection.sniSelectedFor`).
 */
@InternalKuicksilverApi
public val QuicTlsSession.sniSelectedFor: String? get() = (this as? KslQuicTlsSession)?.sniSelectedName

/** What a server does once its `sniSelector` answered `override` for `hello` (TCP and QUIC alike). */
internal sealed interface SniVerdict {
    /** The handshake goes on under `override`. */
    class Override(
        val override: ServerTlsOverride,
    ) : SniVerdict

    /** The handshake goes on under the configuration's own identity. */
    object Default : SniVerdict

    /** The handshake ends with TLS alert `alert`. */
    class Refuse(
        val alert: Int,
        val reason: String,
    ) : SniVerdict
}

/**
 * The server's rule for the selector's answer. An override is used. No override with a server name: RFC 6066 section 3 lets a
 * server that "does not recognize the server name" either abort with a fatal `unrecognized_name(112)` or go on; `null` from
 * the selector is that refusal. No override and no server name: the configuration's own [TlsConfig.identity]; a
 * configuration without one cannot answer a ClientHello that names no server, and RFC 9846 section 9.2 says "Servers
 * requiring this extension SHOULD respond to a ClientHello lacking a "server_name" extension by terminating the connection
 * with a "missing_extension" alert" (109).
 */
internal fun TlsConfig.sniVerdict(
    hello: ClientHelloInfo,
    override: ServerTlsOverride?,
): SniVerdict =
    when {
        override != null -> SniVerdict.Override(override)
        hello.serverName != null -> SniVerdict.Refuse(ALERT_UNRECOGNIZED_NAME, "unrecognized_name")
        identity == null -> SniVerdict.Refuse(ALERT_MISSING_EXTENSION, "missing_extension: no server_name")
        else -> SniVerdict.Default
    }

/**
 * [sniVerdict] for a TLS-over-TCP handshake. RFC 9114 section 3.1: `h3` identifies HTTP/3 over QUIC, so TLS over TCP never
 * negotiates it: an override's ALPN list goes to the handshake without it. A list that names nothing else serves its name over
 * QUIC only, and the TCP handshake ends with `no_application_protocol` (RFC 7301 section 3.2), whatever the client offers;
 * an empty list stays "no ALPN" as in [TlsConfig.alpn]. Then [withoutAlpnVerdict] for the protocols in effect.
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
internal fun TlsConfig.sniVerdictOverTcp(
    hello: ClientHelloInfo,
    override: ServerTlsOverride?,
): SniVerdict {
    val verdict = sniVerdict(hello, override)
    if (verdict is SniVerdict.Refuse) return verdict
    if (verdict !is SniVerdict.Override) return withoutAlpnVerdict(hello, alpn, verdict)
    val o = verdict.override
    val alpn = o.alpn?.toList() ?: return withoutAlpnVerdict(hello, this.alpn, verdict) // copy first: the list checked is the one used
    val tcp = alpn.filter { it != ALPN_H3 }
    if (tcp.isEmpty() && alpn.isNotEmpty()) {
        return SniVerdict.Refuse(ALERT_NO_APPLICATION_PROTOCOL, "no_application_protocol: the name is served over QUIC only")
    }
    return withoutAlpnVerdict(hello, tcp, SniVerdict.Override(ServerTlsOverride(o.identity, tcp, o.clientAuth, o.trust, o.ocspStapling)))
}

/**
 * [verdict], unless the client sent no ALPN extension and [TlsConfig.alpnFallback], the protocol it then speaks, is not among
 * the non-empty [inEffect] of its connection: then `no_application_protocol` (RFC 7301 section 3.2; RFC 9113 section 3.3:
 * "HTTP/2 connections over TLS MUST use protocol negotiation in TLS", so a client without ALPN can only speak the fallback).
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
internal fun TlsConfig.withoutAlpnVerdict(
    hello: ClientHelloInfo,
    inEffect: List<String>,
    verdict: SniVerdict,
): SniVerdict {
    val fallback = alpnFallback ?: return verdict
    if (hello.alpn.isNotEmpty() || inEffect.isEmpty() || fallback in inEffect) return verdict
    return SniVerdict.Refuse(
        ALERT_NO_APPLICATION_PROTOCOL,
        "no_application_protocol: the client sent no ALPN, and $fallback is not offered",
    )
}

/**
 * Whether a TLS-over-TCP server must pause at the ClientHello without an sniSelector: its [TlsConfig.alpnFallback] is missing
 * from its non-empty [TlsConfig.alpn], so a client without ALPN is refused ([withoutAlpnVerdict]). Never for an override's
 * configuration, applied once the base configuration's pause was decided.
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
internal val TlsConfig.pausesForAlpnFallback: Boolean
    get() = !isOverride && alpnFallback.let { it != null && alpn.isNotEmpty() && it !in alpn }

/** The ALPN protocol ID of HTTP/3 (RFC 9114 section 3.1), defined for QUIC only. */
internal const val ALPN_H3 = "h3"

/** TLS alerts of the SNI decision (RFC 9846 section 6; RFC 7301 section 3.2). */
internal const val ALERT_UNRECOGNIZED_NAME = 112
internal const val ALERT_MISSING_EXTENSION = 109
internal const val ALERT_INTERNAL_ERROR = 80
internal const val ALERT_NO_APPLICATION_PROTOCOL = 120

/**
 * The server configurations a base configuration's selector answers lead to, kept so that the next handshake with the same
 * answer gets the same [TlsConfig] object and so the native context its identity's registry already holds
 * ([KslContext.acquire], [SharedServerContexts], which keeps these apart from the base configuration's own contexts): building
 * one cost about 60 µs, an eighth of a QUIC handshake. An answer is the same when it names the same identity, trust and staple
 * objects and equal ALPN and client-certificate settings, so a selector should hand out the same `TrustConfig` and
 * `OcspStapling` objects for a name (a new one per call is a new answer); a `TlsIdentity.Reloadable` stays one key, and the
 * registry gives each of its snapshots its own context, so a reload reaches the next handshake as without the cache. At most
 * [MAX] answers are kept, the least recently used going first: a hit in the older half moves its entry to the young end (best
 * effort under contention, as [SharedServerContexts]), so a hot set of answers stays while others come and go.
 */
internal class OverrideConfigs {
    private class Key(
        val identity: TlsIdentity,
        val alpn: List<String>?,
        val clientAuth: ClientAuth?,
        val trust: TrustConfig?,
        val ocsp: Any?,
    ) {
        override fun equals(other: Any?): Boolean =
            other is Key && other.identity === identity && other.alpn == alpn && other.clientAuth == clientAuth &&
                other.trust === trust && other.ocsp === ocsp

        override fun hashCode(): Int = ((identity.hashCode() * 31 + (alpn?.hashCode() ?: 0)) * 31 + (clientAuth?.hashCode() ?: 0)) * 31
    }

    private class Entry(
        val key: Key,
        val config: TlsConfig,
    )

    // oldest first
    private val entries = AtomicReference<List<Entry>>(emptyList())

    /** Entries kept now (tests). */
    val size: Int get() = entries.load().size

    /** [base] with [o] applied ([TlsConfig.withOverride]), the one made before for an equal answer. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    fun of(
        base: TlsConfig,
        o: ServerTlsOverride,
    ): TlsConfig {
        val key = Key(o.identity, o.alpn?.toList(), o.clientAuth, o.trust, o.ocspStapling)
        val first = entries.load()
        val i = first.indexOfFirst { it.key == key }
        if (i >= 0) {
            val hit = first[i]
            if (i < first.size / 2) entries.compareAndSet(first, first.filter { it !== hit } + hit)
            return hit.config
        }
        val made = base.withOverride(o) // throws for an override build() would refuse: nothing is kept then
        while (true) {
            val list = entries.load()
            list.firstOrNull { it.key == key }?.let { return it.config }
            val grown = list + Entry(key, made)
            if (entries.compareAndSet(list, if (grown.size > MAX) grown.drop(1) else grown)) return made
        }
    }

    companion object {
        const val MAX = 64
    }
}
