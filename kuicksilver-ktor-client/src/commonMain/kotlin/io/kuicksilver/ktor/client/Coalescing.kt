// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.HttpRequestData
import io.ktor.http.isSecure
import io.ktor.util.AttributeKey
import io.kuicksilver.ktor.client.h1.SpinLock
import io.kuicksilver.ktor.client.h3.Destination
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.HostName
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyReason
import io.kuicksilver.tls.VerifyResult
import io.kuicksilver.tls.verifyForReuse
import kotlinx.coroutines.CancellationException

/**
 * Set on a request whose coalesced attempt got 421 (Misdirected Request): its repeat, and any later attempt of the call, goes
 * on a connection of its own origin only (RFC 9110 section 15.5.20: "over a different connection, such as a fresh
 * connection specific to the target resource's origin"). The engine removes it at the start of each call.
 */
internal val NoCoalescingKey: AttributeKey<Unit> = AttributeKey("io.kuicksilver.ktor.client.NoCoalescing")

/**
 * Whether [data] may go on a connection of another origin at all (`connectionCoalescing`, ADR-0018): turned on, a trust
 * that names the origin's host ([coalescingTrust]), an `https` request, no WebSocket (its handshake takes a connection of
 * its own origin, over any protocol), no proxy (a connection through one is never shared, and one to a proxy carries every
 * origin anyway, RFC 9113 section 9.1.1), and not the repeat of a coalesced attempt that got 421 ([NoCoalescingKey]).
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.ktor.utils.io.InternalAPI::class)
internal fun KuicksilverEngineConfig.mayCoalesce(
    data: HttpRequestData,
    viaProxy: Boolean,
): Boolean =
    connectionCoalescing && coalescingTrust(trust) && !viaProxy && data.url.protocol.isSecure() &&
        !data.attributes.contains(io.ktor.client.plugins.websocket.WEBSOCKETS_KEY) &&
        !data.attributes.contains(NoCoalescingKey)

/**
 * Whether [trust] lets a connection speak for another origin. Not under [TrustConfig.Tofu]: a key is remembered for a name
 * only from a handshake with that name, so another origin's connection would be a first contact taken from someone else's
 * handshake. Not under [TrustConfig.ExpectedName] (also as the base of a `Pinned`): the certificate is checked against a
 * configured name, not the host, while RFC 9110 section 4.3.3 attributes authority over another connection only "if the URI
 * origin's host matches any of the hosts present in the server's certificate".
 */
internal fun coalescingTrust(trust: TrustConfig): Boolean {
    val base = (trust as? TrustConfig.Pinned)?.base ?: trust
    return base !is TrustConfig.Tofu && base !is TrustConfig.ExpectedName
}

/** What [checkCoalescing] decided for one request. */
internal enum class Coalesce {
    /** The connection may carry the request. */
    Yes,

    /** It may not (another address, a certificate that does not pass for the host, a 421 earlier); it stays as it is. */
    No,

    /**
     * It may not, and the certificate does not pass for the connection's own origin either any more (expired, revoked, a
     * stale staple, an anchor no longer trusted): it takes no new request (RFC 9114 section 3.3: "If the reason the
     * certificate cannot be verified might apply to other origins already associated with the connection, the client SHOULD
     * revalidate the server certificate for those origins"). Its requests in flight finish; the next ones of every origin set
     * up a new connection, whose handshake verifies the certificate again.
     */
    Retire,
}

/**
 * What one connection knows of the origins it was checked for (by host, normalized as a reference identifier: case and a
 * trailing dot do not make another host; the port is the connection's): accepted (its certificate passed every check for the
 * host, [io.kuicksilver.tls.verifyForReuse]) or refused (it did not, or the server answered 421 to a request of that
 * host). At most [MAX] hosts, the oldest forgotten first (then checked again); a refusal is never forgotten.
 */
internal class CoalescedHosts {
    private val lock = SpinLock()
    private val verdicts = LinkedHashMap<String, Boolean>()

    /**
     * Hosts refused on the connection (a failed check, a 421): kept apart from the acceptances' bound, so they stay refused
     * for good; at most [MAX_REFUSED], past which the connection refuses every host it holds no acceptance for
     * ([refusesNew]): a refusal is never forgotten, and the set never grows without bound.
     */
    private val refused = HashSet<String>()

    /** More hosts were refused than [refused] keeps: any host without an acceptance is refused. */
    private var refusesNew = false

    private var everAccepted = false

    private var retireLogged = false

    fun verdict(host: String): Boolean? {
        val k = key(host)
        return lock.withLock {
            when {
                k in refused -> false
                else -> verdicts[k] ?: if (refusesNew) false else null
            }
        }
    }

    /** True the first time only: the connection's retirement is logged once, whatever the requests that found it. */
    fun firstRetire(): Boolean =
        lock.withLock {
            if (retireLogged) return@withLock false
            retireLogged = true
            true
        }

    /**
     * Whether the connection was ever found fit for another origin: it may have carried requests of more origins than its
     * own (sticky, whatever the bound forgot since).
     */
    fun anyAccepted(): Boolean = lock.withLock { everAccepted }

    fun record(
        host: String,
        accepted: Boolean,
    ) {
        val k = key(host)
        lock.withLock {
            // a refusal is final for the connection: an acceptance racing with a 421 never undoes it
            if (!accepted) {
                verdicts.remove(k)
                if (refused.size < MAX_REFUSED) refused += k else refusesNew = true
                return@withLock
            }
            if (refusesNew && k !in verdicts) return@withLock
            if (k in refused) return@withLock
            everAccepted = true
            verdicts.remove(k)
            verdicts[k] = true
            verdicts.evictEldest(MAX)
        }
    }

    private fun key(host: String): String =
        try {
            HostName.normalize(host).value
        } catch (_: Throwable) {
            host.lowercase()
        }

    internal companion object {
        const val MAX = 256
        const val MAX_REFUSED = 4096
    }
}

/**
 * A connection that may carry other origins: where it is connected to ([remote], the literal its race won with), the host it
 * was set up for ([ownHost]), what its server presented ([chain]: a resumed connection's is its full handshake's) and
 * stapled ([stapleUntil]), whether its Encrypted Client Hello was accepted ([echAccepted]), and its verdicts ([hosts]).
 */
internal class CoalescingPeer(
    val ownHost: String,
    val remote: Destination,
    val chain: List<Certificate>,
    val stapleUntil: Long,
    val echAccepted: Boolean,
    val hosts: CoalescedHosts,
)

/**
 * Whether [peer] may carry a request for `https://[host]` that would connect to [lookupHost] and [port], for ALPN [alpn]
 * (ADR-0018). Both conditions of RFC 9113 section 9.1.1 and RFC 9114 section 3.3, by RFC 9110 section 4.3.3 ("a client will
 * attribute authority to a server when they are communicating over a successfully established and secured connection if
 * the URI origin's host matches any of the hosts present in the server's certificate and the client believes that it could
 * open a connection to that host for that URI. In practice, a client will make a DNS query to check that the origin's host
 * contains the same server IP address as the established connection"):
 *
 * - **the address**, every time: [lookupHost]'s current answers ([RequestDns.answeredDestinations], the NAT64 synthesis
 *   included) contain the connection's address and port. An answer that changed takes the next request elsewhere.
 * - **the certificate**, once per connection and host: the chain passes every check a new connection to [host] would make
 *   ([io.kuicksilver.tls.verifyForReuse] with [host]'s TLS configuration: trust, pins, name, validity, level, the staple's
 *   freshness; RFC 9113 section 9.1.1: "MUST satisfy any checks that the client would perform when forming a new TLS
 *   connection for the host in the URI"), as the handshake's own check holds for the connection's first origin as long as it
 *   lives. The host's name is hidden from the verifier's network requests (RFC 9849 section 10.7) when the connection's ECH
 *   was accepted or a new connection to the host would offer ECH. A refusal is remembered for the connection, and so is a
 *   421 ([CoalescedHosts.record]).
 *
 * A refusal for any reason but the name is checked against the connection's own origin too ([CoalescingPeer.ownHost], its
 * name hidden as for the new host): when that fails as well, the decision is [Coalesce.Retire], and [onRetire] gets the own
 * origin's reason and the new host's, once per connection (the audit log RFC 9110 section 4.3.4 asks automated clients for);
 * when it passes, the reason was the new host's alone (its verifier, its pins) and the
 * connection stays. A lookup or a verifier that fails decides No (the request takes a connection of its own, which
 * reports the failure).
 */
internal suspend fun KuicksilverEngineConfig.checkCoalescing(
    peer: CoalescingPeer,
    host: String,
    port: Int,
    dns: RequestDns,
    alpn: List<String>,
    lookupHost: String = host,
    onRetire: (own: VerifyReason, forHost: VerifyReason) -> Unit = { _, _ -> },
): Coalesce {
    val hosts = peer.hosts
    if (peer.chain.isEmpty() || !coalescingTrust(trust) || hosts.verdict(host) == false) return Coalesce.No
    try {
        if (dns.answeredDestinations(lookupHost, port).none { Destination.of(it).sameAs(peer.remote) }) return Coalesce.No
        if (hosts.verdict(host) == true) return Coalesce.Yes
        val hidden =
            peer.echAccepted || dns
                .echRoute(host) { ech.listFor(it) }
                .offer.list
                ?.isUsable == true
        return when (val v = tlsConfigFor(host, alpn).verifyForReuse(peer.chain, peer.stapleUntil, hidden)) {
            is VerifyResult.Accepted -> {
                hosts.record(host, accepted = true)
                // a 421 recorded while the check ran wins
                if (hosts.verdict(host) == true) Coalesce.Yes else Coalesce.No
            }

            is VerifyResult.Rejected -> {
                hosts.record(host, accepted = false)
                // a certificate that names other hosts but not this one says nothing about the origins it does name; any other
                // reason may hold for the connection's own origin, which is asked again
                if (v.reason is VerifyReason.HostnameMismatch) return Coalesce.No
                val ownHidden =
                    peer.echAccepted || dns
                        .echRoute(peer.ownHost) { ech.listFor(it) }
                        .offer.list
                        ?.isUsable == true
                when (val own = tlsConfigFor(peer.ownHost, alpn).verifyForReuse(peer.chain, peer.stapleUntil, ownHidden)) {
                    is VerifyResult.Accepted -> {
                        Coalesce.No
                    }

                    is VerifyResult.Rejected -> {
                        // logged once per connection: the reason it is retired (its own origin's), and what the new host met
                        if (hosts.firstRetire()) onRetire(own.reason, v.reason)
                        Coalesce.Retire
                    }
                }
            }
        }
    } catch (e: CancellationException) {
        throw e
    } catch (_: Throwable) {
        return Coalesce.No
    }
}

/**
 * The audit line of a retired connection (RFC 9110 section 4.3.4: "Automated clients MUST log the error to an appropriate
 * audit log (if available)"), at Warn, once per connection: why the certificate no longer passes for the connection's own
 * origin [ownHost] (the reason it is retired) and what it met for [host]. The line names both hosts, which an audit needs;
 * an application that must keep host names out of its logs filters it in its `logger`. A logger that throws is ignored.
 */
internal fun EngineEvents.coalescingRetired(
    ownHost: String,
    host: String,
    own: VerifyReason,
    forHost: VerifyReason,
) {
    try {
        if (logger.isEnabled(LogLevel.Warn)) {
            logger.log(
                LogLevel.Warn,
                "connection coalescing: the certificate of the connection to $ownHost no longer passes for it ($own; for " +
                    "$host: $forHost); the connection takes no new requests",
            )
        }
    } catch (_: Throwable) {
        // a logger that fails never fails the call
    }
}
