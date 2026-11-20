// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.connectudp.SystemResolver
import io.kuicksilver.http3.connectudp.UdpProxyImpl
import io.kuicksilver.http3.connectudp.connectUdpTunnel
import io.kuicksilver.http3.message.UdpAddressClass
import io.kuicksilver.http3.message.UdpUriTemplate
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.DatagramSendResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/** Constants of CONNECT-UDP, Proxying UDP in HTTP (RFC 9298). */
@ExperimentalKuicksilverApi
public object ConnectUdp {
    /** The HTTP Upgrade Token, sent as `:protocol` of an Extended CONNECT (RFC 9298 section 3.4). */
    public const val PROTOCOL: String = "connect-udp"

    /**
     * The path and query of the default template, `/.well-known/masque/udp/{target_host}/{target_port}/` (RFC 9298
     * section 2: "UDP proxy deployments SHOULD offer service at this location if they need to interoperate with such
     * clients").
     */
    public const val WELL_KNOWN_PATH: String = UdpUriTemplate.WELL_KNOWN_PATH

    /** The longest UDP payload an HTTP datagram may carry with Context ID 0 (RFC 9298 section 5): 65527 bytes. */
    public const val MAX_UDP_PAYLOAD: Int = 65_527

    /** Whether [request] asks for a UDP tunnel: an Extended CONNECT whose `:protocol` is `connect-udp`, in any case (RFC 9110 section 7.8). */
    public fun isConnectUdp(request: Http3ServerRequest): Boolean =
        request.method == "CONNECT" && request.protocol.equals(PROTOCOL, ignoreCase = true)
}

/**
 * The URI Template a client is configured with to reach a UDP proxy (RFC 9298 section 2), such as
 * `https://proxy.example:4443/masque{?target_host,target_port}`. [parse] checks every requirement of section 2 and refuses
 * the template otherwise ("the client MUST reject its configuration and abort the request without sending it").
 *
 * @property template the template as given.
 * @property scheme the scheme, sent as `:scheme`.
 * @property authority the proxy's authority, sent as `:authority`.
 */
@ExperimentalKuicksilverApi
public class UdpProxyTemplate private constructor(
    internal val parsed: UdpUriTemplate,
) {
    public val template: String get() = parsed.text
    public val scheme: String get() = parsed.scheme!!
    public val authority: String get() = parsed.authority!!

    /**
     * The URI of the UDP proxying request for [targetHost] (an IPv4 or IPv6 literal, with or without brackets, or a DNS
     * host name; no IPv6 zone) and [targetPort] (1..65535): RFC 6570 expansion, so an IPv6 literal's colons come out as
     * `%3A` (RFC 9298 section 3). Throws [IllegalArgumentException] for an invalid target.
     */
    public fun expand(
        targetHost: String,
        targetPort: Int,
    ): String {
        val e = parsed.expand(targetHost, targetPort)
        return "${e.scheme}://${e.authority}${e.pathAndQuery}"
    }

    /** The template. */
    override fun toString(): String = template

    /** Parsing a template. */
    public companion object {
        /**
         * Parses [template] and checks it against RFC 9298 section 2: level 3 or lower; absolute with a non-empty scheme,
         * authority and a path starting with `/`; variables only in the path and query; both `target_host` and
         * `target_port`; only ASCII 0x21-0x7E; none of the `+`, `#`, `.`, `/`, `;` operators. Also refused: userinfo in the
         * authority (RFC 9114 section 4.3.1) and a fragment. Throws [IllegalArgumentException] naming the broken rule.
         */
        public fun parse(template: String): UdpProxyTemplate = UdpProxyTemplate(UdpUriTemplate.parseAbsolute(template))

        /**
         * The default template of RFC 9298 section 2 for a proxy known only by its host and port:
         * `https://[authority]/.well-known/masque/udp/{target_host}/{target_port}/`, [authority] being `host` or `host:port`
         * (an IPv6 literal in brackets).
         */
        public fun wellKnown(authority: String): UdpProxyTemplate = UdpProxyTemplate(UdpUriTemplate.wellKnown(authority))
    }
}

/**
 * A UDP tunnel through a proxy (RFC 9298), from [Http3Connection.connectUdp]: UDP payloads to and from one target, carried
 * as HTTP datagrams with Context ID 0 (section 5), as QUIC DATAGRAM frames when both sides negotiated HTTP/3 datagrams and
 * as DATAGRAM capsules otherwise (RFC 9297 section 3.5). Like UDP, delivery is not guaranteed: datagrams that do not fit
 * the connection to the proxy are refused (`TooLarge`), and the proxy may drop what its own link cannot carry.
 *
 * The tunnel lives as long as its request stream: [close] ends it; the proxy ends it when its socket fails or after a
 * period without traffic (two minutes at least, section 3.1), and [payloads] then completes.
 */
@ExperimentalKuicksilverApi
public interface UdpTunnel {
    /** The target as the request named it: an IP literal (IPv6 without brackets) or a DNS name the proxy resolved. */
    public val targetHost: String

    /** The target's UDP port. */
    public val targetPort: Int

    /** The request stream speaking the Capsule Protocol, for its headers, priority, `reset` and the capsules of extensions. */
    public val stream: CapsuleStream

    /**
     * UDP payloads from the target, in the order they arrived; datagrams with another Context ID are dropped (RFC 9298
     * section 4) and counted in [droppedDatagrams]. Keeps the newest 64 nobody collected. One collector at a time; it
     * completes when the proxy ends the tunnel or the stream is gone.
     */
    public val payloads: Flow<ByteArray>

    /** HTTP datagrams received and dropped: an unknown Context ID, or too short to carry one. */
    public val droppedDatagrams: Long

    /**
     * Sends one UDP payload to the target without suspending; the result is [CapsuleStream.trySendDatagram]'s, with
     * `TooLarge.max` the largest payload that fits now. Throws [IllegalArgumentException] for more than
     * [ConnectUdp.MAX_UDP_PAYLOAD] bytes ("endpoints MUST NOT send HTTP Datagrams with a UDP Proxying Payload field longer
     * than 65527", section 5).
     */
    public fun trySend(payload: ByteArray): DatagramSendResult

    /** [trySend] that waits for room in the transport's queue, as [CapsuleStream.sendDatagram]. */
    public suspend fun send(payload: ByteArray)

    /**
     * Ends the tunnel: our side of the stream ends (FIN) and [payloads] completes once the proxy closed its side. Bounded
     * by `closeTimeout` of [Http3Connection.connectUdp] (the stream is reset when it expires). Calling it again does nothing more.
     */
    public suspend fun close()

    /**
     * The address [asDatagramIo] reports for the target: the target itself when it is an IP literal, else a placeholder
     * from 192.0.2.0/24 (TEST-NET-1, never routed): the client does not resolve the name, the proxy does (section 3.1).
     */
    public val remoteAddress: InetSocketAddress

    /**
     * The tunnel as a UDP socket for a QUIC endpoint (`quicEndpointConfig { io = { tunnel.asDatagramIo() } }`), so that a
     * QUIC or HTTP/3 connection to [remoteAddress] runs through the proxy (proxied QUIC). Every datagram the endpoint sends
     * goes to the target whatever its address (a tunnel has one target, so a server's preferred address and other paths
     * are unreachable through it); every one received is reported as coming from [remoteAddress]. The socket has no ECN,
     * GSO or Don't Fragment ([io.kuicksilver.quic.IoCapabilities.Portable]), so the QUIC connection inside keeps
     * 1200-byte datagrams; the connection to the proxy must carry HTTP datagrams of 1200 bytes plus a few bytes of
     * framing, which needs its path MTU above about 1250 (a socket that sets Don't Fragment, so DPLPMTUD can find it):
     * until then the datagrams are refused as too large and the inner handshake waits. A datagram the tunnel refuses
     * counts as lost on the path. Closing the socket closes the tunnel; once the tunnel ended, `receive` throws. Call it once.
     */
    public fun asDatagramIo(): DatagramIo
}

/**
 * Client: opens a UDP tunnel through the proxy at the other end of this connection (RFC 9298 section 3.4): an Extended
 * CONNECT with `:protocol` `connect-udp`, the `:scheme`, `:authority` and `:path` of [template] expanded for [targetHost]
 * and [targetPort], `capsule-protocol: ?1` and [headers] (a `proxy-authorization`, for example). The template is checked
 * before anything is sent (section 2), and so is the target (section 3): [IllegalArgumentException] otherwise. Any answer
 * other than a 2xx fails the call with [Http3Exception.ConnectRejected], whose headers carry the proxy's `proxy-status`
 * (section 3.5: "Any response other than a successful response indicates that the request has failed"); a server without
 * Extended CONNECT fails it with [Http3Exception.Settings]. Datagrams may be sent once this returns.
 *
 * [closeTimeout] bounds [UdpTunnel.close].
 */
@ExperimentalKuicksilverApi
public suspend fun Http3Connection.connectUdp(
    template: UdpProxyTemplate,
    targetHost: String,
    targetPort: Int,
    headers: Http3Headers = Http3Headers.Empty,
    closeTimeout: Duration = 5.seconds,
): UdpTunnel = connectUdpTunnel(this, template, targetHost, targetPort, headers, closeTimeout)

/**
 * Which targets a [UdpProxy] sends to (RFC 9298 section 7). It sees each address the target resolved to (4 or 16 bytes),
 * the host the client named (a literal or a DNS name) and the port; the proxy uses the first address it allows and answers
 * 403 with `proxy-status: ...; error=destination_ip_prohibited` when it allows none. The check runs on resolved addresses,
 * and the proxy sends to the very address it allowed, so a DNS answer cannot steer it elsewhere afterwards.
 */
@ExperimentalKuicksilverApi
public fun interface UdpTargetFilter {
    /** Whether the proxy may send to [address] (4 or 16 bytes), port [port], for a request that named [host]. */
    public fun allows(
        host: String,
        address: ByteArray,
        port: Int,
    ): Boolean

    /** Both this filter and [other] allow the target. */
    public infix fun and(other: UdpTargetFilter): UdpTargetFilter = UdpTargetFilter { h, a, p -> allows(h, a, p) && other.allows(h, a, p) }

    /** This filter or [other] allows the target. */
    public infix fun or(other: UdpTargetFilter): UdpTargetFilter = UdpTargetFilter { h, a, p -> allows(h, a, p) || other.allows(h, a, p) }

    /** The filters a proxy is usually built from. */
    public companion object {
        /**
         * Globally reachable unicast only, the default (section 7: "the UDP proxy disallows UDP proxying requests to
         * vulnerable targets, such as the UDP proxy's own addresses and localhost, link-local, multicast, and broadcast
         * addresses"): loopback, unspecified, private (RFC 1918, ULA), shared (RFC 6598), link-local, multicast, the limited
         * broadcast address, documentation and benchmarking ranges and the rest of the IANA Special-Purpose Address
         * Registries that is not globally reachable are refused; an IPv4-mapped, NAT64 or 6to4 address is judged by its
         * IPv4 address. A proxy that has public addresses of its own adds them with [excluding].
         */
        public val PublicOnly: UdpTargetFilter = UdpTargetFilter { _, a, _ -> UdpAddressClass.isPublicUnicast(a) }

        /**
         * Every target: loopback, the proxy's own network, broadcast. Only for a proxy whose clients are as trusted as
         * the host it runs on (a test, a lab): with it any client reaches whatever listens on UDP there (CWE-918).
         */
        @DelicateKuicksilverApi
        public val AllowAll: UdpTargetFilter = UdpTargetFilter { _, _, _ -> true }

        /**
         * Addresses within one of [cidrs] (`192.0.2.0/24`, `2001:db8::/32`; an address alone is that host); an IPv4-mapped
         * address matches IPv4 prefixes. Throws [IllegalArgumentException] for a malformed prefix.
         */
        public fun addresses(vararg cidrs: String): UdpTargetFilter {
            val prefixes = cidrs.map { UdpAddressClass.parsePrefix(it) }
            return UdpTargetFilter { _, a, _ -> prefixes.any { (net, len) -> UdpAddressClass.inPrefix(a, net, len) } }
        }

        /** Every address except those within [cidrs], as [addresses] reads them: the proxy's own public addresses, say. */
        public fun excluding(vararg cidrs: String): UdpTargetFilter {
            val inside = addresses(*cidrs)
            return UdpTargetFilter { h, a, p -> !inside.allows(h, a, p) }
        }

        /** Targets the client named by one of [names] (DNS names, compared without case and without a final dot). */
        public fun hosts(vararg names: String): UdpTargetFilter {
            val set = names.map { it.lowercase().removeSuffix(".") }.toSet()
            return UdpTargetFilter { h, _, _ -> h.lowercase().removeSuffix(".") in set }
        }

        /** Ports within one of [ranges]. */
        public fun ports(vararg ranges: IntRange): UdpTargetFilter = UdpTargetFilter { _, _, p -> ranges.any { p in it } }
    }
}

/** Resolves the DNS name a client gave as `target_host` for a [UdpProxy] (RFC 9298 section 3.1). */
@ExperimentalKuicksilverApi
public fun interface UdpProxyResolver {
    /**
     * The IPv4 (4 bytes) and IPv6 (16 bytes) addresses of [host], in order of preference; empty or an exception when it
     * has none. Cancelled at the proxy's `resolveTimeout`.
     */
    public suspend fun resolve(host: String): List<ByteArray>

    /** The platform's resolver. */
    public companion object {
        /**
         * The operating system's resolver (`getaddrinfo`, one family at a time): every IPv4 address, then every IPv6 one. A
         * lookup blocks a thread no deadline interrupts, so lookups run on 16 threads of their own and a seventeenth at once
         * is refused (the request gets 503); a lookup the caller gave up on keeps its thread until it returns.
         */
        public val System: UdpProxyResolver = UdpProxyResolver { SystemResolver.resolve(it) }
    }
}

/**
 * How a [UdpProxy] serves CONNECT-UDP (RFC 9298).
 *
 * @property pathTemplate the path and query a request must have, a URI Template of `target_host` and `target_port`
 *   (RFC 9298 section 2; the default is [ConnectUdp.WELL_KNOWN_PATH]). Each variable once; after an expression, the end,
 *   a `{&...}` or a literal that starts with a character no value contains: a request is read back without guessing.
 * @property targetFilter which targets may be reached (section 7); [UdpTargetFilter.PublicOnly] by default.
 * @property resolver resolves a `target_host` that is a DNS name before the proxy answers (section 3.1).
 * @property resolveTimeout how long a resolution may take; then the request is answered 504 with `dns_timeout`.
 * @property idleTimeout a tunnel without a datagram either way for this long is closed (socket and request stream);
 *   at least two minutes, the floor of section 3.1 ("SHOULD NOT use a period lower than two minutes").
 * @property linkMtu the MTU of the proxy's link towards targets, 1280..65535: UDP payloads above `linkMtu - 28` (IPv4) or
 *   `linkMtu - 48` (IPv6) are dropped rather than sent fragmented (section 5); a datagram from a target above `linkMtu`
 *   bytes is dropped whole (never forwarded cut: a socket truncates what does not fit its buffer).
 * @property maxTunnels tunnels open at once; one more is answered 503 with `connection_limit_reached`.
 * @property maxTunnelsPerClient tunnels open at once per client ([clientIpv6Prefix][UdpProxyConfig.clientIpv6Prefix]);
 *   one more is answered 429.
 * @property clientIpv6Prefix the prefix an IPv6 client is known by for its limits: 64 by default, so a client with a /64
 *   cannot pass for 2^64 clients; 1..128 (128: each address). An IPv4 client is its address.
 * @property clientPacketRate UDP payloads per second all of a client's tunnels together may send to targets, on top of each
 *   tunnel's [packetRate][UdpProxyConfig.packetRate]: more tunnels do not multiply a client's rate.
 * @property clientPacketBurst the client bucket's size.
 * @property packetRate UDP payloads per second a tunnel may send to its target, a token bucket refilled at this rate;
 *   payloads beyond it are dropped, as UDP may drop them (section 7, CWE-400).
 * @property packetBurst the bucket's size, the payloads a tunnel may send at once.
 * @property unansweredLimit UDP payloads a tunnel may send before its target has answered once; later ones are dropped
 *   until it does (section 7: limits a flood of a target that never answers); 0 turns the limit off.
 * @property refuseOwnAddresses refuse the proxy's own addresses as targets, 403 with `destination_ip_prohibited` before a
 *   socket exists: the address the request's connection reached and the listener's when it is bound to one, an
 *   IPv4-mapped, NAT64 (`64:ff9b::/96`) or 6to4 (`2002::/16`) target compared by the IPv4 address it carries. RFC 9298
 *   section 7: a proxy that does not disallow "the UDP proxy's own addresses" lets clients reach services listening on
 *   the proxy host itself, which a firewall in front of it does not see. On by default, applied whatever
 *   [targetFilter][UdpProxyConfig.targetFilter] allows; set false only where a target on the proxy's own host is meant (a
 *   test, a sidecar). Other addresses of the host (NAT aliases, other interfaces), which the library does not list, go to
 *   [UdpTargetFilter.excluding].
 * @property requireCapsuleProtocolField a request without `capsule-protocol: ?1` is answered 400 (as RFC 9298's examples
 *   send it; the RFC does not require it, so a proxy for clients that leave it out sets false).
 * @property proxyName this proxy's name in the `proxy-status` field of its refusals (RFC 9209 section 2), an sf-token.
 * @property packetTooBig send an ICMP Packet Too Big to a target whose UDP payload is dropped because it does not fit the
 *   client's QUIC DATAGRAM frames (RFC 9298 section 6.1), when the process may open a raw ICMP socket (Linux and Android
 *   with CAP_NET_RAW); without that privilege, or with false, the payload is only dropped and counted. True by default;
 *   [UdpProxyStats.packetTooBig] says which applies. At most 10 a second per target address (a burst of 5) and 100 a
 *   second over the proxy, never more than the payloads dropped. Sent from the address the target sent to: see
 *   [socketFactory][UdpProxyConfig.socketFactory].
 * @property socketFactory opens the UDP socket of a tunnel on a wildcard address of the target's family (`0.0.0.0:0`
 *   or `[::]:0`); [DatagramIo.open] by default, the accelerated socket where it exists, which sets Don't Fragment and, on
 *   the wildcard bind, reports each datagram's destination, the source of a [packetTooBig][UdpProxyConfig.packetTooBig]
 *   message. A factory may bind one address instead (its Packet Too Big messages leave from it); a wildcard socket that
 *   does not report destinations (the portable one) sends none, counted in [UdpProxyStats.packetTooBigNoSource]. No DF,
 *   no tunnel (RFC 9298 section 3.1: "UDP proxies MUST NOT introduce fragmentation at the IP layer"): a factory that
 *   throws [io.kuicksilver.quic.QuicException.DontFragmentUnavailable], or a socket whose
 *   [noDontFragmentFamily][DatagramIo.noDontFragmentFamily] is the target's family, refuses the request with 500 and
 *   `proxy-status: <proxyName>; error=proxy_configuration_error; details="no Don't Fragment for <family> targets on this
 *   host"`; the other family is still served. The proxy remembers a family as without DF only for a permanent cause: a
 *   custom factory throws [io.kuicksilver.quic.QuicException.DontFragmentUnavailable] with `permanent = false` for a
 *   failure that may pass on a later attempt (out of descriptors, a bind refused under load), so later requests try again.
 */
@ExperimentalKuicksilverApi
public class UdpProxyConfig(
    public val pathTemplate: String = ConnectUdp.WELL_KNOWN_PATH,
    public val targetFilter: UdpTargetFilter = UdpTargetFilter.PublicOnly,
    public val resolver: UdpProxyResolver = UdpProxyResolver.System,
    public val resolveTimeout: Duration = 5.seconds,
    public val idleTimeout: Duration = 2.minutes,
    public val linkMtu: Int = 1500,
    public val maxTunnels: Int = 4096,
    public val maxTunnelsPerClient: Int = 64,
    public val clientIpv6Prefix: Int = 64,
    public val clientPacketRate: Int = 50_000,
    public val clientPacketBurst: Int = 5_000,
    public val packetRate: Int = 20_000,
    public val packetBurst: Int = 2_000,
    public val unansweredLimit: Int = 256,
    public val refuseOwnAddresses: Boolean = true,
    public val requireCapsuleProtocolField: Boolean = true,
    public val proxyName: String = "proxy",
    public val packetTooBig: Boolean = true,
    public val socketFactory: suspend (InetSocketAddress) -> DatagramIo = { DatagramIo.open(it) },
) {
    internal val template: UdpUriTemplate = UdpUriTemplate.parsePath(pathTemplate)

    init {
        require(resolveTimeout.isPositive()) { "resolveTimeout must be positive" }
        require(idleTimeout >= 2.minutes) { "idleTimeout must be at least two minutes (RFC 9298 section 3.1)" }
        require(linkMtu in 1280..65_535) { "linkMtu must be 1280..65535" }
        require(maxTunnels >= 1) { "maxTunnels must be at least 1" }
        require(maxTunnelsPerClient >= 1) { "maxTunnelsPerClient must be at least 1" }
        require(packetRate >= 1) { "packetRate must be at least 1" }
        require(packetBurst >= 1) { "packetBurst must be at least 1" }
        require(clientIpv6Prefix in 1..128) { "clientIpv6Prefix must be 1..128" }
        require(clientPacketRate >= 1) { "clientPacketRate must be at least 1" }
        require(clientPacketBurst >= 1) { "clientPacketBurst must be at least 1" }
        require(unansweredLimit >= 0) { "unansweredLimit must not be negative" }
        require(proxyName.isNotEmpty() && proxyName[0].let { it in 'a'..'z' || it in 'A'..'Z' || it == '*' }) {
            "proxyName must be a Structured Field token (RFC 8941 section 3.3.4)"
        }
        require(proxyName.all { it.code in 0x21..0x7e && it !in "\"(),;<=>?@[\\]{}" }) {
            "proxyName must be a Structured Field token (RFC 8941 section 3.3.4)"
        }
    }
}

/**
 * What a [UdpProxy] has done since it was made.
 *
 * @property tunnelsOpened requests answered with a 2xx.
 * @property requestsRefused requests answered with another status.
 * @property toTargets UDP payloads sent to targets.
 * @property fromTargets UDP payloads received from targets and sent on to clients.
 * @property droppedUnknownContext HTTP datagrams from clients with a Context ID other than 0, or none (RFC 9298 section 4).
 * @property droppedTooLargeForLink UDP payloads above what [UdpProxyConfig.linkMtu] carries unfragmented (section 5).
 * @property droppedRefusedAsTooLarge UDP payloads within [UdpProxyConfig.linkMtu] that the tunnel's socket refused as too
 *   large for the path or link (EMSGSIZE: a smaller MTU toward the target), as the accelerated socket reports them or as a
 *   send failure says; each is dropped (section 5 carries "the unmodified payload", never a fragment of it) and the tunnel
 *   stays open. A failure not recognized as such a refusal ends the tunnel instead (`docs/spec/rfc/9298.md`, section 3.1).
 * @property droppedRateLimited UDP payloads beyond [UdpProxyConfig.packetRate] or [UdpProxyConfig.clientPacketRate].
 * @property droppedUnanswered UDP payloads beyond [UdpProxyConfig.unansweredLimit] to a target that never answered.
 * @property droppedForeignSource datagrams from an address other than the tunnel's target (section 3.1: "Packets that do not match MUST be discarded").
 * @property droppedTooLargeForClient UDP payloads from targets too large for the client's QUIC DATAGRAM frames (section 6.1).
 * @property droppedClientBusy UDP payloads from targets dropped because the connection's datagram queue was full.
 * @property droppedTooLargeFromTarget datagrams from targets above [UdpProxyConfig.linkMtu] bytes, dropped whole.
 * @property closedUnreachable tunnels closed because an ICMP port unreachable came for their target that quoted a payload
 *   they sent (section 3.1; RFC 8085 section 5.2).
 * @property ignoredUnreachable ICMP unreachable reports not acted on: host unreachable, for another destination, quoting
 *   the headers only or a payload the tunnel did not send lately (possibly forged).
 * @property packetTooBig whether this proxy sends ICMP Packet Too Big messages (RFC 9298 section 6.1), as probed at its
 *   first tunnel.
 * @property packetTooBigSent ICMP Packet Too Big messages sent to targets.
 * @property packetTooBigNoSource ICMP Packet Too Big messages not sent (with
 *   [packetTooBig][UdpProxyStats.packetTooBig] [PacketTooBigStatus.Available])
 *   because the address the target sent to is unknown: a socket of [UdpProxyConfig.socketFactory] bound to a wildcard address
 *   that does not report each datagram's destination (the portable socket; the accelerated one reports it). A socket bound
 *   to one address answers from that address.
 * @property packetTooBigFailed ICMP Packet Too Big messages the raw socket did not send (the family's socket did not open,
 *   the kernel refused the message, or the sender ruled out its addresses); their rate-limit tokens stay spent.
 */
@ExperimentalKuicksilverApi
public class UdpProxyStats internal constructor(
    public val tunnelsOpened: Long,
    public val requestsRefused: Long,
    public val toTargets: Long,
    public val fromTargets: Long,
    public val droppedUnknownContext: Long,
    public val droppedTooLargeForLink: Long,
    public val droppedRefusedAsTooLarge: Long,
    public val droppedRateLimited: Long,
    public val droppedUnanswered: Long,
    public val droppedForeignSource: Long,
    public val droppedTooLargeForClient: Long,
    public val droppedClientBusy: Long,
    public val droppedTooLargeFromTarget: Long,
    public val closedUnreachable: Long,
    public val ignoredUnreachable: Long,
    public val packetTooBig: PacketTooBigStatus,
    public val packetTooBigSent: Long,
    public val packetTooBigNoSource: Long,
    public val packetTooBigFailed: Long,
) {
    /** The counters, for logs. */
    override fun toString(): String =
        "UdpProxyStats(opened=$tunnelsOpened, refused=$requestsRefused, toTargets=$toTargets, fromTargets=$fromTargets, " +
            "unknownContext=$droppedUnknownContext, tooLargeForLink=$droppedTooLargeForLink, " +
            "refusedAsTooLarge=$droppedRefusedAsTooLarge, rateLimited=$droppedRateLimited, " +
            "unanswered=$droppedUnanswered, foreignSource=$droppedForeignSource, tooLargeForClient=$droppedTooLargeForClient, " +
            "clientBusy=$droppedClientBusy, tooLargeFromTarget=$droppedTooLargeFromTarget, closedUnreachable=$closedUnreachable, " +
            "ignoredUnreachable=$ignoredUnreachable, " +
            "packetTooBig=$packetTooBig, packetTooBigSent=$packetTooBigSent, packetTooBigNoSource=$packetTooBigNoSource, " +
            "packetTooBigFailed=$packetTooBigFailed)"
}

/** Whether a [UdpProxy] sends ICMP Packet Too Big (RFC 9298 section 6.1). */
@ExperimentalKuicksilverApi
public enum class PacketTooBigStatus {
    /** [UdpProxyConfig.packetTooBig] is false: payloads too large for the client are dropped and counted only. */
    Off,

    /** No tunnel has been opened yet, so the privilege was not probed. */
    NotProbed,

    /**
     * The process cannot open a raw ICMP socket (no CAP_NET_RAW on Linux and Android; Apple platforms, Windows and the
     * portable build do not offer it): payloads too large for the client are dropped and counted only.
     */
    Unavailable,

    /** Raw ICMP sockets open: each such payload is answered with a Packet Too Big, within the rate limit. */
    Available,
}

/**
 * A UDP proxy (RFC 9298) on an HTTP/3 server: [serve] answers one CONNECT-UDP request and relays its tunnel until it ends.
 * The server's `Http3Settings` need `enableConnectProtocol` (RFC 9220), and `h3Datagram` for datagrams as QUIC DATAGRAM
 * frames (without them the tunnel falls back to DATAGRAM capsules on the stream). Authenticate clients before calling
 * [serve]: "HTTP servers that support UDP proxying ought to restrict its use to authenticated users" (section 7).
 */
@ExperimentalKuicksilverApi
public class UdpProxy(
    /** How the proxy serves. */
    public val config: UdpProxyConfig = UdpProxyConfig(),
) {
    internal val impl = UdpProxyImpl(config)

    /** Requests [serve] holds now: tunnels open and requests still being set up (resolved, answered); what the limits count. */
    public val activeTunnels: StateFlow<Int> get() = impl.active

    /** Counters since the proxy was made. */
    public val stats: UdpProxyStats get() = impl.snapshot()

    /**
     * Serves [request], an Extended CONNECT for `connect-udp` ([ConnectUdp.isConnectUdp]), and returns when its tunnel
     * ended. In order (RFC 9298 sections 3.1, 3.4, 7):
     * - not a CONNECT-UDP request: 400 (`http_request_error`); a path that does not fit [UdpProxyConfig.pathTemplate]: 404;
     *   a `target_host` or `target_port` that breaks section 3, or no `capsule-protocol: ?1` while
     *   [UdpProxyConfig.requireCapsuleProtocolField]: 400;
     * - [UdpProxyConfig.maxTunnels] reached: 503, [UdpProxyConfig.maxTunnelsPerClient]: 429 (`connection_limit_reached`);
     * - a DNS name is resolved before the answer ("the UDP proxy MUST perform DNS resolution before replying"): a failure
     *   or no address is 502 with `proxy-status: <name>; error=dns_error`, a timeout 504 with `dns_timeout`;
     * - no address the [UdpProxyConfig.targetFilter] allows: 403 with `destination_ip_prohibited`;
     * - the socket cannot be opened: the candidates of the other address family are tried first (a family whose socket
     *   failed is skipped for the rest of the request, as one without Don't Fragment is); 502 with `proxy_internal_error`
     *   when none opened and one failed for another reason than DF, also when the other family lacked DF (the failure,
     *   maybe transient, is what is reported), else the no-DF refusal (500, [UdpProxyConfig]);
     * - otherwise 200 with `capsule-protocol: ?1`: the socket is open (a successful response "indicates that the UDP proxy
     *   has opened a socket to the requested target"), and nothing is sent to the target before it.
     *
     * Then HTTP datagrams with Context ID 0 become UDP payloads to the target and the target's payloads become HTTP
     * datagrams; datagrams with other Context IDs are dropped, and one whose payload exceeds 65527 bytes aborts the
     * stream with H3_DATAGRAM_ERROR (section 5). Only datagrams from the target's address and port are taken (section
     * 3.1). The tunnel ends, and the socket closes with it, when the client ends the stream (FIN: our side is closed
     * too), when it resets it or its connection is gone, when the socket fails (the stream is reset and stopped with
     * H3_CONNECT_ERROR: "If a UDP proxy is notified by its operating system that its socket is no longer usable, it MUST
     * close the request stream"), or after [UdpProxyConfig.idleTimeout] without traffic (FIN and STOP_SENDING
     * H3_NO_ERROR). Cancelling the call ends the tunnel the same way, with H3_CONNECT_ERROR.
     */
    public suspend fun serve(request: Http3ServerRequest): Unit = impl.serve(request)

    /**
     * [serve], telling [answered] (once, in the calling coroutine) the status the request was answered with as soon as it
     * went out: the 200 of a tunnel, or a refusal. Not called when the stream failed before an answer could be written.
     */
    @io.kuicksilver.annotations.InternalKuicksilverApi
    public suspend fun serve(
        request: Http3ServerRequest,
        answered: (status: Int) -> Unit,
    ): Unit = impl.serve(request, answered)
}
