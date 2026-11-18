// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.KuicksilverDsl
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * The PROXY protocol (HAProxy, "The PROXY protocol", versions 1 and 2) on one TCP connector, plain or TLS: a proxy or L4 load
 * balancer in front of the server sends a header with the client's address before anything else on the connection, and
 * the engine reports that address as the request's origin (`call.request.origin`), while `call.request.local` keeps the
 * TCP peer (the proxy). Made by `proxyProtocol { ... }` on `plainConnector { }` or `tlsConnector(identity) { }`; off by
 * default.
 *
 * On such a connector every connection must start with a valid header, version 1 or 2, before TLS on a TLS connector:
 * the spec says the receiver "MUST not try to guess whether the protocol header is present or not". A connection whose
 * TCP peer is not one of [trustedSources] is closed at accept, before a byte is read: only the configured proxies may
 * speak the protocol ("The receiver SHOULD ensure proper access filtering so that only trusted proxies are allowed to use
 * this protocol"), and a client that reaches the port directly cannot set its own address. A header that is malformed,
 * longer than [maxHeaderSize] or not complete within [headerTimeout] closes the connection. HTTP/3 (QUIC, UDP) on a TLS
 * connector's port is not affected: the protocol is defined for connection-oriented transports in front of the server, so
 * HTTP/3 requests report their UDP peer.
 */
@ExperimentalKuicksilverApi
public class ProxyProtocolConfig private constructor(
    /** The addresses and CIDR blocks (`10.0.0.0/8`, `2001:db8::/32`, `192.0.2.7`) allowed to send the header, as given. */
    public val trustedSources: List<String>,
    /** How long a connection may take to send its whole header, counted from accept; see [Builder.headerTimeout]. */
    public val headerTimeout: Duration,
    /** The longest header accepted, in bytes; see [Builder.maxHeaderSize]. */
    public val maxHeaderSize: Int,
) {
    internal val blocks: List<IpBlock> = trustedSources.map { IpBlock.parse(it) }

    /**
     * Whether a TCP peer of address [peer] (4 or 16 bytes; null when unknown) may send the header: an IPv4-mapped IPv6
     * address (`::ffff:a.b.c.d`, as a dual-stack listener reports IPv4 peers) is matched as its IPv4 address.
     */
    internal fun trusts(peer: ByteArray?): Boolean {
        if (peer == null) return false
        val ip = unmappedIp(peer)
        return blocks.any { it.contains(ip) }
    }

    /** For logs. */
    override fun toString(): String = "PROXY protocol from $trustedSources"

    /** Builds a [ProxyProtocolConfig]; used by `proxyProtocol { ... }` on a connector. */
    @KuicksilverDsl
    public class Builder {
        /**
         * The TCP peers allowed to send the header: IPv4 or IPv6 addresses, each alone or as a CIDR block (`10.0.0.0/8`,
         * `2001:db8::/32`). At least one is required; a block with bits set past its prefix (`10.0.0.1/8`), a zone ID or
         * anything else that is not a numeric address is refused at [build]. An IPv4-mapped block (`::ffff:10.0.0.0/104`)
         * is the IPv4 block it maps; IPv4 peers match IPv4 blocks only, also where the listener reports them as IPv4-mapped
         * IPv6 addresses.
         */
        public val trustedSources: MutableList<String> = mutableListOf()

        /** Adds [sources] to [trustedSources]. */
        public fun trust(vararg sources: String) {
            trustedSources += sources
        }

        /**
         * How long a connection may take, from accept, to deliver its whole header; 5 s by default, at most the engine's
         * `requestHeaderTimeoutSeconds`, which goes on counting from accept through the TLS handshake and the first request
         * head. A proxy sends the header at once with the connection ("the sender must always ensure that the header is sent
         * at once"), so a short bound cuts a peer that trickles it without hurting a proxy.
         */
        public var headerTimeout: Duration = 5.seconds

        /**
         * The longest header accepted, in bytes: 4096 by default, from 232 (a version 2 header with AF_UNIX addresses and no
         * TLV) to 65551 (the 16 fixed bytes and the largest length field). A version 1 header is never longer than 107 bytes
         * whatever this says; a version 2 header whose length field says more than this is refused before its body is read.
         */
        public var maxHeaderSize: Int = 4096

        /** The configuration; throws [IllegalArgumentException] for no or an invalid trusted source, a timeout that is not positive, or a size out of range. */
        public fun build(): ProxyProtocolConfig {
            require(trustedSources.isNotEmpty()) { "proxyProtocol needs at least one trusted source" }
            require(headerTimeout.isPositive()) { "proxyProtocol.headerTimeout must be positive" }
            require(maxHeaderSize in MIN_MAX_HEADER_SIZE..ProxyProtocolCodec.V2_MAX) {
                "proxyProtocol.maxHeaderSize must be $MIN_MAX_HEADER_SIZE..${ProxyProtocolCodec.V2_MAX}"
            }
            return ProxyProtocolConfig(trustedSources.toList(), headerTimeout, maxHeaderSize)
        }
    }

    internal companion object {
        const val DEFAULT_MAX_HEADER_SIZE = 4096

        /** 16 fixed bytes and two AF_UNIX addresses of 108 bytes: the smallest limit that takes every family. */
        const val MIN_MAX_HEADER_SIZE = 16 + 216
    }
}

/**
 * An IP address block: [bytes] (4 or 16, bits past [prefix] zero) and its prefix length. Parsed from `a.b.c.d[/n]` or an
 * IPv6 text address `[/n]`; an IPv4-mapped IPv6 block of prefix 96 or more is the IPv4 block it maps (RFC 4291 section
 * 2.5.5.2), so it matches the IPv4 peers that [ProxyProtocolConfig.trusts] compares as IPv4.
 */
internal class IpBlock(
    val bytes: ByteArray,
    val prefix: Int,
) {
    fun contains(ip: ByteArray): Boolean {
        if (ip.size != bytes.size) return false
        var bits = prefix
        var i = 0
        while (bits > 0) {
            val mask = if (bits >= 8) 0xff else (0xff shl (8 - bits)) and 0xff
            if ((ip[i].toInt() and mask) != (bytes[i].toInt() and mask)) return false
            bits -= 8
            i++
        }
        return true
    }

    companion object {
        fun parse(text: String): IpBlock {
            val slash = text.indexOf('/')
            val addr = if (slash < 0) text else text.substring(0, slash)
            require(addr.isNotEmpty() && addr.none { it == '[' || it == ']' || it == '%' || it.isWhitespace() }) {
                "not an IP address or CIDR block: \"$text\""
            }
            val bytes = parseIpLiteral(addr) ?: throw IllegalArgumentException("not an IP address or CIDR block: \"$text\"")
            val max = bytes.size * 8
            val prefix =
                if (slash < 0) {
                    max
                } else {
                    val p = text.substring(slash + 1)
                    require(p.isNotEmpty() && p.length <= 3 && p.all { it in '0'..'9' } && (p.length == 1 || p[0] != '0')) {
                        "not a prefix length: \"$text\""
                    }
                    p.toInt().also { require(it <= max) { "prefix length over $max: \"$text\"" } }
                }
            require(hostBitsZero(bytes, prefix)) { "bits set past the prefix length: \"$text\"" }
            val unmapped = unmappedIp(bytes)
            return if (unmapped.size == 4 && prefix >= 96) IpBlock(unmapped, prefix - 96) else IpBlock(bytes, prefix)
        }

        private fun hostBitsZero(
            bytes: ByteArray,
            prefix: Int,
        ): Boolean {
            for (bit in prefix until bytes.size * 8) {
                if ((bytes[bit / 8].toInt() shr (7 - bit % 8)) and 1 != 0) return false
            }
            return true
        }
    }
}
