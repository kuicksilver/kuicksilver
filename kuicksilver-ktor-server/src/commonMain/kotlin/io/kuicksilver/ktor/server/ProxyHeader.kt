// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.mutableOriginConnectionPoint
import io.ktor.server.request.ApplicationRequest
import io.ktor.util.AttributeKey
import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/** The command of a PROXY protocol header: version 2's command nibble; a version 1 header is always [Proxy]. */
@ExperimentalKuicksilverApi
public enum class ProxyCommand {
    /** The proxy opened the connection itself (a health check): the real connection's addresses apply. */
    Local,

    /** The connection is relayed for a client; the header's addresses, when it has some, are the client's. */
    Proxy,
}

/** The address family of a PROXY protocol header: version 1's `TCP4`, `TCP6`, `UNKNOWN`, version 2's high nibble of byte 14. */
@ExperimentalKuicksilverApi
public enum class ProxyFamily {
    /** No address (version 1 `UNKNOWN`, version 2 AF_UNSPEC): the real connection's addresses apply. */
    Unspecified,

    /** IPv4 (`TCP4`, AF_INET). */
    Inet,

    /** IPv6 (`TCP6`, AF_INET6). */
    Inet6,

    /** A Unix socket path (AF_UNIX, version 2 only). */
    Unix,
}

/** The transport of a PROXY protocol header: version 2's low nibble of byte 14; `TCP4` and `TCP6` are [Stream]. */
@ExperimentalKuicksilverApi
public enum class ProxyTransport {
    /** Not given (version 1 `UNKNOWN`, version 2 UNSPEC). */
    Unspecified,

    /** SOCK_STREAM (TCP). */
    Stream,

    /** SOCK_DGRAM (UDP). */
    Dgram,
}

/** One TLV of a version 2 header: its [type] (0..255) and value. */
@ExperimentalKuicksilverApi
public class ProxyTlv internal constructor(
    /** The type byte (`PP2_TYPE_*`), 0..255. */
    public val type: Int,
    private val bytes: ByteArray,
) {
    /** A copy of the value. */
    public val value: ByteArray get() = bytes.copyOf()

    /** The value as UTF-8 text, or null when it is not valid UTF-8. */
    public fun text(): String? =
        try {
            bytes.decodeToString(throwOnInvalidSequence = true)
        } catch (_: CharacterCodingException) {
            null
        }

    /** For logs: the type and the value's length, never the value. */
    override fun toString(): String = "TLV 0x${type.toString(16)} (${bytes.size} bytes)"
}

/**
 * The `PP2_TYPE_SSL` TLV of a version 2 header: how the client reached the proxy over TLS, as the proxy reports it. This
 * is the proxy's word, not a TLS session of this server: it is trusted as far as the proxy is ([ProxyProtocolConfig]).
 */
@ExperimentalKuicksilverApi
public class ProxySsl internal constructor(
    /** The `client` bit field: [PP2_CLIENT_SSL] (0x01), [PP2_CLIENT_CERT_CONN] (0x02), [PP2_CLIENT_CERT_SESS] (0x04). */
    public val client: Int,
    /** The `verify` field: 0 when the client presented a certificate that the proxy verified, else non-zero. */
    public val verify: Long,
    /** The sub-TLVs (`PP2_SUBTYPE_SSL_*`), in order. */
    public val subTlvs: List<ProxyTlv>,
) {
    /** The client connected over SSL/TLS. */
    public val clientSsl: Boolean get() = client and PP2_CLIENT_SSL != 0

    /** The TLS version (`PP2_SUBTYPE_SSL_VERSION`, for example `TLSv1.3`), or null. */
    public val version: String? get() = sub(0x21)

    /** The client certificate's subject Common Name (`PP2_SUBTYPE_SSL_CN`), or null. */
    public val commonName: String? get() = sub(0x22)

    /** The cipher (`PP2_SUBTYPE_SSL_CIPHER`), or null. */
    public val cipher: String? get() = sub(0x23)

    /** The certificate's signature algorithm (`PP2_SUBTYPE_SSL_SIG_ALG`), or null. */
    public val signatureAlgorithm: String? get() = sub(0x24)

    /** The certificate's key algorithm (`PP2_SUBTYPE_SSL_KEY_ALG`), or null. */
    public val keyAlgorithm: String? get() = sub(0x25)

    private fun sub(type: Int): String? = subTlvs.firstOrNull { it.type == type }?.text()

    /** For logs. */
    override fun toString(): String = "SSL(client=0x${client.toString(16)}, verify=$verify, ${subTlvs.size} sub-TLVs)"

    /** The bits of [client]. */
    public companion object {
        /** `PP2_CLIENT_SSL`: the client connected over SSL/TLS. */
        public const val PP2_CLIENT_SSL: Int = 0x01

        /** `PP2_CLIENT_CERT_CONN`: the client presented a certificate on this connection. */
        public const val PP2_CLIENT_CERT_CONN: Int = 0x02

        /** `PP2_CLIENT_CERT_SESS`: the client presented a certificate at least once in this TLS session. */
        public const val PP2_CLIENT_CERT_SESS: Int = 0x04
    }
}

/**
 * The PROXY protocol header a connection began with ([ProxyProtocolConfig]). [sourceAddress] and [destinationAddress] are
 * the client's address and the one it connected to on the proxy: IP literals (a dotted quad, or IPv6 as RFC 5952
 * recommends) for [ProxyFamily.Inet] and [ProxyFamily.Inet6], the socket path for [ProxyFamily.Unix] (an abstract one as
 * `@` and its name), null for a [ProxyCommand.Local] header and for [ProxyFamily.Unspecified]. The ports are null where
 * the family has none.
 */
@ExperimentalKuicksilverApi
public class ProxyHeader internal constructor(
    /** 1 (text) or 2 (binary). */
    public val version: Int,
    /** [ProxyCommand.Local] or [ProxyCommand.Proxy]. */
    public val command: ProxyCommand,
    /** The address family. */
    public val family: ProxyFamily,
    /** The transport. */
    public val transport: ProxyTransport,
    /** The client's address, or null. */
    public val sourceAddress: String?,
    /** The client's port, or null. */
    public val sourcePort: Int?,
    /** The address the client connected to, or null. */
    public val destinationAddress: String?,
    /** The port the client connected to, or null. */
    public val destinationPort: Int?,
    /**
     * The TLVs of a version 2 header with the PROXY command and an address family, in order, `PP2_TYPE_NOOP` left out;
     * empty otherwise. A `PP2_TYPE_CRC32C` TLV is listed after its checksum was verified.
     */
    public val tlvs: List<ProxyTlv>,
    /** The source address bytes (4 or 16) of an [ProxyFamily.Inet] or [ProxyFamily.Inet6] header with the PROXY command. */
    internal val sourceIp: ByteArray? = null,
) {
    /** The first TLV of [type], or null. */
    public fun tlv(type: Int): ProxyTlv? = tlvs.firstOrNull { it.type == type }

    /** `PP2_TYPE_ALPN`: the application protocol the client negotiated with the proxy, or null. */
    public val alpn: String? get() = tlv(PP2_TYPE_ALPN)?.text()

    /** `PP2_TYPE_AUTHORITY`: the host name the client sent the proxy (SNI), or null (also when it is not valid UTF-8). */
    public val authority: String? get() = tlv(PP2_TYPE_AUTHORITY)?.text()

    /** `PP2_TYPE_UNIQUE_ID`: the proxy's opaque ID of the connection (at most 128 bytes), or null. */
    public val uniqueId: ByteArray? get() = tlv(PP2_TYPE_UNIQUE_ID)?.value

    /** `PP2_TYPE_NETNS`: the network namespace the proxy accepted the connection in, or null. */
    public val netns: String? get() = tlv(PP2_TYPE_NETNS)?.text()

    /** `PP2_TYPE_SSL`, parsed, or null. */
    public val ssl: ProxySsl? get() = tlv(PP2_TYPE_SSL)?.let { ProxyProtocolCodec.ssl(it.value) }

    /** Whether the header names the client's IP address, which then is the request's origin. */
    internal val namesClient: Boolean get() = sourceIp != null

    /** For logs; addresses included, TLV values left out. */
    override fun toString(): String =
        "PROXY v$version $command $family $transport $sourceAddress:$sourcePort -> $destinationAddress:$destinationPort, ${tlvs.size} TLVs"

    /** The TLV types the spec defines. */
    public companion object {
        /** `PP2_TYPE_ALPN`. */
        public const val PP2_TYPE_ALPN: Int = 0x01

        /** `PP2_TYPE_AUTHORITY`. */
        public const val PP2_TYPE_AUTHORITY: Int = 0x02

        /** `PP2_TYPE_CRC32C`. */
        public const val PP2_TYPE_CRC32C: Int = 0x03

        /** `PP2_TYPE_NOOP`. */
        public const val PP2_TYPE_NOOP: Int = 0x04

        /** `PP2_TYPE_UNIQUE_ID`. */
        public const val PP2_TYPE_UNIQUE_ID: Int = 0x05

        /** `PP2_TYPE_SSL`. */
        public const val PP2_TYPE_SSL: Int = 0x20

        /** `PP2_TYPE_NETNS`. */
        public const val PP2_TYPE_NETNS: Int = 0x30
    }
}

internal val ProxyHeaderKey: AttributeKey<ProxyHeader> = AttributeKey("io.kuicksilver.ktor.server.ProxyHeader")

/**
 * The PROXY protocol header of this request's connection, or null when its connector does not take one (and for HTTP/3,
 * which has none). `call.request.origin` already reports the client it names; this gives the rest (TLVs, a LOCAL command).
 */
@ExperimentalKuicksilverApi
public val ApplicationRequest.proxyHeader: ProxyHeader? get() = call.attributes.getOrNull(ProxyHeaderKey)

/**
 * Records [header] on this call and, when it names the client's IP address (the PROXY command with an IPv4 or IPv6
 * family), makes that the call's origin: `origin.remoteHost`, `remoteAddress` and `remotePort` the client's,
 * `origin.localHost`, `localAddress` and `localPort` the address it connected to on the proxy. `request.local` stays
 * the TCP connection (its peer is the proxy), for logs. A plugin that reads forwarding fields (`XForwardedHeaders`,
 * `ForwardedHeaders`) changes the same origin after this, from the client's address on.
 */
internal fun ApplicationCall.applyProxyHeader(header: ProxyHeader?) {
    if (header == null) return
    attributes.put(ProxyHeaderKey, header)
    if (!header.namesClient) return
    val origin = mutableOriginConnectionPoint
    val src = header.sourceAddress ?: return
    origin.remoteHost = src
    origin.remoteAddress = src
    header.sourcePort?.let { origin.remotePort = it }
    header.destinationAddress?.let {
        origin.localHost = it
        origin.localAddress = it
    }
    header.destinationPort?.let { origin.localPort = it }
}
