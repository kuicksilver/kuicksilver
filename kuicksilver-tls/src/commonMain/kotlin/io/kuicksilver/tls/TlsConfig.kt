// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.annotations.KuicksilverDsl
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

/** The side of the handshake a [TlsConfig] is for; fixed when the builder is created, since the rules of the two differ. */
public enum class TlsRole {
    /** Initiates the handshake and verifies the server against [TlsConfig.trust] and its reference identifier. */
    Client,

    /** Answers the handshake with [TlsConfig.identity] (or the [TlsConfig.sniSelector] choice) and may ask for a client certificate. */
    Server,
}

/** Versions offered: QUIC is always TLS 1.3; TCP defaults to 1.3 and accepts 1.2 only when asked (RFC 9325 profile). */
public enum class TlsVersions {
    /** TLS 1.3 only (RFC 8446): the default, and the only value QUIC accepts (RFC 9001 section 4.2). */
    Tls13,

    /**
     * TLS 1.3, or TLS 1.2 (RFC 5246) with a peer that lacks 1.3, under the RFC 9325 profile: ECDHE with AEAD suites only and
     * Extended Master Secret required. TCP only; it lets any peer without 1.3 downgrade the connection to 1.2.
     */
    Tls12And13,
}

/** Whether a server asks for a client certificate (RFC 8446 section 4.3.2); a client configuration refuses anything but [None]. */
public enum class ClientAuth {
    /** No CertificateRequest is sent and clients stay anonymous at the TLS level: the default. */
    None,

    /** A certificate is requested; a client without one is accepted, a presented one must pass [TlsConfig.trust]. */
    Optional,

    /** A certificate is requested and the handshake fails unless the client presents one that passes [TlsConfig.trust]. */
    Required,
}

/** TLS 1.3 cipher suites in preference order. CCM_8 is refused for QUIC (RFC 9001 section 5.3). */
public class CipherSuites(
    suites: List<String>,
) {
    /**
     * The IANA suite names (RFC 8446 appendix B.4), most preferred first; never empty. They configure TLS 1.3 only: with
     * [TlsVersions.Tls12And13] the TLS 1.2 suites are the fixed ECDHE + AEAD list of the RFC 9325 profile.
     */
    public val suites: List<String> = suites.toList()

    init {
        require(suites.isNotEmpty()) { "at least one cipher suite" }
    }

    internal val openSslList: String get() = suites.joinToString(":")

    /** The suite names this stack supports and the default order. */
    public companion object {
        /** `TLS_AES_128_GCM_SHA256`, mandatory to implement in TLS 1.3 (RFC 8446 section 9.1). */
        public const val AES_128_GCM: String = "TLS_AES_128_GCM_SHA256"

        /** `TLS_AES_256_GCM_SHA384`. */
        public const val AES_256_GCM: String = "TLS_AES_256_GCM_SHA384"

        /** `TLS_CHACHA20_POLY1305_SHA256`, fast on CPUs without AES instructions. */
        public const val CHACHA20_POLY1305: String = "TLS_CHACHA20_POLY1305_SHA256"

        /** AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 in this order: OpenSSL's TLS 1.3 default, valid for TCP and QUIC. */
        public val Default: CipherSuites = CipherSuites(listOf(AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305))
    }
}

/**
 * Server-side session tickets (TCP): a current key and previous keys; rotation at most weekly, lifetime at most half of it.
 * Invalid values throw [TlsException.Config] on construction. QUIC sessions ignore it.
 *
 * @property rotateEvery how often the process-wide generated keys rotate (default 1 day, at most 7 days); the previous key
 *   still decrypts until the next rotation. Explicit [keys] are not rotated by the library. A longer period lets one stolen
 *   ticket key decrypt more resumed sessions (RFC 8446 section 4.6.1).
 * @property ticketLifetime how long an issued ticket resumes (default 12 hours, at most [rotateEvery] / 2, whole seconds);
 *   a longer lifetime widens the window in which resumptions can be linked to one client.
 */
public class SessionTicketConfig(
    keys: List<ByteArray>? = null,
    public val rotateEvery: Duration = 1.days,
    public val ticketLifetime: Duration = 12.hours,
) {
    /** 80-byte entries (name 16 | AES-256 32 | HMAC-SHA256 32), first encrypts; null = fresh random keys per process. */
    public val keys: List<ByteArray>? = keys?.map { it.copyOf() }

    init {
        if (rotateEvery > 7.days) throw TlsException.Config("rotateEvery must be at most 7 days")
        if (ticketLifetime > rotateEvery / 2) throw TlsException.Config("ticketLifetime must be at most rotateEvery / 2")
        if (keys != null && (keys.isEmpty() || keys.any { it.size != 80 })) throw TlsException.Config("ticket keys are 80-byte entries")
    }

    /** Holds [Default]. */
    public companion object {
        /** Generated keys rotated daily, 12-hour tickets: the right choice unless several server processes must share keys. */
        public val Default: SessionTicketConfig = SessionTicketConfig()
    }
}

/** Immutable TLS configuration (docs/guide/tls.md, Configuration); build it with [tlsConfig] or [Builder]. */
public class TlsConfig private constructor(
    /** Which side of the handshake this configuration drives. */
    public val role: TlsRole,
    /** ALPN protocol IDs in preference order (RFC 7301); empty means no ALPN extension. See [Builder.alpn]. */
    public val alpn: List<String>,
    /** A client's SNI and reference identifier, as configured (not normalized); see [Builder.serverName]. */
    public val serverName: String?,
    /** The TLS versions offered and accepted; see [Builder.versions]. */
    public val versions: TlsVersions,
    /** The TLS 1.3 cipher suites in preference order; see [Builder.cipherSuites]. */
    public val cipherSuites: CipherSuites,
    /** The certificate chain and key this side presents, if any; see [Builder.identity]. */
    public val identity: TlsIdentity?,
    /** How the peer's certificate is trusted (ADR-0011); see [Builder.trust]. */
    public val trust: TrustConfig,
    /** Whether a server asks for a client certificate; see [Builder.clientAuth]. */
    public val clientAuth: ClientAuth,
    /** A server's per-connection identity choice from the ClientHello (TCP only); see [Builder.sniSelector]. */
    public val sniSelector: (suspend (ClientHelloInfo) -> ServerTlsOverride?)?,
    /** Session ticket keys and lifetimes of a TCP server; see [Builder.sessionTickets]. */
    public val sessionTickets: SessionTicketConfig,
    /** Where TLS secrets are written for debugging, null (the default) for nowhere; see [Builder.keylog]. */
    public val keylog: KeylogSink?,
    /** The deadline of a TLS-over-TCP handshake; see [Builder.handshakeTimeout]. */
    public val handshakeTimeout: Duration,
    /** Whether every verification failure is sent as `handshake_failure`; see [Builder.genericAlerts]. */
    public val genericAlerts: Boolean,
) {
    /** A copy with one connection's selector override applied (server side); the override passes the checks of [Builder.build]. */
    internal fun withOverride(o: ServerTlsOverride): TlsConfig {
        val overrideAlpn = o.alpn?.toList()?.also { validateAlpn(it) } // copy first: the stored list is the one validated
        checkServerAuth(o.clientAuth ?: clientAuth, o.trust ?: trust)
        return TlsConfig(
            role,
            overrideAlpn ?: alpn,
            serverName,
            versions,
            cipherSuites,
            o.identity,
            o.trust ?: trust,
            o.clientAuth ?: clientAuth,
            null,
            sessionTickets,
            keylog,
            handshakeTimeout,
            genericAlerts,
        )
    }

    /** Validates the combination for the transport it is used with; QUIC is stricter (RFC 9001 section 4.2). */
    internal fun validateFor(quic: Boolean) {
        if (quic) {
            if (versions != TlsVersions.Tls13) throw TlsException.Config("QUIC requires TLS 1.3 only")
            if (alpn.isEmpty()) throw TlsException.Config("QUIC requires a non-empty ALPN list")
            if (cipherSuites.suites.any {
                    it.contains(
                        "CCM_8",
                    )
                }
            ) {
                throw TlsException.Config("TLS_AES_128_CCM_8_SHA256 is not allowed in QUIC")
            }
            if (sniSelector !=
                null
            ) {
                throw TlsException.Config(
                    "sniSelector is not supported for QUIC sessions in v1 (drive() is synchronous); use TlsConnection or a per-identity server",
                )
            }
        }
    }

    /** Throws [TlsException.Config] unless this config can drive a QUIC handshake: TLS 1.3 only, a non-empty ALPN list, no CCM_8, no `sniSelector` in v1 (RFC 9001 sections 4.2, 5.3, 8.1). */
    @InternalKuicksilverApi
    public fun checkQuicCompatible(): Unit = validateFor(quic = true)

    /**
     * Mutable builder behind [tlsConfig]; every property starts at its safe default and [build] validates the combination.
     * Not thread-safe; use one builder per configuration.
     *
     * @property role the side the configuration is for, fixed at creation.
     */
    @KuicksilverDsl
    public class Builder(
        public val role: TlsRole,
    ) {
        /**
         * ALPN protocol IDs in preference order (RFC 7301), each 1..255 bytes of UTF-8 and at most 255 bytes together with one length byte each; default empty, which sends no ALPN
         * extension. QUIC needs at least one (RFC 9001 section 8.1); a server that shares none with the client's offer
         * fails the handshake with `no_application_protocol`.
         */
        public var alpn: List<String> = emptyList()

        /**
         * Client: the host name sent as SNI and, unless [TrustConfig.ExpectedName] replaces it, the reference identifier the
         * certificate must match (RFC 9525); an IP literal is matched but never sent as SNI (RFC 6066 section 3). Default null;
         * a client needs it or an ExpectedName. Validated by [HostName.normalize] in [build]. Servers ignore it.
         */
        public var serverName: String? = null

        /** The versions offered; default [TlsVersions.Tls13]. [TlsVersions.Tls12And13] is for TCP peers without TLS 1.3 only. */
        public var versions: TlsVersions = TlsVersions.Tls13

        /** The TLS 1.3 cipher suites in preference order; default [CipherSuites.Default]. QUIC refuses CCM_8 suites. */
        public var cipherSuites: CipherSuites = CipherSuites.Default

        /**
         * The chain and private key this side presents: required for a server unless [sniSelector] supplies one per connection,
         * optional for a client (sent when the server asks for a certificate). Default null. v1 accepts [TlsIdentity.InMemory].
         */
        public var identity: TlsIdentity? = null

        /**
         * How the peer is trusted; default [TrustConfig.Platform], the OS trust store. A client checks the server with it; a
         * server checks client certificates with it when [clientAuth] is not [ClientAuth.None], and then v1 accepts only
         * [TrustConfig.AnchoredCa], optionally inside [TrustConfig.Pinned] (ADR-0012). The host name check is never disabled.
         */
        public var trust: TrustConfig = TrustConfig.Platform

        /** Whether a server requests a client certificate; default [ClientAuth.None]. Anything else needs an AnchoredCa [trust]. */
        public var clientAuth: ClientAuth = ClientAuth.None

        /**
         * Server, TCP only: called with the ClientHello while the handshake is paused, it chooses this connection's identity
         * and settings. Null from it with SNI present ends the handshake with `unrecognized_name`; without SNI the default
         * [identity] is used. Default null; a QUIC session refuses a configuration that has one ([TlsException.Config], v1).
         */
        public var sniSelector: (suspend (ClientHelloInfo) -> ServerTlsOverride?)? = null

        /** Session ticket keys and lifetimes of a TCP server; default [SessionTicketConfig.Default]. Clients and QUIC ignore it. */
        public var sessionTickets: SessionTicketConfig = SessionTicketConfig.Default

        /**
         * Receives the handshake secrets as RFC 9850 key log lines, so that a capture can be decrypted; default null, and
         * keep it null in production: anyone who reads the sink can decrypt the traffic. `SSLKEYLOGFILE` is never read.
         */
        @DelicateKuicksilverApi public var keylog: KeylogSink? = null

        /**
         * The deadline of a TLS-over-TCP handshake ([TlsConnection], `Socket.tls`); default 10 seconds. When it passes the
         * handshake fails with [TlsException.Protocol]. QUIC connections use their own `QuicConfig.handshakeTimeout`.
         */
        public var handshakeTimeout: Duration = 10.seconds

        /**
         * Send every verification failure as `handshake_failure` instead of the specific alert. Default false; true hides
         * from the peer why it was rejected at the cost of harder diagnosis on its side. The local [TlsException.Verify]
         * keeps the real reason either way.
         */
        public var genericAlerts: Boolean = false

        /**
         * Validates the settings and returns an immutable [TlsConfig]. Throws [TlsException.Config] for an ALPN entry that is
         * empty or longer than 255 bytes (UTF-8) or a list longer than 255 bytes on the wire, a server without [identity] or [sniSelector], [clientAuth] on a client or without an
         * AnchoredCa [trust], and an invalid [serverName] or ExpectedName. Transport-specific rules (QUIC) are checked when
         * the configuration is used.
         */
        @OptIn(DelicateKuicksilverApi::class)
        public fun build(): TlsConfig {
            val validAlpn = alpn.toList().also { validateAlpn(it) } // copy first: the stored list is the one validated
            if (role == TlsRole.Server) {
                if (identity == null && sniSelector == null) throw TlsException.Config("a server needs an identity or an sniSelector")
                checkServerAuth(clientAuth, trust)
            } else {
                if (clientAuth != ClientAuth.None) throw TlsException.Config("clientAuth applies to servers")
                serverName?.let { HostName.normalize(it) }
            }
            if (trust is TrustConfig.ExpectedName) HostName.normalize((trust as TrustConfig.ExpectedName).name)
            return TlsConfig(
                role,
                validAlpn,
                serverName,
                versions,
                cipherSuites,
                identity,
                trust,
                clientAuth,
                sniSelector,
                sessionTickets,
                keylog,
                handshakeTimeout,
                genericAlerts,
            )
        }
    }
}

/** The longest ALPN list `ksl` takes on the wire (each name with its length byte). */
private const val ALPN_WIRE_MAX = 255

/** RFC 7301 section 3.1: each protocol name is 1..255 bytes of UTF-8 and the whole list fits [ALPN_WIRE_MAX] bytes on the wire. */
internal fun validateAlpn(alpn: List<String>) {
    var wire = 0
    for (p in alpn) {
        val n = p.encodeToByteArray().size
        if (n == 0 || n > 255) throw TlsException.Config("ALPN entries must be 1..255 bytes")
        wire += 1 + n
    }
    if (wire > ALPN_WIRE_MAX) throw TlsException.Config("the ALPN list must fit $ALPN_WIRE_MAX bytes on the wire (it takes $wire)")
}

/** Client certificates are verified against an AnchoredCa trust only (optionally inside Pinned) in v1. */
private fun checkServerAuth(
    clientAuth: ClientAuth,
    trust: TrustConfig,
) {
    if (clientAuth == ClientAuth.None) return
    val base = if (trust is TrustConfig.Pinned) trust.base else trust
    if (base !is TrustConfig.AnchoredCa) {
        throw TlsException.Config("client certificates are verified against AnchoredCa only (optionally with Pinned) in v1")
    }
}

/** DSL entry point: `tlsConfig(TlsRole.Client) { serverName = "example.com"; alpn = listOf("h3") }`. */
public inline fun tlsConfig(
    role: TlsRole,
    block: TlsConfig.Builder.() -> Unit,
): TlsConfig = TlsConfig.Builder(role).apply(block).build()

/**
 * What a server's [TlsConfig.sniSelector] sees.
 *
 * @property serverName the host name from the client's SNI extension (RFC 6066), or null when it sent none; unverified input.
 * @property alpn the protocols the client offers (RFC 7301), in its preference order; empty without ALPN.
 * @property signatureSchemes the TLS SignatureScheme code points of `signature_algorithms` (RFC 8446 section 4.2.3), e.g.
 *   `0x0403` for ecdsa_secp256r1_sha256, so the selector can pick an identity whose key the client can verify.
 */
public class ClientHelloInfo(
    public val serverName: String?,
    public val alpn: List<String>,
    public val signatureSchemes: List<Int>,
)

/**
 * What a server's selector may override for one connection. `null` from the selector with a presented SNI is fatal (`unrecognized_name`).
 *
 * @property identity the chain and key presented on this connection instead of [TlsConfig.identity].
 * @property alpn replaces [TlsConfig.alpn] for this connection; null keeps it.
 * @property clientAuth replaces [TlsConfig.clientAuth] for this connection; null keeps it.
 * @property trust replaces [TlsConfig.trust] for client certificates on this connection; null keeps it. The override passes
 *   the checks of [TlsConfig.Builder.build]: with client certificates the trust must be AnchoredCa (optionally inside Pinned)
 *   and ALPN entries are counted in bytes; a failing override aborts that connection's handshake with [TlsException.Config].
 */
public class ServerTlsOverride(
    public val identity: TlsIdentity,
    public val alpn: List<String>? = null,
    public val clientAuth: ClientAuth? = null,
    public val trust: TrustConfig? = null,
)
