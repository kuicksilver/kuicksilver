// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.util.logging.KtorSimpleLogger
import io.ktor.util.logging.Logger
import io.ktor.util.logging.isDebugEnabled
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.annotations.KuicksilverDsl
import io.kuicksilver.annotations.SecuritySensitive
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http3.Http3EarlyDataPolicy
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.ConnectionListener
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicLbConfig
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.CipherSuites
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.ClientHelloInfo
import io.kuicksilver.tls.EchServerKeys
import io.kuicksilver.tls.KeyExchangeGroups
import io.kuicksilver.tls.KeylogSink
import io.kuicksilver.tls.OcspStapling
import io.kuicksilver.tls.ServerTlsOverride
import io.kuicksilver.tls.SessionTicketConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsVersions
import io.kuicksilver.tls.TrustConfig
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * The TLS of every TLS connector (`tlsConnector { }`, which may override any of it with its own `tls { }`) and of Ktor's own
 * connectors (`port = …`, `connector { }`, the deployment port of `EngineMain`), which serve TLS once this has an identity
 * ([identity] or [pemFiles]). HTTP/3 on the UDP twin of a port shares it; QUIC is TLS 1.3 only.
 */
@KuicksilverDsl
public class ServerTlsConfig internal constructor() {
    /** Where this block's identity came from: nothing set here, [identity], or [pemFiles]. */
    private enum class Source { None, Value, Files }

    private var identitySource = Source.None
    private var trustSource = Source.None
    private var ocspSource = Source.None
    private var identityValue: TlsIdentity? = null
    private var clientTrustValue: TrustConfig? = null
    private var ocspValue: OcspStapling? = null

    /**
     * The certificate chain and key, shared by TCP and QUIC; null by default. A `TlsIdentity.Reloadable` lets the
     * certificate be replaced while the server runs (docs/guide/ktor.md, "Certificate rotation"); [pemFiles] reads one from
     * files. Setting it in a block that called [pemFiles] fails with IllegalArgumentException: one identity, one source
     * (null sets none, so [pemFiles] may follow it).
     */
    @SecuritySensitive
    public var identity: TlsIdentity?
        get() = identityValue
        set(value) {
            require(identitySource != Source.Files) {
                "tls { identity } and tls { pemFiles(...) } are two sources of one identity: set one"
            }
            identityValue = value
            // null sets no identity: pemFiles may still give the one source
            identitySource = if (value == null) Source.None else Source.Value
            identityFiles = null
        }

    /** The chain and key files of [pemFiles] when this block called it: what [reloadInterval] watches. */
    internal var identityFiles: Pair<String, String>? = null
        private set

    /** The files of the identity this block inherits from the engine's (a connector's block), watched by the engine's watcher. */
    internal var inheritedIdentityFiles: Boolean = false
        private set

    /**
     * Reads the server certificate chain (PEM, leaf first) from [certificateChain] and the unencrypted PKCS#8 key
     * (`-----BEGIN PRIVATE KEY-----`) from [privateKey] now, as [identity]; with [reloadInterval] the engine watches both
     * files for a renewed certificate (certbot, a Kubernetes secret). The engine closes the identity read here when it stops.
     *
     * @throws IllegalArgumentException when this block set [identity].
     * @throws kotlinx.io.IOException when a file cannot be read or is larger than 1 MiB.
     * @throws io.kuicksilver.tls.TlsException.Config when a file holds no certificate or a damaged one, the key is
     *   encrypted, or the key does not match the chain.
     */
    @SecuritySensitive
    public fun pemFiles(
        certificateChain: String,
        privateKey: String,
    ) {
        require(identitySource != Source.Value) { "tls { identity } and tls { pemFiles(...) } are two sources of one identity: set one" }
        val loaded = TlsIdentity.fromPem(readPemText(certificateChain), readPemKey(privateKey))
        (ownedIdentity as? AutoCloseable)?.close()
        ownedIdentity = loaded
        identityValue = loaded
        identitySource = Source.Files
        identityFiles = certificateChain to privateKey
    }

    /** The identity [pemFiles] read: the engine's own, closed when it stops (or replaced by the reloadable over it). */
    internal var ownedIdentity: TlsIdentity? = null
        private set

    /**
     * How often the files of [pemFiles] are checked for a renewed certificate (and those of [clientCaFile] and
     * [ocspStaplingFile] for a new bundle or response); null (the default) reads them once. A new chain is applied once two
     * reads a second apart agree and the key matches it; a failure keeps what is in use, is logged, and is retried after 1 s,
     * then twice as long each time up to this interval. New handshakes get the new certificate, running connections keep
     * theirs (docs/guide/ktor.md, "Certificate rotation"). It needs [pemFiles]: the start fails without them (call
     * `TlsIdentity.Reloadable.reload` yourself for an identity of your own). With it a chain file that also holds the
     * private key is refused, as the watcher would refuse it. At least 1 second.
     *
     * @throws IllegalArgumentException when set below 1 second.
     */
    public var reloadInterval: Duration? = null
        set(value) {
            require(value == null || value >= 1.seconds) { "tls { reloadInterval } must be at least 1 second, or null" }
            field = value
        }

    /**
     * Ask for ([ClientAuth.Optional]) or require ([ClientAuth.Required]) a client certificate; [ClientAuth.None] by default.
     * Other than None it needs [clientTrust] (or [clientCaFile]): the start fails without.
     */
    @SecuritySensitive
    public var clientAuth: ClientAuth = ClientAuth.None

    /**
     * Verifies client certificates (`TrustConfig.AnchoredCa`, optionally pinned); null by default. A
     * `TrustConfig.ReloadableCa` replaces the CA bundle at run time: once `reload` returns, no handshake on TCP or QUIC
     * accepts a certificate only a removed CA vouches for (docs/guide/tls.md, "Rotating the client CA"). Setting it in a
     * block that called [clientCaFile] fails with IllegalArgumentException.
     */
    @SecuritySensitive
    public var clientTrust: TrustConfig?
        get() = clientTrustValue
        set(value) {
            require(
                trustSource != Source.Files,
            ) { "tls { clientTrust } and tls { clientCaFile(...) } are two sources of one trust: set one" }
            clientTrustValue = value
            trustSource = if (value == null) Source.None else Source.Value
            clientCaFile = null
        }

    /** The PEM file of [clientCaFile] when this block called it: watched with [reloadInterval]. */
    internal var clientCaFile: String? = null
        private set

    /**
     * Reads the CA certificates client certificates are verified against from the PEM file [path] now, as [clientTrust]
     * (an `AnchoredCa`); with [reloadInterval] the engine watches the file and applies a new bundle to new handshakes. A file
     * that also holds a private key is refused; certificates in it that are not CA certificates are named in a warning
     * (each is trusted as an anchor).
     *
     * @throws IllegalArgumentException when this block set [clientTrust].
     * @throws kotlinx.io.IOException when the file cannot be read, is larger than 1 MiB or holds a private key.
     * @throws io.kuicksilver.tls.TlsException.Config when it holds no certificate or a damaged one.
     */
    @SecuritySensitive
    public fun clientCaFile(path: String) {
        require(trustSource != Source.Value) { "tls { clientTrust } and tls { clientCaFile(...) } are two sources of one trust: set one" }
        // the watcher's checks at startup too: a key in the file is refused, a damaged file or one without a certificate fails
        val roots = Certificate.parsePem(readPemText(path, refusePrivateKey = true, holds = CA_FILE_HOLDS))
        warnNonCa(path, roots, CONFIG_LOG)
        clientTrustValue = TrustConfig.AnchoredCa(roots)
        trustSource = Source.Files
        clientCaFile = path
    }

    /**
     * The TLS versions TCP connections may negotiate: [TlsVersions.Tls13] (the default) refuses a client without TLS 1.3
     * with a `protocol_version` alert (RFC 9846 appendix E.2); [TlsVersions.Tls12And13] also serves TLS 1.2 clients (RFC
     * 9325 section 3.1.1: "Implementations MUST support TLS 1.2"), and a client that offers TLS 1.3 still gets it. TLS 1.2
     * runs under the RFC 9325 profile: ECDHE with AES-GCM or ChaCha20-Poly1305 only (no static RSA, no CBC, no SHA-1 MAC),
     * Extended Master Secret required, no renegotiation, no compression; a TLS 1.2 session resumes for at most
     * [SessionTicketConfig.ticketLifetime] after its full handshake, however often its ticket is renewed. HTTP/2 (when on)
     * is offered over TLS 1.2 as well (RFC 9113 section 9.2), but only where the deployment supports the suite section 9.2.2
     * requires of it, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 with P-256: a TLS 1.2 handshake whose certificate has no
     * rsaEncryption key gets `http/1.1` (the start says so at Info), and the start fails when [keyExchangeGroups] leaves
     * `secp256r1` out. HTTP/3 stays TLS 1.3 (RFC 9001 section 4.2).
     */
    @SecuritySensitive
    public var versions: TlsVersions = TlsVersions.Tls13

    /** The TLS 1.3 cipher suites in preference order; AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 by default. */
    @SecuritySensitive
    public var cipherSuites: CipherSuites = CipherSuites.Default

    /**
     * Picks an identity per SNI name (`TlsConfig.Builder.sniSelector`), on TCP and HTTP/3 connections alike: one selector
     * answers both, so a name gets the same certificate, client-certificate policy and staple over HTTP/1.1, HTTP/2 and
     * HTTP/3, and the `Alt-Svc` the TCP side advertises leads to a QUIC endpoint that presents the same identity. On HTTP/3
     * it runs off the connection's loop, as on TCP inside the handshake. An answer's `alpn` restricts the name: without one
     * the name gets every protocol of the connector; with one, TCP negotiates from it without `h3` (QUIC only, RFC 9114
     * section 3.1: a list of `h3` alone ends the name's TCP handshake with `no_application_protocol`; a client without ALPN
     * speaks HTTP/1.1, RFC 9113 section 3.3, refused there when the list leaves `http/1.1` out), and HTTP/3 is served (and
     * advertised with `Alt-Svc` on that name's TCP responses) only when it lists `h3`, else the QUIC handshake ends with
     * `no_application_protocol`. Return the same `TrustConfig` and `OcspStapling` objects for a name, so that its handshakes
     * share one TLS context. Null with SNI present refuses the handshake (`unrecognized_name`); null for a ClientHello
     * without SNI leaves [identity] to answer it. A request on such a connection must be for the name its identity was
     * chosen for (else 421, RFC 9110 section 7.4). Null by default.
     */
    public var sniSelector: (suspend (ClientHelloInfo) -> ServerTlsOverride?)? = null

    /**
     * Session ticket keys and lifetimes (TLS resumption on TCP, and the QUIC side's tickets); [SessionTicketConfig.Default]
     * (keys made and rotated in process) by default.
     */
    @SecuritySensitive
    public var sessionTickets: SessionTicketConfig = SessionTicketConfig.Default

    /**
     * The key-exchange groups of TCP and QUIC handshakes, in the server's order of preference
     * (`TlsConfig.Builder.keyExchangeGroups`); default [KeyExchangeGroups.Default]. The server takes the first of them a
     * client sent a key share for, else asks for the first the client supports with a HelloRetryRequest; a client with none
     * of them is refused with `handshake_failure`. Key shares are a client's setting: a list with them makes the start
     * fail. With [versions] Tls12And13 the list needs an elliptic curve, the hybrids being TLS 1.3 only, and with
     * [clientAuth] it also limits the curves of a TLS 1.2 client's ECDSA certificate (RFC 8422 section 5.1).
     */
    @ExperimentalKuicksilverApi
    @SecuritySensitive
    public var keyExchangeGroups: KeyExchangeGroups = KeyExchangeGroups.Default

    /**
     * The OCSP response to staple for [identity] on TCP and QUIC (RFC 6066 section 8, RFC 9325 section 7.5;
     * docs/guide/tls.md, "Certificate revocation"); null by default. `OcspStapling.update` replaces it while the server
     * runs. Setting it in a block that called [ocspStaplingFile] fails with IllegalArgumentException.
     */
    @ExperimentalKuicksilverApi
    public var ocspStapling: OcspStapling?
        get() = ocspValue
        set(value) {
            require(
                ocspSource != Source.Files,
            ) { "tls { ocspStapling } and tls { ocspStaplingFile(...) } are two sources of one response: set one" }
            ocspValue = value
            ocspSource = if (value == null) Source.None else Source.Value
            ocspFile = null
        }

    /** The file of [ocspStaplingFile] when this block called it. */
    internal var ocspFile: String? = null
        private set

    /**
     * Reads the DER `OCSPResponse` (RFC 6960, at most 1 MiB) in [path] now, as [ocspStapling]. Whether it is stapled is
     * logged at startup and when that changes (checked every [reloadInterval], re-reading the file, or hourly without one:
     * a response expires).
     *
     * @throws IllegalArgumentException when this block set [ocspStapling].
     * @throws kotlinx.io.IOException when the file cannot be read or is larger than 1 MiB.
     * @throws io.kuicksilver.tls.TlsException.Config when it is empty or not a DER SEQUENCE.
     */
    @ExperimentalKuicksilverApi
    public fun ocspStaplingFile(path: String) {
        require(
            ocspSource != Source.Value,
        ) { "tls { ocspStapling } and tls { ocspStaplingFile(...) } are two sources of one response: set one" }
        ocspValue = OcspStapling(readOcspResponseFile(path))
        ocspSource = Source.Files
        ocspFile = path
    }

    /** Tests: [stapling] as if [ocspStaplingFile] had read it from [path]. */
    internal fun ocspStaplingFileForTest(
        stapling: OcspStapling,
        path: String,
    ) {
        ocspValue = stapling
        ocspSource = Source.Files
        ocspFile = path
    }

    /**
     * The Encrypted Client Hello keys (RFC 9849, shared mode) of TCP and QUIC handshakes alike; null (the default) ignores a
     * client's ECH (it is told nothing, and goes on with its outer ClientHello). Publish the keys' ECHConfigList in the
     * `ech` parameter of the HTTPS record of every name served (RFC 9848). [EchServerKeys.rotate] replaces the keys while
     * the server runs. A client whose ECH is not decrypted (an old key, GREASE) gets the keys' retry configurations and must
     * authenticate the certificate for the configurations' `public_name` (RFC 9849 section 6.1.7): [identity] (or what
     * [sniSelector] answers for that name) must be valid for it.
     */
    @ExperimentalKuicksilverApi
    @SecuritySensitive
    public var echKeys: EchServerKeys? = null

    /**
     * Receives the handshake secrets of TCP and QUIC connections as RFC 9850 key log lines; null by default, and keep it
     * null in production: anyone who reads the sink can decrypt the traffic.
     */
    @DelicateKuicksilverApi
    @SecuritySensitive
    public var keylog: KeylogSink? = null

    /** Set by `EngineMain`, which read [echKeys] from files: the engine closes them when it stops. */
    internal var closeEchKeysOnStop: Boolean = false

    /** Tests shorten the identity watcher's settle time (two equal reads of a changed chain); null keeps 1 s. */
    internal var settleForTest: Duration? = null

    /** Tests replace how the identity watcher reads the chain file (a read that never returns, say); null reads the file. */
    internal var readTextForTest: ((String) -> String)? = null

    /**
     * A block for a connector that starts from [base] (the engine's resolved TLS): what it does not set is inherited, what it
     * sets overrides, an identity or trust of its own included (the inherited files stay the engine's to watch).
     */
    @OptIn(DelicateKuicksilverApi::class)
    internal fun inherit(base: ResolvedServerTls) {
        identityValue = base.identity
        inheritedIdentityFiles = base.identityFiles != null || base.inheritedIdentityFiles
        clientTrustValue = base.trust
        ocspValue = base.ocspStapling
        reloadInterval = base.reloadInterval
        clientAuth = base.clientAuth
        versions = base.versions
        cipherSuites = base.cipherSuites
        sniSelector = base.sniSelector
        sessionTickets = base.sessionTickets
        keyExchangeGroups = base.keyExchangeGroups
        echKeys = base.echKeys
        keylog = base.keylog
    }

    /**
     * These settings with what they read from files made reloadable when [reloadInterval] is set. Throws
     * IllegalArgumentException for a combination that cannot work, naming the options ([where] is the block's path).
     */
    @OptIn(DelicateKuicksilverApi::class)
    internal fun resolve(where: String): ResolvedServerTls {
        val reload = reloadInterval
        val files = identityFiles
        val inheritedFiles = inheritedIdentityFiles && identitySource == Source.None
        require(reload == null || files != null || inheritedFiles) {
            "$where { reloadInterval } watches the files of $where { pemFiles(...) }: set them, or call " +
                "TlsIdentity.Reloadable.reload yourself for an identity of your own"
        }
        require(clientAuth == ClientAuth.None || clientTrustValue != null) {
            "$where { clientAuth = $clientAuth } needs $where { clientTrust } or $where { clientCaFile(...) }: the client " +
                "certificates are verified against it"
        }
        var identity = identityValue
        var reloadableIdentity: TlsIdentity.Reloadable? = null
        if (reload != null && files != null) {
            // the watcher's checks at startup too: a chain file that holds the key (a combined PEM) is refused, and an
            // expired or not yet valid leaf is refused as every later reload would refuse it
            try {
                readPemText(files.first, refusePrivateKey = true)
                reloadableIdentity = TlsIdentity.reloadable(identity as TlsIdentity.InMemory)
            } catch (e: Throwable) {
                // the engine never serves it: its native key goes now
                (ownedIdentity as? AutoCloseable)?.close()
                throw e
            }
            identity = reloadableIdentity
        }
        var trust = clientTrustValue
        var reloadableCa: TrustConfig.ReloadableCa? = null
        if (reload != null && clientCaFile != null) {
            reloadableCa = TrustConfig.reloadable(trust as TrustConfig.AnchoredCa)
            trust = reloadableCa
        }
        return ResolvedServerTls(
            identity = identity,
            clientAuth = clientAuth,
            trust = trust,
            cipherSuites = cipherSuites,
            sniSelector = sniSelector,
            ocspStapling = ocspValue,
            versions = versions,
            keyExchangeGroups = keyExchangeGroups,
            echKeys = echKeys,
            sessionTickets = sessionTickets,
            keylog = keylog,
            reloadInterval = reload,
            identityFiles = files,
            inheritedIdentityFiles = inheritedFiles,
            reloadableIdentity = reloadableIdentity,
            ownedIdentity = if (identitySource == Source.Files) ownedIdentity else null,
            clientCaFile = clientCaFile,
            reloadableCa = reloadableCa,
            ocspFile = ocspFile,
            settle = settleForTest ?: 1.seconds,
            readText = readTextForTest,
        )
    }

    internal companion object {
        /** Where warnings about files read in the configuration go before the application exists (a client CA file with leaves). */
        val CONFIG_LOG: Logger = KtorSimpleLogger("io.kuicksilver.ktor.server.EngineMain")
    }
}

/**
 * A [ServerTlsConfig] as the engine serves it: the identity and trust made reloadable where [reloadInterval] watches their
 * files, and those files with what the watchers need.
 */
@OptIn(DelicateKuicksilverApi::class)
internal class ResolvedServerTls(
    val identity: TlsIdentity?,
    val clientAuth: ClientAuth,
    val trust: TrustConfig?,
    val cipherSuites: CipherSuites,
    val sniSelector: (suspend (ClientHelloInfo) -> ServerTlsOverride?)?,
    val ocspStapling: OcspStapling?,
    val versions: TlsVersions,
    val keyExchangeGroups: KeyExchangeGroups,
    val echKeys: EchServerKeys?,
    val sessionTickets: SessionTicketConfig,
    val keylog: KeylogSink?,
    val reloadInterval: Duration?,
    /** The chain and key files this block read (not inherited ones): the identity watcher's. */
    val identityFiles: Pair<String, String>?,
    /** Whether [identity] is the engine's, read from files the engine's watcher already watches. */
    val inheritedIdentityFiles: Boolean = false,
    val reloadableIdentity: TlsIdentity.Reloadable? = null,
    /** What the engine closes when it stops: the identity read from files (the reloadable over it, when there is one). */
    val ownedIdentity: TlsIdentity? = null,
    val clientCaFile: String? = null,
    val reloadableCa: TrustConfig.ReloadableCa? = null,
    val ocspFile: String? = null,
    val settle: Duration = 1.seconds,
    val readText: ((String) -> String)? = null,
) {
    /** What the engine closes at its stop: the reloadable over a file identity, else the identity read from files. */
    val closeOnStop: AutoCloseable? get() = reloadableIdentity ?: ownedIdentity as? AutoCloseable

    internal companion object {
        /** No TLS settings: an engine whose `tls { }` was never touched. */
        @OptIn(DelicateKuicksilverApi::class)
        val None: ResolvedServerTls = ServerTlsConfig().resolve("tls")
    }
}

/** HTTP/1.1 of the server engine. */
@KuicksilverDsl
public class Http1ServerConfig internal constructor() {
    /**
     * Whether a bare LF (one without the CR before it) ends a line of an HTTP/1.1 request head (the request line, a field
     * line, the empty line after them) and of a chunked request's trailer section; false by default. RFC 9112 section 2.2
     * lets a recipient take a bare LF as a line end (MAY) and warns in section 11.2 that lenient parsing "can result in
     * request smuggling" when parsers disagree: behind a proxy that reads a bare LF as part of a line, this server would
     * end the line there and frame the head otherwise. So by default such a request gets `400 Bad Request` and the
     * connection closes, as llhttp (Node.js, nghttpx) answers; Go's net/http and nginx accept it. Turn it on only for
     * hand-written clients (scripts, devices) that send LF alone, and only where no proxy in front forwards a bare LF. The
     * chunk-size line takes CRLF alone either way, and the empty lines a client may send before a request line are skipped,
     * a bare LF among them, either way. Not used by HTTP/2 or HTTP/3.
     */
    @DelicateKuicksilverApi
    @SecuritySensitive
    public var allowBareLf: Boolean = false
}

/**
 * HTTP/2 (RFC 9113) on the TLS connectors: ALPN offers `h2` before `http/1.1`, so a client that offers both gets HTTP/2
 * (docs/guide/ktor.md, "HTTP/2 on the server"). Plain connectors serve HTTP/2 only with their own opt-in, h2c
 * ([KuicksilverPlainConnector.Builder.h2c]), whose connections take [settings] and [repeatOffenderPenalty] too.
 */
@KuicksilverDsl
public class Http2ServerConfig internal constructor() {
    /**
     * Serve HTTP/2 on the TLS connectors; true by default (since 0.3.0): their ALPN offers `h2`, then `http/1.1`, so a
     * client that offers both (browsers, OkHttp, the JDK's client, curl, Kuicksilver's) gets HTTP/2. False keeps the ALPN at
     * `http/1.1`: the switch for a middlebox that breaks HTTP/2. Without it a plain connector's client that sends the
     * HTTP/2 preface is answered `505 HTTP Version Not Supported`, unless that connector has h2c. Over TLS 1.3, and over
     * TLS 1.2 where `tls { versions = TlsVersions.Tls12And13 }` allows it (RFC 9113 section 9.2). WebSockets come over
     * HTTP/2 too (RFC 8441), unless `webSockets { overHttp2 = false }`.
     */
    public var enabled: Boolean = true

    /**
     * Null (the default): each HTTP/2 connection that breaks a flood limit of [settings] is ended with GOAWAY
     * ENHANCE_YOUR_CALM, and that is all. A duration: a client address whose HTTP/2 connections end that way three times
     * within a minute has its TCP connections (HTTP/1.1 too) closed at accept, before the TLS handshake, for this long
     * (docs/guide/ktor.md, "HTTP/2 on the server"; threat model 3.23). An IPv6 client counts by its /56, an IPv4-mapped one
     * by its IPv4 address; a slow field block is not a strike. Enable it only where the server sees the real address of each
     * client: behind a NAT, a load balancer that rewrites source addresses (SNAT, Kubernetes `externalTrafficPolicy:
     * Cluster`) or a TCP proxy, every client shares the proxy's address and one flooder locks them all out.
     *
     * @throws IllegalArgumentException when set to zero, a negative duration or [Duration.INFINITE].
     */
    @ExperimentalKuicksilverApi
    @SecuritySensitive
    public var repeatOffenderPenalty: Duration? = null
        set(value) {
            require(value == null || (value.isPositive() && value.isFinite())) {
                "http2 { repeatOffenderPenalty } must be a positive duration, or null (off)"
            }
            field = value
        }

    internal val settingsBuilder: Http2Settings.Builder = Http2Settings.Builder()

    /**
     * The HTTP/2 SETTINGS, windows and flood limits of every HTTP/2 connection (`Http2Settings.Builder`, threat model 3.23).
     * The engine bounds `maxHeaderBlockTime` by its `requestHeaderTimeout`: a field block slower than the smaller of the two
     * ends the connection.
     */
    @ExperimentalKuicksilverApi
    public fun settings(block: Http2Settings.Builder.() -> Unit) {
        settingsBuilder.block()
    }
}

/** 0-RTT on HTTP/3 (ADR-0015); experimental. */
@ExperimentalKuicksilverApi
@KuicksilverDsl
public class ServerEarlyDataConfig internal constructor() {
    /**
     * Accept 0-RTT on HTTP/3 (off by default). Early requests can be replayed by an attacker: only those [policy] declares
     * replayable (GET, HEAD and OPTIONS by default) run before the handshake completes, every other request waits for it.
     * Handlers of early requests must be free of side effects; see `ApplicationRequest.receivedEarly`. A request a gateway
     * marked `Early-Data` (RFC 8470 section 5.1) is treated as early whatever this setting.
     */
    @SecuritySensitive
    public var enabled: Boolean = false

    /**
     * Which early requests run before the handshake completes; the others wait for it. [Http3EarlyDataPolicy.WaitForHandshake]
     * (GET, HEAD and OPTIONS replayable) by default. A request a gateway forwarded from early data that this does not declare
     * replayable gets `425 Too Early` (RFC 8470 section 5.1), on HTTP/3 and over TCP.
     */
    @SecuritySensitive
    public var policy: Http3EarlyDataPolicy = Http3EarlyDataPolicy.WaitForHandshake()
}

/** WebTransport over HTTP/3 (draft-ietf-webtrans-http3-17) to `webTransport(path) { }` routes; experimental. */
@ExperimentalKuicksilverApi
@KuicksilverDsl
public class ServerWebTransportConfig internal constructor() {
    /**
     * Serve WebTransport; false by default. Turns on the HTTP/3 SETTINGS it needs (Extended CONNECT, H3_DATAGRAM,
     * RESET_STREAM_AT). Needs QUIC datagrams (`http3 { quic { datagrams { maxFrameSize } } }`, on by default): the engine
     * refuses to start without.
     */
    public var enabled: Boolean = false

    /**
     * The most WebTransport sessions a client may open on one connection (`SETTINGS_WT_MAX_SESSIONS`), 1..65535; 4 by
     * default.
     *
     * @throws IllegalArgumentException when set outside 1..65535.
     */
    public var maxSessionsPerConnection: Int = 4
        set(value) {
            require(value in 1..65_535) { "http3 { webTransport { maxSessionsPerConnection } } must be 1..65535, not $value" }
            field = value
        }

    /** The bidirectional streams a client may open in one session at first (`SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI`); 24 by default. */
    public var initialMaxStreamsBidi: Long = 24

    /** The unidirectional streams a client may open in one session at first (`SETTINGS_WT_INITIAL_MAX_STREAMS_UNI`); 24 by default. */
    public var initialMaxStreamsUni: Long = 24

    /** The bytes a client may send in one session at first, over all its streams (`SETTINGS_WT_INITIAL_MAX_DATA`); 3,932,160 by default. */
    public var initialMaxData: Long = 3_932_160
}

/**
 * The QUIC endpoint of each HTTP/3 listener (one per TLS connector, on the UDP twin of its port): loops, admission limits
 * and load balancing.
 */
@KuicksilverDsl
public class ServerEndpointConfig internal constructor() {
    /**
     * Endpoint loops on the UDP port, on every platform with a QUIC server: a socket per loop with kernel `SO_REUSEPORT`
     * flow hashing on Linux and Android, one socket whose datagrams are routed to the loops by connection ID in process on
     * macOS, iOS and Windows (docs/guide/quic.md, "Several loops on one port"). One connection runs on one loop. Where the
     * accelerated socket cannot open (a JVM on the portable socket), more than 1 cannot run: the engine logs why and serves
     * HTTP/1.1 only on that connector. 1..255; 1 by default.
     *
     * @throws IllegalArgumentException when set outside 1..255.
     */
    public var loops: Int = 1
        set(value) {
            require(value in 1..255) { "http3 { endpoint { loops } } must be 1..255" }
            field = value
        }

    /**
     * The most QUIC connections each HTTP/3 listener holds at once, handshakes in flight included, over all its [loops]
     * together: beyond it a new client's Initial is dropped silently and counted in `EndpointStats.connectionsRefusedLimits`
     * ([KuicksilverApplicationEngine.http3Stats]). At least 1; default 10,000.
     *
     * @throws IllegalArgumentException when set below 1.
     */
    @SecuritySensitive
    public var maxConnections: Int = 10_000
        set(value) {
            require(value >= 1) { "http3 { endpoint { maxConnections } } must be at least 1" }
            field = value
        }

    /**
     * The most QUIC connections one client IP holds at once on each HTTP/3 listener, over all its [loops] together, ports
     * ignored; null turns the limit off. Beyond it a new client's Initial is dropped silently (the client fails at its
     * handshake timeout), counted in `EndpointStats.connectionsRefusedLimits`, and logged once per 5 minutes. Behind a NAT,
     * Kubernetes `kube-proxy` with `externalTrafficPolicy: Cluster`, or a UDP load balancer that does not keep client
     * addresses, every client shares one address: set null there (docs/guide/deployment.md, "QUIC connection limits"). On
     * by default (256), unlike `tcp { maxConnectionsPerIp }`: QUIC Initials come unvalidated and cost more state, and a proxy
     * in front of QUIC is rare. At least 1, or null.
     *
     * @throws IllegalArgumentException when set below 1.
     */
    @SecuritySensitive
    public var maxConnectionsPerIp: Int? = 256
        set(value) {
            require(value == null || value >= 1) { "http3 { endpoint { maxConnectionsPerIp } } must be at least 1, or null (off)" }
            field = value
        }

    /**
     * Handshaken QUIC connections waiting for the engine's HTTP/3 accept loop on each listener, all its loops together:
     * while this many wait, a new client is refused at once with CONNECTION_REFUSED, counted in
     * `EndpointStats.connectionsRefusedAcceptQueue`. At least 1; default 128.
     *
     * @throws IllegalArgumentException when set below 1.
     */
    public var acceptQueue: Int = 128
        set(value) {
            require(value >= 1) { "http3 { endpoint { acceptQueue } } must be at least 1" }
            field = value
        }

    /**
     * Admission of new QUIC connections: `ConnectionAdmission.default()` (a Retry above 256 handshakes in flight or 8 MiB of
     * their buffers) by default; Ktor-Netty's `quicTokenHandler`. While `http3Advertising` is `Drain`, every new client is
     * refused with CONNECTION_REFUSED whatever this says.
     */
    @SecuritySensitive
    public var admission: ConnectionAdmission = ConnectionAdmission.default()

    /**
     * A server connection older than this is closed with NO_ERROR, whatever its activity; null (the default) for no limit.
     *
     * @throws IllegalArgumentException when set to zero, a negative duration or [Duration.INFINITE].
     */
    public var maxConnectionLifetime: Duration? = null
        set(value) {
            require(value == null || (value.isPositive() && value.isFinite())) {
                "http3 { endpoint { maxConnectionLifetime } } must be a positive duration, or null (no limit)"
            }
            field = value
        }

    /**
     * The QUIC-LB configuration of every HTTP/3 listener's connection IDs (draft-ietf-quic-load-balancers-21;
     * docs/guide/quic.md, "Behind a load balancer"); null (the default) for none. The listeners' connection ID length
     * follows it, and `expert { connectionIdLength }` is refused next to it. Change it on the running engine with
     * [KuicksilverApplicationEngine.updateLoadBalancer].
     */
    @ExperimentalKuicksilverApi
    public var loadBalancer: QuicLbConfig? = null

    internal val endpointBuilder: QuicEndpointConfig.Builder = QuicEndpointConfig.Builder()

    /** The connection ID length and the admission internals few servers need; experimental. */
    @ExperimentalKuicksilverApi
    public val expert: ServerEndpointExpert = ServerEndpointExpert(endpointBuilder.expert)

    /** Sets the [expert] options. */
    @ExperimentalKuicksilverApi
    public fun expert(block: ServerEndpointExpert.() -> Unit) {
        expert.block()
    }
}

/**
 * The expert options of the HTTP/3 listeners' QUIC endpoints: the connection ID length, and the admission internals of
 * `QuicEndpointConfig.Builder.Expert` (stateless limits, the Initial queue, reflective ports); experimental.
 */
@ExperimentalKuicksilverApi
@KuicksilverDsl
public class ServerEndpointExpert internal constructor(
    private val endpoint: QuicEndpointConfig.Builder.Expert,
) {
    /** Whether [connectionIdLength] was assigned: with `loadBalancer` the engine refuses it, since QUIC-LB dictates the length. */
    internal var connectionIdLengthAssigned: Boolean = false
        private set

    /**
     * Default 8 bytes (4..20): the length of every connection ID the listeners issue (RFC 9000 section 5.1), the length
     * their short headers are parsed with. With `loadBalancer` the length is the QUIC-LB configuration's, and setting this
     * fails the start.
     *
     * @throws IllegalArgumentException when set outside 4..20.
     */
    public var connectionIdLength: Int = 8
        set(value) {
            require(value in 4..20) { "http3 { endpoint { expert { connectionIdLength } } } must be 4..20, not $value" }
            field = value
            connectionIdLengthAssigned = true
        }

    /** Default 1024, at least 1: Initials waiting for admission after one receive batch; more are dropped. */
    public var initialAdmissionQueue: Int by endpoint::initialAdmissionQueue

    /**
     * Default true: drop Initials whose source port is 53, 123, 1900, 5353 or 11211: a reflection attempt, never a real
     * client (threat-model 3.1). False only weakens the default.
     */
    @DelicateKuicksilverApi
    @SecuritySensitive
    public var rejectInitialFromReflectivePorts: Boolean by endpoint::rejectInitialFromReflectivePorts

    /**
     * Default 8 per second, at least 1: stateless answers (Retry, Version Negotiation, Stateless Reset, INVALID_TOKEN close)
     * per client address per second (RFC 9000 section 8: amplification).
     */
    @SecuritySensitive
    public var statelessPerAddressPerSecond: Int by endpoint::statelessPerAddressPerSecond

    /** Default 1000 per second, at least 1: stateless answers per second over all addresses. */
    @SecuritySensitive
    public var statelessTotalPerSecond: Int by endpoint::statelessTotalPerSecond
}

/**
 * HTTP/3 of the server engine (RFC 9114): served on UDP on the port of every TLS connector and announced with `Alt-Svc`.
 */
@KuicksilverDsl
public class Http3ServerConfig internal constructor() {
    /** Serve HTTP/3 on UDP on the port of every TLS connector; true by default. */
    public var enabled: Boolean = true

    /**
     * Announce HTTP/3 with `h3=":<port>"; ma=86400` over TLS (on by default): an `Alt-Svc` field on HTTP/1.1 and HTTP/2
     * responses, and on HTTP/2 also an ALTSVC frame per origin and value on each connection, refreshed every 12 hours (RFC
     * 7838 sections 3 and 4). The start logs, per port, that the UDP port must be open.
     */
    public var altSvc: Boolean = true

    /**
     * Serve CONNECT-UDP (RFC 9298) over HTTP/3 to `connectUdp(proxy)` routes (ADR-0024); false by default. Only HTTP/3
     * carries it. The proxy's target filter, limits and template are the `UdpProxy`'s the route is given; there is no
     * configuration-file key, since a filter or a resolver is code.
     */
    @ExperimentalKuicksilverApi
    @SecuritySensitive
    public var connectUdp: Boolean = false

    /** 0-RTT (ADR-0015); experimental. */
    @ExperimentalKuicksilverApi
    public val earlyData: ServerEarlyDataConfig = ServerEarlyDataConfig()

    /** Sets the [earlyData] options. */
    @ExperimentalKuicksilverApi
    public fun earlyData(block: ServerEarlyDataConfig.() -> Unit) {
        earlyData.block()
    }

    /** WebTransport; experimental. */
    @ExperimentalKuicksilverApi
    public val webTransport: ServerWebTransportConfig = ServerWebTransportConfig()

    /** Sets the [webTransport] options. */
    @ExperimentalKuicksilverApi
    public fun webTransport(block: ServerWebTransportConfig.() -> Unit) {
        webTransport.block()
    }

    internal val quicBuilder: QuicConfig.Builder = QuicConfig.Builder()

    /**
     * The QUIC transport of the HTTP/3 connections (`QuicConfig.Builder`). The engine derives and refuses
     * `expert { resetStreamAt }` (on with [webTransport]) and `expert { cancelErrorCode }` (HTTP/3 resets with its own
     * codes) with IllegalArgumentException at the start. `maxBidiStreams` and `expert { maxUniStreams }` stay settable:
     * left alone, they default to 100, raised to fit [webTransport]'s sessions (`max(100, sessions x (initialMaxStreamsBidi
     * + 1))` and `max(100, 3 + sessions x initialMaxStreamsUni)`); set, `expert { maxUniStreams }` must be at least 3 (RFC
     * 9114 section 6.2) and both must fit the sessions.
     */
    public fun quic(block: QuicConfig.Builder.() -> Unit) {
        quicBuilder.block()
    }

    internal val settingsBuilder: Http3Settings.Builder = Http3Settings.Builder()

    /**
     * The HTTP/3 SETTINGS and limits of the connections (`Http3Settings.Builder`: QPACK, field sections). The engine bounds
     * `maxHeaderBlockTime` by its `requestHeaderTimeout`, and derives and refuses `enableConnectProtocol` (from
     * `webSockets { overHttp3 }`, [webTransport] and [connectUdp]), `h3Datagram`, `webTransport { }` (from [webTransport])
     * and `earlyData` (from [earlyData]).
     */
    public fun settings(block: Http3Settings.Builder.() -> Unit) {
        settingsBuilder.block()
    }

    /** The QUIC endpoint of each HTTP/3 listener; change it with [endpoint]. */
    public val endpoint: ServerEndpointConfig = ServerEndpointConfig()

    /** Sets the [endpoint] options: `http3 { endpoint { maxConnectionsPerIp = null } }` behind a NAT. */
    public fun endpoint(block: ServerEndpointConfig.() -> Unit) {
        endpoint.block()
    }
}

/** WebSockets of the server engine, over HTTP/1.1, HTTP/2 and HTTP/3. */
@KuicksilverDsl
public class ServerWebSocketsConfig internal constructor() {
    /**
     * Accept WebSockets over HTTP/2 (RFC 8441): the HTTP/2 SETTINGS carry `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`, and an
     * Extended CONNECT with `:protocol = websocket` reaches Ktor's `webSocket {}` routes as an upgrade request
     * (docs/guide/ktor.md, "WebSockets over HTTP/2"). On by default; no effect while HTTP/2 is off. When false the parameter
     * is not sent, and a client keeps opening its WebSockets over HTTP/1.1.
     */
    public var overHttp2: Boolean = true

    /**
     * Accept WebSockets over HTTP/3 (RFC 9220): advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`. On by default. When false, a
     * WebSocket Extended CONNECT is answered 501 (RFC 9220 section 3), also while WebTransport advertises Extended CONNECT.
     */
    public var overHttp3: Boolean = true

    /**
     * The largest WebSocket message, and so frame, the server takes from a client, in bytes (RFC 6455 section 10.4: an
     * implementation "SHOULD impose a limit on frame sizes and the total message size after reassembly"); 16 MiB by
     * default, as `PerMessageDeflate`'s `maxInflatedMessageSize`. A frame whose header claims more, or that takes its
     * message past it, closes the connection with 1009 (message too big) before any of its payload is read; a compressed
     * message is held to the smaller of this and the extension's limit, counted inflated. Over HTTP/1.1, HTTP/2 and HTTP/3
     * alike; Ktor's `WebSockets { maxFrameSize }` applies on top of it.
     *
     * @throws IllegalArgumentException when set below 1.
     */
    @SecuritySensitive
    public var maxMessageSize: Long = 16_777_216L
        set(value) {
            require(value >= 1) { "webSockets { maxMessageSize } must be at least 1" }
            field = value
        }
}

/** The TCP connections of every connector, HTTP/1.1 and HTTP/2 alike: their idle timeout and limits (threat model 3.2). */
@KuicksilverDsl
public class TcpLimitsConfig internal constructor() {
    /**
     * How long a TCP connection stays open without a request, on HTTP/1.1 and HTTP/2 alike; 45 s by default. An HTTP/1.1
     * connection is then closed, both directions; an HTTP/2 one gets GOAWAY first. On a keep-alive connection the engine's
     * `requestHeaderTimeout` also runs from the end of the last response, so the smaller of the two closes an idle
     * HTTP/1.1 connection. A response the client reads nothing of (its socket takes nothing) ends the connection after the
     * longer of this and 5 minutes: the engine sees a client's reading progress about 1 MiB at a time (the buffer in front
     * of the socket), and 1 MiB in 5 minutes keeps clients down to about 3.4 KiB/s. A closing connection sends what is left
     * for as long as the client takes it, and is aborted after the same time without progress. A request body that sends no
     * byte for this long (counted after `100 Continue` when the client asked for it) fails the handler's read; over HTTP/1.1
     * the client gets 408 when no response has started, and the connection closes. Each wait for body bytes has its own
     * deadline, so a slow but moving upload is read in full. `EngineMain` reads Ktor's own
     * `ktor.deployment.connectionIdleTimeoutSeconds` into it. HTTP/3 has its own, `http3 { quic { maxIdleTimeout } }`.
     *
     * @throws IllegalArgumentException when set to zero or less.
     */
    public var idleTimeout: Duration = 45.seconds
        set(value) {
            require(value.isPositive()) { "tcp { idleTimeout } must be positive" }
            field = value
        }

    /**
     * The most TCP connections each connector holds at once, counted from `accept` (TLS handshakes included) until the
     * socket is released. At the limit the connector stops accepting: the OS backlog holds new clients (their connect
     * succeeds, nothing is read from them) until a connection closes, and the server spends no descriptor or TLS work on
     * them. When the backlog is full too (511 on the JVM, 50 on Kotlin/Native) the OS drops further connection attempts
     * (Linux by default; the client's TCP retries them) or resets them. The default does not protect a process whose
     * descriptor limit is lower (`ulimit -n`: 256 in a macOS shell, often 1024 on Linux): raise that limit or set this below
     * it (docs/guide/ktor.md, "Connection limits"). At least 1; default 10,000.
     *
     * @throws IllegalArgumentException when set below 1.
     */
    @SecuritySensitive
    public var maxConnections: Int = 10_000
        set(value) {
            require(value >= 1) { "tcp { maxConnections } must be at least 1" }
            field = value
        }

    /**
     * The most TCP connections one client address holds at once on a connector; null (the default) turns the limit off.
     * Behind a reverse proxy, a load balancer, Kubernetes source NAT or any NAT every client shares one address, and an
     * HTTP/1.1 proxy opens an upstream connection per request in flight (and one per WebSocket or SSE stream): enable it
     * (256, say) only when the server faces its clients directly. A connection over it is reset right after `accept`, before
     * its TLS handshake, which a proxy in front reports as 502 or 503, and it is reported to
     * [KuicksilverServerEventListener.connectionRefused] with the reason `per-IP limit`. An address is its bytes, never a
     * name: an IPv4-mapped client as its IPv4 address, an IPv6 client by its whole address (as QUIC's
     * `http3 { endpoint { maxConnectionsPerIp } }`). Off by default, unlike QUIC's (256): the TCP handshake proves a
     * client's address before any state is kept for it, and proxies in front of TCP are common. At least 1, or null.
     *
     * @throws IllegalArgumentException when set below 1.
     */
    @SecuritySensitive
    public var maxConnectionsPerIp: Int? = null
        set(value) {
            require(value == null || value >= 1) { "tcp { maxConnectionsPerIp } must be at least 1, or null (off)" }
            field = value
        }
}

/** Where the engine's diagnostics, traces and events go. */
@KuicksilverDsl
public class ServerObservability internal constructor() {
    /**
     * Where the engine's own diagnostics go: its listeners, TCP, HTTP/1.1, HTTP/2 and HTTP/3 connections, the TLS files it
     * watches, and the HTTP/3 endpoints (docs/guide/quic.md, "Observability"). [ApplicationLog] (the default) is the
     * application's log, Ktor's `environment.log`; any other logger takes them all, as the client's `observability { logger }`
     * does. A warning about one call's answer (a final 1xx over HTTP/2, a CONNECT the application answered over HTTP/1.1)
     * goes to the application's log either way, with the application's own lines.
     */
    public var logger: KuicksilverLogger = ApplicationLog

    /**
     * A qlog trace per HTTP/3 connection (docs/guide/quic.md, "qlog"); null (the default) traces nothing. Wrap a file sink in
     * `AsyncQlogSink` so a slow disk never stalls the endpoint: `qlog = AsyncQlogSink(DirectoryQlogSink(dir))`.
     */
    public var qlog: QlogSink? = null

    /** Hears the lifecycle of every QUIC connection of the HTTP/3 listeners; null (the default) for none. */
    @ExperimentalKuicksilverApi
    public var connectionListener: ConnectionListener? = null

    /** Hears connections and requests over HTTP/1.1, HTTP/2 and HTTP/3 (docs/guide/ktor.md, "Observability"); null for none. */
    @ExperimentalKuicksilverApi
    public var eventListener: KuicksilverServerEventListener? = null

    /** Holds [ApplicationLog]. */
    public companion object {
        /**
         * The default [logger]: the application's log (Ktor's `environment.log`), which the engine takes when it starts.
         * Outside an engine's configuration it is [KuicksilverLogger.Default].
         */
        public val ApplicationLog: KuicksilverLogger =
            object : KuicksilverLogger by KuicksilverLogger.Default {
                override fun toString(): String = "ServerObservability.ApplicationLog"
            }
    }
}

/**
 * [logger] as a Ktor [Logger], for the engine's own lines when `observability { logger }` is not the application's log.
 * Every member of the platform's `Logger` goes to [logger] (an SLF4J logger on the JVM and Android: the formatted forms,
 * the markers and the `isXxxEnabled` checks too, so nothing reaches a real SLF4J logger); trace goes as debug. A level
 * [logger] does not enable is dropped before its message is built, and nothing [logger] throws reaches the engine
 * ([LoggerGuard]): a failing logger cannot end a listener's accept loop.
 */
internal expect fun kuicksilverLoggerAsKtor(logger: KuicksilverLogger): Logger

/**
 * [logger] behind a guard, for [kuicksilverLoggerAsKtor]: a level is checked before the message is built, an `isEnabled`
 * that throws reads as false, and what [logger] (or building the message) throws is dropped, a CancellationException too
 * (as the QUIC endpoints' own guard does: rethrowing it would end the caller's coroutine for a logging failure).
 */
internal class LoggerGuard(
    private val logger: KuicksilverLogger,
) {
    fun enabled(level: LogLevel): Boolean =
        try {
            logger.isEnabled(level)
        } catch (_: Throwable) {
            false
        }

    inline fun log(
        level: LogLevel,
        cause: Throwable? = null,
        message: () -> String,
    ) {
        try {
            if (enabled(level)) logger.log(level, message(), cause)
        } catch (_: Throwable) {
        }
    }

    override fun toString(): String = logger.toString()
}

/** [log] (Ktor's `environment.log`) as a [KuicksilverLogger]: the QUIC endpoints' lines go where the application's go. */
internal class KtorLogBridge(
    private val log: Logger,
) : KuicksilverLogger {
    override fun isEnabled(level: LogLevel): Boolean = level != LogLevel.Debug || log.isDebugEnabled

    override fun log(
        level: LogLevel,
        message: String,
        cause: Throwable?,
    ) {
        when (level) {
            LogLevel.Debug -> if (cause == null) log.debug(message) else log.debug(message, cause)
            LogLevel.Info -> if (cause == null) log.info(message) else log.info(message, cause)
            LogLevel.Warn -> if (cause == null) log.warn(message) else log.warn(message, cause)
            else -> if (cause == null) log.error(message) else log.error(message, cause)
        }
    }

    override fun toString(): String = "environment.log"
}
