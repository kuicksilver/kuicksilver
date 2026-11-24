// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.config.ApplicationConfig
import io.ktor.server.config.ApplicationConfigValue
import io.ktor.server.engine.CommandLineConfig
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.loadCommonConfiguration
import io.ktor.util.logging.KtorSimpleLogger
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.KeyExchangeGroups
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsVersions
import io.kuicksilver.tls.TrustConfig
import kotlin.jvm.JvmStatic
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * `EngineMain` for the Kuicksilver engine, configured like Ktor's own engines (`ktor.deployment.*`, and on the JVM
 * `ktor.security.ssl.*` with `-sslPort`). Keys of its own, on every platform:
 * `kuicksilver.tls.certificateChain` and `kuicksilver.tls.privateKey` (PEM files: the deployment port then serves TLS
 * and HTTP/3), `kuicksilver.tls.clientAuth` (`none`, `optional` or `required`: ask for a client certificate) and
 * `kuicksilver.tls.clientCa` (the PEM file of the CAs client certificates are verified against),
 * `kuicksilver.tls.versions` (`tls13`, the default, or `tls12And13`: TLS 1.2 clients served too, under the RFC 9325 profile),
 * `kuicksilver.tls.keyExchangeGroups` (a list of `KeyExchangeGroups` names, the server's order of preference, e.g.
 * `["X25519MLKEM768", "x25519", "secp256r1"]`, or one string of them separated by `:` or `,`; the default list when absent),
 * `kuicksilver.tls.ocspStapling` (a DER OCSP response file stapled on TCP and QUIC, read again every
 * `kuicksilver.tls.reloadInterval`; whether it is stapled is logged at startup and when that changes),
 * `kuicksilver.tls.echKeys` (a list of PEM files of Encrypted Client Hello keys, each what `openssl ech` writes, every one
 * of them sent in retry configurations; read once at startup, rotated in code with `EchServerKeys.rotate`, freed when the
 * engine stops),
 * `kuicksilver.tls.trustedGateway` (`true`: every client of the deployment port, TLS or cleartext behind a TLS-terminating
 * proxy, is a trusted gateway: no `421 Misdirected Request`),
 * `kuicksilver.tls.reloadInterval` (how often those files are checked for a renewed certificate or CA bundle, e.g. `1h`;
 * off by default), `kuicksilver.http3`, `kuicksilver.http2` (off by default), `kuicksilver.h2c` (`off`, the default,
 * `withHttp11` or `only`: HTTP/2 over cleartext TCP with prior knowledge on the plain deployment port, [H2cMode]; only without
 * the `kuicksilver.tls.*` identity files), `kuicksilver.http2RepeatOffenderPenalty` (a duration; off by
 * default), `kuicksilver.maxTcpConnections`, `kuicksilver.maxTcpConnectionsPerIp` (`0` or absent is off),
 * `kuicksilver.quicMaxConnections`, `kuicksilver.quicMaxConnectionsPerIp` (`0` is off), `kuicksilver.quicAcceptQueue`, `kuicksilver.altSvc`,
 * `kuicksilver.webSocketsOverHttp3`, `kuicksilver.webSocketsOverHttp2` (on by default), `kuicksilver.h1AllowBareLf` (off by
 * default: a bare LF in an HTTP/1.1 request head gets 400), `kuicksilver.udpSocketCount` (endpoint loops on the UDP port, every platform with a QUIC
 * server), `kuicksilver.proxyProtocol.trustedSources`, `headerTimeout` and `maxHeaderSize` (the PROXY protocol on the
 * deployment port, [ProxyProtocolConfig]; off by default), and the QUIC transport of the HTTP/3 listeners under `kuicksilver.quic`
 * ([KuicksilverApplicationEngine.Configuration.quic], each key the `QuicConfig` option of its name): `initialUdpPayloadSize`,
 * `maxSendUdpPayloadSize`, `maxUdpPayloadSize` (bytes), `pmtud` and `allowMigration` (`true`/`false`), `maxIdleTimeout`,
 * `handshakeTimeout` and `keepAlive` (durations such as `30s`; `0` is none for the idle timeout and off for keep-alive),
 * `maxBidiStreams` and `maxUniStreams`.
 */
public object EngineMain {
    /** Where configuration warnings go before the application exists (a client CA file with non-CA certificates). */
    private val startupLog = KtorSimpleLogger("io.kuicksilver.ktor.server.EngineMain")

    /** Starts the server from command-line arguments and the configuration file, and blocks until it stops. */
    @JvmStatic
    public fun main(args: Array<String>) {
        createServer(args).start(true)
    }

    /**
     * The server [main] would run, not started yet. Throws [IllegalArgumentException] when only one of the two
     * `kuicksilver.tls.*` file keys is set, `kuicksilver.tls.reloadInterval` is set without them or is not a duration of
     * at least 1 second (or `0`), `kuicksilver.tls.clientAuth` is not `none`, `optional` or `required`, or is not `none`
     * exactly when `kuicksilver.tls.clientCa` is set, `kuicksilver.tls.clientCa` is set without the identity files,
     * `kuicksilver.tls.versions` is not `tls13` or `tls12And13` or is set without the identity files,
     * `kuicksilver.tls.keyExchangeGroups` is not a list `KeyExchangeGroups` takes (an unknown name, a duplicate, an empty list)
     * or is set without the identity files,
     * `kuicksilver.tls.ocspStapling` or `kuicksilver.tls.echKeys` is set without the identity files, `kuicksilver.h2c` is not
     * `off`, `withHttp11` or `only`, or is not `off` with the identity files (h2c needs the cleartext port), a boolean key is not
     * `true`/`false`, or `kuicksilver.maxTcpConnections`,
     * `kuicksilver.maxTcpConnectionsPerIp` or one of the `kuicksilver.quic*` limits is not a whole number in range, a
     * `kuicksilver.proxyProtocol.*` key is invalid or set without `trustedSources`, or a `kuicksilver.quic.*` key is not one of
     * the QUIC keys, does not parse or is out of the range of its `QuicConfig` option (e.g. `initialUdpPayloadSize` below 1200). Throws
     * `kotlinx.io.IOException` when a PEM file (`kuicksilver.tls.certificateChain`, `privateKey`, `clientCa`) cannot be read
     * or is larger than 1 MiB, and when the chain file (with `kuicksilver.tls.reloadInterval`) or the client CA file also holds
     * a private key. Throws `TlsException.Config` when a PEM file holds no certificate or a damaged one, the key does not
     * match the chain or is encrypted, and, with `kuicksilver.tls.reloadInterval`, when the leaf certificate has expired or is
     * not valid yet or no certificate of the client CA file is valid now, and when the `kuicksilver.tls.ocspStapling` file is
     * empty or not a DER SEQUENCE (`kotlinx.io.IOException` when it cannot be read or is larger than 1 MiB), and when an
     * `kuicksilver.tls.echKeys` file is not an ECH key (`kotlinx.io.IOException` when it cannot be read or is larger than 1
     * MiB).
     */
    public fun createServer(args: Array<String>): EmbeddedServer<KuicksilverApplicationEngine, KuicksilverApplicationEngine.Configuration> {
        val config = CommandLineConfig(args)
        return EmbeddedServer(config.rootConfig, Kuicksilver) {
            takeFrom(config.engineConfig)
            loadConfiguration(config.rootConfig.environment.config)
        }
    }

    private fun KuicksilverApplicationEngine.Configuration.loadConfiguration(config: ApplicationConfig) {
        val deployment = config.config("ktor.deployment")
        loadCommonConfiguration(deployment)
        deployment
            .propertyOrNull("connectionIdleTimeoutSeconds")
            ?.getString()
            ?.toInt()
            ?.let { connectionIdleTimeoutSeconds = it }
        val chain = config.propertyOrNull("kuicksilver.tls.certificateChain")?.getString()
        val key = config.propertyOrNull("kuicksilver.tls.privateKey")?.getString()
        require((chain == null) == (key == null)) { "kuicksilver.tls.certificateChain and kuicksilver.tls.privateKey go together" }
        val reload = parseReloadInterval(config.propertyOrNull("kuicksilver.tls.reloadInterval")?.getString())
        require(reload == null || chain != null) { "kuicksilver.tls.reloadInterval needs kuicksilver.tls.certificateChain and privateKey" }
        val versions = parseTlsVersions(config.propertyOrNull("kuicksilver.tls.versions")?.getString())
        require(versions == null || chain != null) { "kuicksilver.tls.versions needs kuicksilver.tls.certificateChain and privateKey" }
        versions?.let { tlsVersions = it }
        val groups = config.propertyOrNull("kuicksilver.tls.keyExchangeGroups")?.let { parseKeyExchangeGroups(groupNames(it)) }
        require(groups == null || chain != null) {
            "kuicksilver.tls.keyExchangeGroups needs kuicksilver.tls.certificateChain and privateKey"
        }
        @OptIn(ExperimentalKuicksilverApi::class)
        groups?.let { tlsKeyExchangeGroups = it }
        val gateway =
            config
                .propertyOrNull("kuicksilver.tls.trustedGateway")
                ?.getString()
                ?.trim()
                ?.toBooleanStrict()
        gateway?.let { tlsTrustedGateway = it }
        val ocspFile = config.propertyOrNull("kuicksilver.tls.ocspStapling")?.getString()
        require(ocspFile == null || chain != null) { "kuicksilver.tls.ocspStapling needs kuicksilver.tls.certificateChain and privateKey" }
        if (ocspFile != null) {
            @OptIn(ExperimentalKuicksilverApi::class)
            tlsOcspStapling = io.kuicksilver.tls.OcspStapling(readOcspResponseFile(ocspFile))
            tlsOcspFile = ocspFile
        }
        val echFiles = config.propertyOrNull("kuicksilver.tls.echKeys")?.let { pemFiles(it) }
        require(echFiles == null || chain != null) { "kuicksilver.tls.echKeys needs kuicksilver.tls.certificateChain and privateKey" }
        if (echFiles != null) {
            @OptIn(ExperimentalKuicksilverApi::class)
            tlsEchKeys = io.kuicksilver.tls.EchServerKeys(echFiles.map { readEchKeyFile(it) })
        }
        // before the identity: a refused client CA leaves no native key behind
        loadClientCa(config, chain != null, reload != null)
        if (chain != null && key != null) {
            // with reloading, the startup files get the watcher's checks: a combined PEM (key in the chain file) is refused
            val loaded = TlsIdentity.fromPem(readPemText(chain, refusePrivateKey = reload != null), readPemKey(key))
            @OptIn(ExperimentalKuicksilverApi::class)
            identity =
                if (reload == null) {
                    loaded
                } else {
                    // refuses an expired or not yet valid leaf at startup, as every later reload would
                    try {
                        TlsIdentity.reloadable(loaded)
                    } catch (e: Throwable) {
                        loaded.close()
                        throw e
                    }
                }
            identityFiles = chain to key
            closeIdentityOnStop = true
            @OptIn(ExperimentalKuicksilverApi::class)
            identityReloadInterval = reload
        }
        config
            .propertyOrNull("kuicksilver.http3")
            ?.getString()
            ?.toBooleanStrict()
            ?.let { http3 = it }
        config
            .propertyOrNull("kuicksilver.http2")
            ?.getString()
            ?.toBooleanStrict()
            ?.let {
                @OptIn(ExperimentalKuicksilverApi::class)
                http2 = it
            }
        parseH2c(config.propertyOrNull("kuicksilver.h2c")?.getString())?.let {
            @OptIn(ExperimentalKuicksilverApi::class)
            require(it == H2cMode.Off || chain == null) {
                "kuicksilver.h2c needs the cleartext deployment port: it cannot go with kuicksilver.tls.certificateChain and privateKey"
            }
            h2cDeploymentPort = it
        }
        config
            .propertyOrNull("kuicksilver.h1AllowBareLf")
            ?.getString()
            ?.toBooleanStrict()
            ?.let {
                @OptIn(ExperimentalKuicksilverApi::class)
                h1AllowBareLf = it
            }
        config
            .propertyOrNull("kuicksilver.webSocketsOverHttp2")
            ?.getString()
            ?.toBooleanStrict()
            ?.let {
                @OptIn(ExperimentalKuicksilverApi::class)
                webSocketsOverHttp2 = it
            }
        config
            .propertyOrNull("kuicksilver.http2RepeatOffenderPenalty")
            ?.getString()
            ?.let {
                @OptIn(ExperimentalKuicksilverApi::class)
                http2RepeatOffenderPenalty = parsePenalty(it)
            }
        config
            .propertyOrNull("kuicksilver.maxTcpConnections")
            ?.getString()
            ?.let {
                @OptIn(ExperimentalKuicksilverApi::class)
                maxTcpConnections = parseCount("kuicksilver.maxTcpConnections", it)
            }
        config
            .propertyOrNull("kuicksilver.maxTcpConnectionsPerIp")
            ?.getString()
            ?.let {
                @OptIn(ExperimentalKuicksilverApi::class)
                maxTcpConnectionsPerIp = parseCount("kuicksilver.maxTcpConnectionsPerIp", it).takeIf { n -> n != 0 }
            }
        config
            .propertyOrNull("kuicksilver.quicMaxConnections")
            ?.getString()
            ?.let {
                @OptIn(ExperimentalKuicksilverApi::class)
                quicMaxConnections = parseCount("kuicksilver.quicMaxConnections", it)
            }
        config
            .propertyOrNull("kuicksilver.quicMaxConnectionsPerIp")
            ?.getString()
            ?.let {
                @OptIn(ExperimentalKuicksilverApi::class)
                quicMaxConnectionsPerIp = parseCount("kuicksilver.quicMaxConnectionsPerIp", it).takeIf { n -> n != 0 }
            }
        config
            .propertyOrNull("kuicksilver.quicAcceptQueue")
            ?.getString()
            ?.let {
                @OptIn(ExperimentalKuicksilverApi::class)
                quicAcceptQueue = parseCount("kuicksilver.quicAcceptQueue", it)
            }
        config
            .propertyOrNull("kuicksilver.altSvc")
            ?.getString()
            ?.toBooleanStrict()
            ?.let { altSvc = it }
        config
            .propertyOrNull("kuicksilver.webSocketsOverHttp3")
            ?.getString()
            ?.toBooleanStrict()
            ?.let { webSocketsOverHttp3 = it }
        config
            .propertyOrNull("kuicksilver.udpSocketCount")
            ?.getString()
            ?.toInt()
            ?.let { udpSocketCount = it }
        deploymentProxyProtocol = parseProxyProtocol(config)
        parseQuic(config, quic)?.let { quic = it }
    }

    /**
     * The `kuicksilver.quic.*` keys ([QUIC_KEYS]) applied to [base]: null when none is set. Throws [IllegalArgumentException] naming
     * the key for one that is not a QUIC key, a value that does not parse, or a value [QuicConfig] refuses.
     */
    @OptIn(ExperimentalKuicksilverApi::class)
    internal fun parseQuic(
        config: ApplicationConfig,
        base: QuicConfig,
    ): QuicConfig? {
        // every key of QUIC_KEYS starts so (each written whole there, for tools/check/config-table.sh)
        val keys = config.keys().filter { k -> QUIC_KEYS.any { k.startsWith(it.substringBeforeLast('.') + '.') } }
        if (keys.isEmpty()) return null
        // a misspelt key would otherwise leave the default in place without a word: an operator tuning a tunnel must know
        keys.firstOrNull { it !in QUIC_KEYS }?.let {
            throw IllegalArgumentException("$it is not a QUIC key; the keys are ${QUIC_KEYS.joinToString()}")
        }

        fun value(key: String): String? = config.propertyOrNull(key)?.getString()?.trim()
        val b = base.toBuilder()
        value("kuicksilver.quic.initialUdpPayloadSize")?.let {
            b.initialUdpPayloadSize = parseCount("kuicksilver.quic.initialUdpPayloadSize", it)
        }
        value("kuicksilver.quic.maxSendUdpPayloadSize")?.let {
            b.maxSendUdpPayloadSize = parseCount("kuicksilver.quic.maxSendUdpPayloadSize", it)
        }
        value("kuicksilver.quic.maxUdpPayloadSize")?.let {
            val n = parseCount("kuicksilver.quic.maxUdpPayloadSize", it)
            // the HTTP/3 listener's QuicEndpoint refuses more at bind, after the configuration was read: name the key now
            require(n <= QUIC_ENDPOINT_SLOT) {
                "kuicksilver.quic.maxUdpPayloadSize must be at most $QUIC_ENDPOINT_SLOT (the endpoint's datagram slots), not $n"
            }
            b.maxUdpPayloadSize = n
        }
        value("kuicksilver.quic.pmtud")?.let { b.pmtud = parseBoolean("kuicksilver.quic.pmtud", it) }
        value("kuicksilver.quic.maxIdleTimeout")?.let { b.maxIdleTimeout = parseDuration("kuicksilver.quic.maxIdleTimeout", it) }
        value("kuicksilver.quic.handshakeTimeout")?.let { b.handshakeTimeout = parseDuration("kuicksilver.quic.handshakeTimeout", it) }
        value("kuicksilver.quic.keepAlive")?.let {
            b.keepAlive = parseDuration("kuicksilver.quic.keepAlive", it).takeUnless { d -> d == Duration.ZERO }
        }
        value("kuicksilver.quic.maxBidiStreams")?.let { b.maxBidiStreams = parseLong("kuicksilver.quic.maxBidiStreams", it) }
        value("kuicksilver.quic.maxUniStreams")?.let { b.maxUniStreams = parseLong("kuicksilver.quic.maxUniStreams", it) }
        value("kuicksilver.quic.allowMigration")?.let { b.allowMigration = parseBoolean("kuicksilver.quic.allowMigration", it) }
        return try {
            b.build()
        } catch (e: IllegalArgumentException) {
            // QuicConfig names the option: "initialUdpPayloadSize must be 1200..65527"
            throw IllegalArgumentException("kuicksilver.quic: ${e.message}", e)
        }
    }

    /** The largest datagram a `QuicEndpoint` handles (its 1500-byte slots), which bounds `maxUdpPayloadSize` at bind. */
    private const val QUIC_ENDPOINT_SLOT = 1500

    /** The `kuicksilver.quic.*` keys [parseQuic] reads, each a [QuicConfig] option of the same name. */
    internal val QUIC_KEYS: List<String> =
        listOf(
            "kuicksilver.quic.initialUdpPayloadSize",
            "kuicksilver.quic.maxSendUdpPayloadSize",
            "kuicksilver.quic.maxUdpPayloadSize",
            "kuicksilver.quic.pmtud",
            "kuicksilver.quic.maxIdleTimeout",
            "kuicksilver.quic.handshakeTimeout",
            "kuicksilver.quic.keepAlive",
            "kuicksilver.quic.maxBidiStreams",
            "kuicksilver.quic.maxUniStreams",
            "kuicksilver.quic.allowMigration",
        )

    /** A `true`/`false` key. */
    private fun parseBoolean(
        key: String,
        value: String,
    ): Boolean = value.toBooleanStrictOrNull() ?: throw IllegalArgumentException("$key: \"$value\" is not true or false")

    /** A whole-number key of [Long] range; the builder checks its range. */
    private fun parseLong(
        key: String,
        value: String,
    ): Long = value.trim().toLongOrNull() ?: throw IllegalArgumentException("$key: \"$value\" is not a whole number")

    /** A duration key: `0`, or a duration as `kotlin.time.Duration.parse` reads it (`30s`, `1m`, `PT30S`). */
    private fun parseDuration(
        key: String,
        value: String,
    ): Duration {
        if (value == "0") return Duration.ZERO
        return try {
            Duration.parse(value)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("$key: \"$value\" is not a duration (30s, 1m)", e)
        }
    }

    /**
     * `kuicksilver.proxyProtocol.trustedSources` (a list, or one comma-separated string, of addresses and CIDR blocks; it
     * turns the PROXY protocol on for the deployment port), `kuicksilver.proxyProtocol.headerTimeout` (a duration) and
     * `kuicksilver.proxyProtocol.maxHeaderSize` (bytes); null when none is set. Throws [IllegalArgumentException] for a
     * value the builder refuses, a value that does not parse, or the other two keys without `trustedSources`.
     */
    @OptIn(ExperimentalKuicksilverApi::class)
    private fun parseProxyProtocol(config: ApplicationConfig): ProxyProtocolConfig? {
        val sourcesKey = config.propertyOrNull("kuicksilver.proxyProtocol.trustedSources")
        val timeout = config.propertyOrNull("kuicksilver.proxyProtocol.headerTimeout")?.getString()?.trim()
        val size = config.propertyOrNull("kuicksilver.proxyProtocol.maxHeaderSize")?.getString()
        if (sourcesKey == null) {
            require(timeout == null && size == null) {
                "kuicksilver.proxyProtocol.headerTimeout and maxHeaderSize need kuicksilver.proxyProtocol.trustedSources"
            }
            return null
        }
        val sources =
            (runCatching { sourcesKey.getList() }.getOrNull() ?: sourcesKey.getString().split(','))
                .map { it.trim() }
                .filter { it.isNotEmpty() }
        return ProxyProtocolConfig
            .Builder()
            .apply {
                trustedSources += sources
                timeout?.let {
                    headerTimeout =
                        try {
                            Duration.parse(it)
                        } catch (e: IllegalArgumentException) {
                            throw IllegalArgumentException("kuicksilver.proxyProtocol.headerTimeout: \"$it\" is not a duration (5s)", e)
                        }
                }
                size?.let { maxHeaderSize = parseCount("kuicksilver.proxyProtocol.maxHeaderSize", it) }
            }.build()
    }

    /**
     * `kuicksilver.tls.clientAuth` and `kuicksilver.tls.clientCa`: client certificates on the deployment port, verified against
     * the CA file, which [reload] makes a `TrustConfig.ReloadableCa` the identity's watcher interval also polls.
     */
    private fun KuicksilverApplicationEngine.Configuration.loadClientCa(
        config: ApplicationConfig,
        tls: Boolean,
        reload: Boolean,
    ) {
        val auth = parseClientAuth(config.propertyOrNull("kuicksilver.tls.clientAuth")?.getString())
        val caFile = config.propertyOrNull("kuicksilver.tls.clientCa")?.getString()
        require(caFile == null || tls) { "kuicksilver.tls.clientCa needs kuicksilver.tls.certificateChain and privateKey" }
        require(auth == ClientAuth.None || caFile != null) { "kuicksilver.tls.clientAuth $auth needs kuicksilver.tls.clientCa" }
        require(caFile == null || auth != ClientAuth.None) {
            "kuicksilver.tls.clientCa needs kuicksilver.tls.clientAuth optional or required"
        }
        if (caFile == null) return
        // the watcher's checks at startup too: a key in the file is refused, a damaged file or one without a certificate fails
        val roots = Certificate.parsePem(readPemText(caFile, refusePrivateKey = true, holds = CA_FILE_HOLDS))
        warnNonCa(caFile, roots, startupLog)
        val bundle = TrustConfig.AnchoredCa(roots)
        clientAuth = auth
        @OptIn(ExperimentalKuicksilverApi::class)
        clientTrust = if (reload) TrustConfig.reloadable(bundle) else bundle
        clientCaFile = caFile
    }

    /**
     * `kuicksilver.tls.versions`: `tls13` or `tls12And13` (the names of `TlsVersions`, case ignored); null when absent. TLS 1.2
     * alone is not a choice: RFC 9325 section 3.1.1, implementations "SHOULD support TLS 1.3 and, if implemented, MUST prefer
     * to negotiate TLS 1.3 over earlier versions of TLS".
     */
    internal fun parseTlsVersions(value: String?): TlsVersions? =
        when (value?.trim()?.lowercase()) {
            null -> null
            "tls13" -> TlsVersions.Tls13
            "tls12and13" -> TlsVersions.Tls12And13
            else -> throw IllegalArgumentException("kuicksilver.tls.versions: \"$value\" is not tls13 or tls12And13")
        }

    /** The files of `kuicksilver.tls.echKeys`: a list, or one value of paths separated by `,`. */
    private fun pemFiles(value: ApplicationConfigValue): List<String> =
        (
            runCatching { value.getList() }.getOrNull()
                ?: runCatching { value.getString() }.getOrNull()?.split(',')
                ?: throw IllegalArgumentException("kuicksilver.tls.echKeys: a list of PEM files")
        ).map { it.trim() }.filter { it.isNotEmpty() }.also {
            require(it.isNotEmpty()) { "kuicksilver.tls.echKeys: at least one PEM file" }
        }

    /**
     * An ECH key file (a private key and its ECHConfigList, 1 MiB at most) as an `EchKey`: the characters read go to it
     * without a `String` being made, and are zeroed (the key zeroes its copy once `EchServerKeys` has read it).
     */
    @OptIn(ExperimentalKuicksilverApi::class)
    private fun readEchKeyFile(path: String): io.kuicksilver.tls.EchKey {
        val chars = readPemKey(path)
        try {
            return io.kuicksilver.tls.EchKey(chars)
        } finally {
            chars.fill('\u0000')
        }
    }

    /**
     * The names of `kuicksilver.tls.keyExchangeGroups`: a list, or one value (a `-P:` key, a `${?ENV}` substitution) of names
     * separated by `:` or `,`. Throws [IllegalArgumentException] naming the key for a value that is neither.
     */
    private fun groupNames(value: ApplicationConfigValue): List<String> =
        runCatching { value.getList() }.getOrNull()
            ?: runCatching { value.getString() }.getOrNull()?.split(':', ',')
            ?: throw IllegalArgumentException("kuicksilver.tls.keyExchangeGroups: a list of group names, or one string of them")

    /**
     * `kuicksilver.tls.keyExchangeGroups`: the group names, the server's most preferred first (`KeyExchangeGroups`, case ignored).
     * Throws [IllegalArgumentException] with the reason `KeyExchangeGroups` gives (an unknown name, a duplicate, an empty list).
     */
    @OptIn(ExperimentalKuicksilverApi::class)
    internal fun parseKeyExchangeGroups(names: List<String>): KeyExchangeGroups =
        try {
            KeyExchangeGroups(names.map { it.trim() })
        } catch (e: TlsException.Config) {
            throw IllegalArgumentException("kuicksilver.tls.keyExchangeGroups: ${e.message}", e)
        }

    /** `kuicksilver.h2c`: `off`, `withHttp11` or `only` (case ignored), null when absent. */
    @OptIn(ExperimentalKuicksilverApi::class)
    internal fun parseH2c(value: String?): H2cMode? =
        when (value?.trim()?.lowercase()) {
            null -> null
            "off" -> H2cMode.Off
            "withhttp11" -> H2cMode.WithHttp11
            "only" -> H2cMode.Only
            else -> throw IllegalArgumentException("kuicksilver.h2c: \"$value\" is not off, withHttp11 or only")
        }

    /** `kuicksilver.tls.clientAuth`: `none` (or absent), `optional` or `required`. */
    internal fun parseClientAuth(value: String?): ClientAuth =
        when (value?.trim()) {
            null, "none" -> ClientAuth.None
            "optional" -> ClientAuth.Optional
            "required" -> ClientAuth.Required
            else -> throw IllegalArgumentException("kuicksilver.tls.clientAuth: \"$value\" is not none, optional or required")
        }

    /** A whole-number key; the setter checks its range. */
    private fun parseCount(
        key: String,
        value: String,
    ): Int = value.trim().toIntOrNull() ?: throw IllegalArgumentException("$key: \"$value\" is not a whole number")

    /** `kuicksilver.http2RepeatOffenderPenalty`: `0` (off) or a duration as `kotlin.time.Duration.parse` reads it (`30s`). */
    private fun parsePenalty(value: String): Duration {
        val v = value.trim()
        if (v == "0") return Duration.ZERO
        return try {
            Duration.parse(v)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("kuicksilver.http2RepeatOffenderPenalty: \"$v\" is not a duration (30s, 1m)", e)
        }
    }

    /**
     * `kuicksilver.tls.reloadInterval`: a duration as `kotlin.time.Duration.parse` reads it (`30s`, `1h`, `PT1H`); `0` or
     * absent turns polling off. Throws [IllegalArgumentException] for anything else, or a duration below 1 second.
     */
    internal fun parseReloadInterval(value: String?): Duration? {
        val v = value?.trim() ?: return null
        if (v == "0") return null
        val d =
            try {
                Duration.parse(v)
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("kuicksilver.tls.reloadInterval: \"$v\" is not a duration (30s, 1h)", e)
            }
        if (d == Duration.ZERO) return null
        require(d >= 1.seconds) { "kuicksilver.tls.reloadInterval must be 0 (off) or at least 1 second, not $v" }
        return d
    }
}
