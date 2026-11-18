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
 * `kuicksilver.tls.trustedGateway` (`true`: every client of the deployment port, TLS or cleartext behind a TLS-terminating
 * proxy, is a trusted gateway: no `421 Misdirected Request`),
 * `kuicksilver.tls.reloadInterval` (how often those files are checked for a renewed certificate or CA bundle, e.g. `1h`;
 * off by default), `kuicksilver.http3`, `kuicksilver.http2` (off by default), `kuicksilver.http2RepeatOffenderPenalty` (a duration; off by
 * default), `kuicksilver.maxTcpConnections`, `kuicksilver.maxTcpConnectionsPerIp` (`0` or absent is off),
 * `kuicksilver.quicMaxConnections`, `kuicksilver.quicMaxConnectionsPerIp` (`0` is off), `kuicksilver.quicAcceptQueue`, `kuicksilver.altSvc`,
 * `kuicksilver.webSocketsOverHttp3`, `kuicksilver.webSocketsOverHttp2` (on by default), `kuicksilver.udpSocketCount` (endpoint loops on the UDP port, every platform with a QUIC
 * server), `kuicksilver.proxyProtocol.trustedSources`, `headerTimeout` and `maxHeaderSize` (the PROXY protocol on the
 * deployment port, [ProxyProtocolConfig]; off by default).
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
     * `kuicksilver.tls.ocspStapling` is set without the identity files, a boolean key is not
     * `true`/`false`, or `kuicksilver.maxTcpConnections`,
     * `kuicksilver.maxTcpConnectionsPerIp` or one of the `kuicksilver.quic*` limits is not a whole number in range, or a
     * `kuicksilver.proxyProtocol.*` key is invalid or set without `trustedSources`. Throws
     * `kotlinx.io.IOException` when a PEM file (`kuicksilver.tls.certificateChain`, `privateKey`, `clientCa`) cannot be read
     * or is larger than 1 MiB, and when the chain file (with `kuicksilver.tls.reloadInterval`) or the client CA file also holds
     * a private key. Throws `TlsException.Config` when a PEM file holds no certificate or a damaged one, the key does not
     * match the chain or is encrypted, and, with `kuicksilver.tls.reloadInterval`, when the leaf certificate has expired or is
     * not valid yet or no certificate of the client CA file is valid now, and when the `kuicksilver.tls.ocspStapling` file is
     * empty or not a DER SEQUENCE (`kotlinx.io.IOException` when it cannot be read or is larger than 1 MiB).
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
