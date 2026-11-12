// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.config.ApplicationConfig
import io.ktor.server.engine.CommandLineConfig
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.loadCommonConfiguration
import io.ktor.util.logging.KtorSimpleLogger
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.TlsIdentity
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
 * `kuicksilver.tls.reloadInterval` (how often those files are checked for a renewed certificate or CA bundle, e.g. `1h`;
 * off by default), `kuicksilver.http3`, `kuicksilver.http2` (off by default), `kuicksilver.http2RepeatOffenderPenalty` (a duration; off by
 * default), `kuicksilver.maxTcpConnections`, `kuicksilver.maxTcpConnectionsPerIp` (`0` or absent is off),
 * `kuicksilver.quicMaxConnections`, `kuicksilver.quicMaxConnectionsPerIp` (`0` is off), `kuicksilver.quicAcceptQueue`, `kuicksilver.altSvc`,
 * `kuicksilver.webSocketsOverHttp3`, `kuicksilver.webSocketsOverHttp2` (on by default), `kuicksilver.udpSocketCount` (endpoint loops on the UDP port, every platform with a QUIC
 * server).
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
     * exactly when `kuicksilver.tls.clientCa` is set, `kuicksilver.tls.clientCa` is set without the identity files, a boolean key is not `true`/`false`, or `kuicksilver.maxTcpConnections`,
     * `kuicksilver.maxTcpConnectionsPerIp` or one of the `kuicksilver.quic*` limits is not a whole number in range. Throws
     * `kotlinx.io.IOException` when a PEM file (`kuicksilver.tls.certificateChain`, `privateKey`, `clientCa`) cannot be read
     * or is larger than 1 MiB, and when the chain file (with `kuicksilver.tls.reloadInterval`) or the client CA file also holds
     * a private key. Throws `TlsException.Config` when a PEM file holds no certificate or a damaged one, the key does not
     * match the chain or is encrypted, and, with `kuicksilver.tls.reloadInterval`, when the leaf certificate has expired or is
     * not valid yet or no certificate of the client CA file is valid now.
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
