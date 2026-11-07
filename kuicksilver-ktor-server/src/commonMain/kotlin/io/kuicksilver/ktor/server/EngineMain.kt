// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.config.ApplicationConfig
import io.ktor.server.engine.CommandLineConfig
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.loadCommonConfiguration
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.tls.TlsIdentity
import kotlin.jvm.JvmStatic
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * `EngineMain` for the Kuicksilver engine, configured like Ktor's own engines (`ktor.deployment.*`, and on the JVM
 * `ktor.security.ssl.*` with `-sslPort`). Keys of its own, on every platform:
 * `kuicksilver.tls.certificateChain` and `kuicksilver.tls.privateKey` (PEM files: the deployment port then serves TLS
 * and HTTP/3), `kuicksilver.tls.reloadInterval` (how often those files are checked for a renewed certificate, e.g. `1h`;
 * off by default), `kuicksilver.http3`, `kuicksilver.http2` (off by default), `kuicksilver.http2RepeatOffenderPenalty` (a duration; off by
 * default), `kuicksilver.maxTcpConnections`, `kuicksilver.maxTcpConnectionsPerIp` (`0` or absent is off), `kuicksilver.altSvc`,
 * `kuicksilver.webSocketsOverHttp3`, `kuicksilver.udpSocketCount` (endpoint loops on the UDP port, every platform with a QUIC
 * server).
 */
public object EngineMain {
    /** Starts the server from command-line arguments and the configuration file, and blocks until it stops. */
    @JvmStatic
    public fun main(args: Array<String>) {
        createServer(args).start(true)
    }

    /**
     * The server [main] would run, not started yet. Throws [IllegalArgumentException] when only one of the two
     * `kuicksilver.tls.*` file keys is set, `kuicksilver.tls.reloadInterval` is set without them or is not a duration of
     * at least 1 second (or `0`), a boolean key is not `true`/`false`, or `kuicksilver.maxTcpConnections` or
     * `kuicksilver.maxTcpConnectionsPerIp` is not a whole number in range.
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
