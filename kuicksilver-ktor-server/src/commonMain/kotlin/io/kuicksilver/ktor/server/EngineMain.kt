// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.config.ApplicationConfig
import io.ktor.server.config.ApplicationConfigValue
import io.ktor.server.engine.CommandLineConfig
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.loadCommonConfiguration
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.KeyExchangeGroups
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsVersions
import kotlin.jvm.JvmStatic
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * `EngineMain` for the Kuicksilver engine, configured like Ktor's own engines (`ktor.deployment.*`, and on the JVM
 * `ktor.security.ssl.*` with `-sslPort`). Its own keys follow the engine's DSL: a key is the path of its option under
 * `kuicksilver.` (`kuicksilver.http3.endpoint.maxConnections` is `http3 { endpoint { maxConnections } }`), with three
 * exceptions: the TLS files (`kuicksilver.tls.certificateChain`, `privateKey`, `clientCa`, `ocspStapling`, `echKeys`,
 * which the DSL reads with `pemFiles`, `clientCaFile` and `ocspStaplingFile`), the `kuicksilver.connector` block (the
 * deployment port, a Ktor connector: `allowMisdirectedHosts`, `h2c`, `proxyProtocol.*`) and Ktor's own
 * `ktor.deployment.connectionIdleTimeoutSeconds` (`http1 { idleTimeout }`). Every key is in [KNOWN_KEYS]; the same keys
 * work in `application.yaml`.
 *
 * Values: `true`/`false` for a switch (nothing else); a duration as `kotlin.time.Duration.parse` reads it (`30s`, `1h`,
 * `PT30S`), in whole milliseconds; names of an enumeration in any case (`required`, `tls12And13`, `withHttp11`); `off` for
 * "none" or "no limit" of a key that has one (`tls.reloadInterval`, `http2.repeatOffenderPenalty`,
 * `http3.endpoint.maxConnectionsPerIp`, `http3.quic.maxIdleTimeout`, `http3.quic.keepAlive`, `tcp.maxConnectionsPerIp`),
 * where `0` is refused. An unknown key
 * under `kuicksilver.` fails the start, naming the key that replaced it (a 0.2.x key or an earlier 0.3.0 one,
 * [RENAMED_KEYS]) or the closest known key.
 */
public object EngineMain {
    /** Starts the server from command-line arguments and the configuration file, and blocks until it stops. */
    @JvmStatic
    public fun main(args: Array<String>) {
        createServer(args).start(true)
    }

    /**
     * The server [main] would run, not started yet. Throws [IllegalArgumentException] naming the key for a key that is not
     * one of [KNOWN_KEYS] (an old key names its replacement), a value that does not parse or that the engine's option
     * refuses, `0` for a key whose "none" is `off`, only one of `kuicksilver.tls.certificateChain` and `privateKey`, another
     * `kuicksilver.tls.*` key without them, `kuicksilver.tls.clientAuth` other than `none` without `kuicksilver.tls.clientCa`
     * (or the other way round), `kuicksilver.connector.h2c` other than `off` with them, and a `kuicksilver.connector.proxyProtocol.*`
     * key without `trustedSources`. Throws `kotlinx.io.IOException` when a PEM, OCSP or ECH key file cannot be read, is larger
     * than 1 MiB, or (the client CA file) holds a private key, and `TlsException.Config` when such a file holds no
     * certificate or a damaged one, the key does not match the chain or is encrypted, or a file is not what its key reads.
     * The start fails later (with `kuicksilver.tls.reloadInterval`) for a chain file that holds the private key or an
     * expired leaf certificate.
     */
    public fun createServer(args: Array<String>): EmbeddedServer<KuicksilverApplicationEngine, KuicksilverApplicationEngine.Configuration> {
        val config = CommandLineConfig(args)
        return EmbeddedServer(config.rootConfig, Kuicksilver) {
            takeFrom(config.engineConfig)
            loadConfiguration(config.rootConfig.environment.config)
        }
    }

    /**
     * Every key of `EngineMain` under `kuicksilver.`, each the path of its DSL option (tools/check/config-table.sh reads them
     * from here).
     */
    internal val KNOWN_KEYS: Set<String> =
        linkedSetOf(
            "kuicksilver.requestHeaderTimeout",
            "kuicksilver.tls.certificateChain",
            "kuicksilver.tls.privateKey",
            "kuicksilver.tls.reloadInterval",
            "kuicksilver.tls.clientAuth",
            "kuicksilver.tls.clientCa",
            "kuicksilver.tls.versions",
            "kuicksilver.tls.keyExchangeGroups",
            "kuicksilver.tls.ocspStapling",
            "kuicksilver.tls.echKeys",
            "kuicksilver.connector.allowMisdirectedHosts",
            "kuicksilver.connector.h2c",
            "kuicksilver.connector.proxyProtocol.trustedSources",
            "kuicksilver.connector.proxyProtocol.headerTimeout",
            "kuicksilver.connector.proxyProtocol.maxHeaderSize",
            "kuicksilver.http1.allowBareLf",
            "kuicksilver.http2.enabled",
            "kuicksilver.http2.repeatOffenderPenalty",
            "kuicksilver.http3.enabled",
            "kuicksilver.http3.altSvc",
            "kuicksilver.http3.earlyData.enabled",
            "kuicksilver.http3.endpoint.loops",
            "kuicksilver.http3.endpoint.maxConnections",
            "kuicksilver.http3.endpoint.maxConnectionsPerIp",
            "kuicksilver.http3.endpoint.acceptQueue",
            "kuicksilver.http3.quic.maxIdleTimeout",
            "kuicksilver.http3.quic.handshakeTimeout",
            "kuicksilver.http3.quic.keepAlive",
            "kuicksilver.http3.quic.maxBidiStreams",
            "kuicksilver.http3.quic.pathMtu.maxReceive",
            "kuicksilver.http3.quic.pathMtu.initial",
            "kuicksilver.http3.quic.pathMtu.maxSend",
            "kuicksilver.http3.quic.pathMtu.discovery",
            "kuicksilver.http3.quic.migration.allow",
            "kuicksilver.webSockets.overHttp2",
            "kuicksilver.webSockets.overHttp3",
            "kuicksilver.webSockets.maxMessageSize",
            "kuicksilver.tcp.maxConnections",
            "kuicksilver.tcp.maxConnectionsPerIp",
        )

    /**
     * The keys of 0.2.x and of earlier 0.3.0 snapshots and the keys that replaced them: an old key fails the start with its
     * replacement named, and is never read (docs/guide/configuration.md, "Migrating from 0.2.x").
     */
    internal val RENAMED_KEYS: Map<String, String> =
        linkedMapOf(
            // 0.2.x (kuicksilver.tls.certificateChain and privateKey kept their names)
            "kuicksilver.http3" to "kuicksilver.http3.enabled",
            "kuicksilver.altSvc" to "kuicksilver.http3.altSvc",
            "kuicksilver.udpSocketCount" to "kuicksilver.http3.endpoint.loops",
            "kuicksilver.webSocketsOverHttp3" to "kuicksilver.webSockets.overHttp3",
            // 0.3.0 snapshots
            "kuicksilver.tls.trustedGateway" to "kuicksilver.connector.allowMisdirectedHosts",
            "kuicksilver.http2" to "kuicksilver.http2.enabled",
            "kuicksilver.h2c" to "kuicksilver.connector.h2c",
            "kuicksilver.http2RepeatOffenderPenalty" to "kuicksilver.http2.repeatOffenderPenalty",
            "kuicksilver.maxTcpConnections" to "kuicksilver.tcp.maxConnections",
            "kuicksilver.maxTcpConnectionsPerIp" to "kuicksilver.tcp.maxConnectionsPerIp",
            "kuicksilver.quicMaxConnections" to "kuicksilver.http3.endpoint.maxConnections",
            "kuicksilver.quicMaxConnectionsPerIp" to "kuicksilver.http3.endpoint.maxConnectionsPerIp",
            "kuicksilver.quicAcceptQueue" to "kuicksilver.http3.endpoint.acceptQueue",
            "kuicksilver.webSocketsOverHttp2" to "kuicksilver.webSockets.overHttp2",
            "kuicksilver.h1AllowBareLf" to "kuicksilver.http1.allowBareLf",
            "kuicksilver.proxyProtocol.trustedSources" to "kuicksilver.connector.proxyProtocol.trustedSources",
            "kuicksilver.proxyProtocol.headerTimeout" to "kuicksilver.connector.proxyProtocol.headerTimeout",
            "kuicksilver.proxyProtocol.maxHeaderSize" to "kuicksilver.connector.proxyProtocol.maxHeaderSize",
            "kuicksilver.quic.initialUdpPayloadSize" to "kuicksilver.http3.quic.pathMtu.initial",
            "kuicksilver.quic.maxSendUdpPayloadSize" to "kuicksilver.http3.quic.pathMtu.maxSend",
            "kuicksilver.quic.maxUdpPayloadSize" to "kuicksilver.http3.quic.pathMtu.maxReceive",
            "kuicksilver.quic.pmtud" to "kuicksilver.http3.quic.pathMtu.discovery",
            "kuicksilver.quic.maxIdleTimeout" to "kuicksilver.http3.quic.maxIdleTimeout",
            "kuicksilver.quic.handshakeTimeout" to "kuicksilver.http3.quic.handshakeTimeout",
            "kuicksilver.quic.keepAlive" to "kuicksilver.http3.quic.keepAlive",
            "kuicksilver.quic.maxBidiStreams" to "kuicksilver.http3.quic.maxBidiStreams",
            "kuicksilver.quic.allowMigration" to "kuicksilver.http3.quic.migration.allow",
        )

    /** Keys that are gone because the engine derives their value, and why. */
    internal val DERIVED_KEYS: Map<String, String> =
        mapOf("kuicksilver.quic.maxUniStreams" to "RFC 9114 section 6.2: HTTP/3 needs at least 3, the engine keeps the default")

    /**
     * Refuses every key under `kuicksilver.` that is not one of [KNOWN_KEYS], the first in alphabetical order: an old key
     * with its replacement, a derived one with its reason, any other with the closest known key when there is one.
     */
    internal fun checkKeys(config: ApplicationConfig) {
        val keys =
            config
                .keys()
                .filter { it.startsWith(PREFIX) }
                .map { leafKey(it) }
                .distinct()
                .sorted()
        for (key in keys) {
            if (key in KNOWN_KEYS) continue
            if (key == "kuicksilver.http3") {
                throw IllegalArgumentException("kuicksilver.http3 = true|false was replaced in 0.3.0 by kuicksilver.http3.enabled")
            }
            RENAMED_KEYS[key]?.let { throw IllegalArgumentException("$key was replaced in 0.3.0 by $it") }
            DERIVED_KEYS[key]?.let { throw IllegalArgumentException("$key is derived by the engine ($it); remove it") }
            throw IllegalArgumentException(
                "$key is not a Kuicksilver key" + (suggestion(key)?.let { "; did you mean $it?" } ?: ""),
            )
        }
    }

    /** A list's key as Ktor's map configuration spells it (`kuicksilver.tls.echKeys.0`, `.size`) is the list's key. */
    private fun leafKey(key: String): String {
        var k = key
        while (true) {
            val last = k.substringAfterLast('.')
            if (last == "size" || (last.isNotEmpty() && last.all { it in '0'..'9' })) k = k.substringBeforeLast('.') else return k
        }
    }

    /**
     * The key meant by a [key] that is not one: the replacement of an old key within 3 edits of it, else the known key within 3
     * edits (the closest), else the known key with the same last name that shares the longest start with it, when only one does
     * (`kuicksilver.http3.quic.maxConnections` is `kuicksilver.http3.endpoint.maxConnections`, not `kuicksilver.tcp.maxConnections`).
     */
    internal fun suggestion(key: String): String? {
        RENAMED_KEYS.entries
            .map { (old, new) -> levenshtein(key, old) to new }
            .filter { it.first <= 3 }
            .minByOrNull { it.first }
            ?.let { return it.second }
        KNOWN_KEYS
            .map { levenshtein(key, it) to it }
            .filter { it.first <= 3 }
            .minByOrNull { it.first }
            ?.let { return it.second }
        val leaf = key.substringAfterLast('.')
        val sameLeaf = KNOWN_KEYS.filter { it.substringAfterLast('.') == leaf }.groupBy { it.commonPrefixWith(key).length }
        return sameLeaf.maxByOrNull { it.key }?.value?.singleOrNull()
    }

    /** The edit distance (insertions, deletions, substitutions) between [a] and [b]. */
    private fun levenshtein(
        a: String,
        b: String,
    ): Int {
        var prev = IntArray(b.length + 1) { it }
        for (i in 1..a.length) {
            val cur = IntArray(b.length + 1)
            cur[0] = i
            for (j in 1..b.length) {
                cur[j] = minOf(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + if (a[i - 1] == b[j - 1]) 0 else 1)
            }
            prev = cur
        }
        return prev[b.length]
    }

    @OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
    private fun KuicksilverApplicationEngine.Configuration.loadConfiguration(config: ApplicationConfig) {
        val deployment = config.config("ktor.deployment")
        loadCommonConfiguration(deployment)
        val k = Keys(config)
        k.read("ktor.deployment.connectionIdleTimeoutSeconds", { it.toIntOrNull()?.seconds }, "a whole number of seconds") {
            http1.idleTimeout = it
        }
        checkKeys(config)
        k.duration("kuicksilver.requestHeaderTimeout") { requestHeaderTimeout = it }
        loadTls(config, k)
        k.boolean("kuicksilver.connector.allowMisdirectedHosts") { deploymentAllowMisdirectedHosts = it }
        k.enum("kuicksilver.connector.h2c", H2cMode.entries) {
            require(it == H2cMode.Off || tls.identity == null) {
                "kuicksilver.connector.h2c needs the cleartext deployment port: it cannot go with kuicksilver.tls.certificateChain and privateKey"
            }
            deploymentH2c = it
        }
        deploymentProxyProtocol = parseProxyProtocol(config, k)
        k.boolean("kuicksilver.http1.allowBareLf") { http1.allowBareLf = it }
        k.boolean("kuicksilver.http2.enabled") { http2.enabled = it }
        k.durationOrOff("kuicksilver.http2.repeatOffenderPenalty") { http2.repeatOffenderPenalty = it }
        k.boolean("kuicksilver.http3.enabled") { http3.enabled = it }
        k.boolean("kuicksilver.http3.altSvc") { http3.altSvc = it }
        k.boolean("kuicksilver.http3.earlyData.enabled") { http3.earlyData.enabled = it }
        k.int("kuicksilver.http3.endpoint.loops") { http3.endpoint.loops = it }
        k.int("kuicksilver.http3.endpoint.maxConnections") { http3.endpoint.maxConnections = it }
        k.intOrOff("kuicksilver.http3.endpoint.maxConnectionsPerIp") { http3.endpoint.maxConnectionsPerIp = it }
        k.int("kuicksilver.http3.endpoint.acceptQueue") { http3.endpoint.acceptQueue = it }
        val q = http3.quicBuilder
        k.durationOrOff("kuicksilver.http3.quic.maxIdleTimeout") { q.maxIdleTimeout = it }
        k.duration("kuicksilver.http3.quic.handshakeTimeout") { q.handshakeTimeout = it }
        k.durationOrOff("kuicksilver.http3.quic.keepAlive") { q.keepAlive = it }
        k.long("kuicksilver.http3.quic.maxBidiStreams") { q.maxBidiStreams = it }
        k.int("kuicksilver.http3.quic.pathMtu.maxReceive") {
            // the HTTP/3 listener's QuicEndpoint refuses more at bind, after the configuration was read: name the key now
            require(it <= QUIC_ENDPOINT_SLOT) { "must be at most $QUIC_ENDPOINT_SLOT (the endpoint's datagram slots), not $it" }
            q.pathMtu.maxReceive = it
        }
        k.int("kuicksilver.http3.quic.pathMtu.initial") { q.pathMtu.initial = it }
        k.int("kuicksilver.http3.quic.pathMtu.maxSend") { q.pathMtu.maxSend = it }
        k.boolean("kuicksilver.http3.quic.pathMtu.discovery") { q.pathMtu.discovery = it }
        k.boolean("kuicksilver.http3.quic.migration.allow") { q.migration.allow = it }
        if (config.keys().any { it.startsWith("kuicksilver.http3.quic.") }) {
            try {
                q.build()
            } catch (e: IllegalArgumentException) {
                // QuicConfig names the option: "pathMtu { initial } must be 1200..65527"
                throw IllegalArgumentException("kuicksilver.http3.quic: ${e.message}", e)
            }
        }
        k.boolean("kuicksilver.webSockets.overHttp2") { webSockets.overHttp2 = it }
        k.boolean("kuicksilver.webSockets.overHttp3") { webSockets.overHttp3 = it }
        k.long("kuicksilver.webSockets.maxMessageSize") { webSockets.maxMessageSize = it }
        k.int("kuicksilver.tcp.maxConnections") { tcp.maxConnections = it }
        k.intOrOff("kuicksilver.tcp.maxConnectionsPerIp") { tcp.maxConnectionsPerIp = it }
    }

    /** The `kuicksilver.tls.*` keys: the deployment port's identity files and what goes with them. */
    @OptIn(ExperimentalKuicksilverApi::class)
    private fun KuicksilverApplicationEngine.Configuration.loadTls(
        config: ApplicationConfig,
        k: Keys,
    ) {
        val chain = k.value("kuicksilver.tls.certificateChain")
        val key = k.value("kuicksilver.tls.privateKey")
        require((chain == null) == (key == null)) { "kuicksilver.tls.certificateChain and kuicksilver.tls.privateKey go together" }
        for (needs in listOf("reloadInterval", "clientCa", "versions", "keyExchangeGroups", "ocspStapling", "echKeys")) {
            require(chain != null || config.propertyOrNull("kuicksilver.tls.$needs") == null) {
                "kuicksilver.tls.$needs needs kuicksilver.tls.certificateChain and privateKey"
            }
        }
        if (chain == null || key == null) return
        k.enum("kuicksilver.tls.versions", listOf(TlsVersions.Tls13, TlsVersions.Tls12And13), { it.toString() }) { tls.versions = it }
        config.propertyOrNull("kuicksilver.tls.keyExchangeGroups")?.let { tls.keyExchangeGroups = parseKeyExchangeGroups(groupNames(it)) }
        k.value("kuicksilver.tls.ocspStapling")?.let { tls.ocspStaplingFile(it) }
        config.propertyOrNull("kuicksilver.tls.echKeys")?.let { v ->
            tls.echKeys = io.kuicksilver.tls.EchServerKeys(pemFiles(v).map { readEchKeyFile(it) })
            tls.closeEchKeysOnStop = true
        }
        // before the identity: a refused client CA leaves no native key behind
        val auth = k.enumValue("kuicksilver.tls.clientAuth", ClientAuth.entries) ?: ClientAuth.None
        val caFile = k.value("kuicksilver.tls.clientCa")
        require(
            auth == ClientAuth.None || caFile != null,
        ) { "kuicksilver.tls.clientAuth ${auth.name.lowercase()} needs kuicksilver.tls.clientCa" }
        require(
            caFile == null || auth != ClientAuth.None,
        ) { "kuicksilver.tls.clientCa needs kuicksilver.tls.clientAuth optional or required" }
        if (caFile != null) {
            tls.clientCaFile(caFile)
            tls.clientAuth = auth
        }
        tls.pemFiles(chain, key)
        k.durationOrOff("kuicksilver.tls.reloadInterval") { tls.reloadInterval = it }
    }

    /** The largest datagram a `QuicEndpoint` handles (its 1500-byte slots), which bounds `pathMtu { maxReceive }` at bind. */
    private const val QUIC_ENDPOINT_SLOT = 1500

    private const val PREFIX = "kuicksilver."

    private const val DURATION = "a duration in whole milliseconds (30s, 1h, 250ms)"

    /**
     * The rules every key reads by: a value is trimmed; a value the option refuses fails with the key named before the
     * option's own message.
     */
    private class Keys(
        private val config: ApplicationConfig,
    ) {
        fun value(key: String): String? = config.propertyOrNull(key)?.getString()?.trim()

        /** [key] read with [parse] ([what] names what it must be) and given to [apply]; the option's refusal names the key. */
        fun <T> read(
            key: String,
            parse: (String) -> T?,
            what: String,
            apply: (T) -> Unit,
        ) {
            val v = value(key) ?: return
            val parsed = parse(v) ?: throw IllegalArgumentException("$key: \"$v\" is not $what")
            named(key) { apply(parsed) }
        }

        /** [read] for a key whose "none" is `off` (applied as null); `0` is refused with a hint. */
        fun <T : Any> readOrOff(
            key: String,
            parse: (String) -> T?,
            what: String,
            apply: (T?) -> Unit,
        ) {
            val v = value(key) ?: return
            if (v == "off") return named(key) { apply(null) }
            require(v != "0") { "$key: use off instead of 0" }
            val parsed = parse(v) ?: throw IllegalArgumentException("$key: \"$v\" is not $what, or off")
            named(key) { apply(parsed) }
        }

        fun boolean(
            key: String,
            apply: (Boolean) -> Unit,
        ) = read(key, { it.toBooleanStrictOrNull() }, "true or false", apply)

        fun int(
            key: String,
            apply: (Int) -> Unit,
        ) = read(key, { it.toIntOrNull() }, "a whole number", apply)

        fun intOrOff(
            key: String,
            apply: (Int?) -> Unit,
        ) = readOrOff(key, { it.toIntOrNull() }, "a whole number", apply)

        fun long(
            key: String,
            apply: (Long) -> Unit,
        ) = read(key, { it.toLongOrNull() }, "a whole number", apply)

        fun duration(
            key: String,
            apply: (Duration) -> Unit,
        ) = read(key, ::parseDuration, DURATION, apply)

        fun durationOrOff(
            key: String,
            apply: (Duration?) -> Unit,
        ) = readOrOff(key, ::parseDuration, DURATION, apply)

        /** An enumeration key: one of [values] by its name, any case. */
        fun <T : Any> enum(
            key: String,
            values: List<T>,
            name: (T) -> String = { it.toString() },
            apply: (T) -> Unit,
        ) = enumValue(key, values, name)?.let { named(key) { apply(it) } }

        fun <T : Any> enumValue(
            key: String,
            values: List<T>,
            name: (T) -> String = { it.toString() },
        ): T? {
            val v = value(key) ?: return null
            return values.firstOrNull { name(it).equals(v, ignoreCase = true) }
                ?: throw IllegalArgumentException(
                    "$key: \"$v\" is not ${values.joinToString(", ") { name(it).replaceFirstChar(Char::lowercase) }}",
                )
        }

        /**
         * A duration in whole milliseconds, the unit every timer and transport parameter behind a key works in: `1.5ms`
         * would be cut to 1 ms, and `0.5ms` to the 0 that means "none".
         */
        private fun parseDuration(v: String): Duration? =
            runCatching { Duration.parse(v) }.getOrNull()?.takeIf { it.isInfinite() || it.inWholeMilliseconds.milliseconds == it }

        /** Runs [block], the option's refusal prefixed with [key]. */
        fun named(
            key: String,
            block: () -> Unit,
        ) {
            try {
                block()
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("$key: ${e.message}", e)
            }
        }
    }

    /**
     * `kuicksilver.connector.proxyProtocol.trustedSources` (a list, or one comma-separated string, of addresses and CIDR
     * blocks; it turns the PROXY protocol on for the deployment port), `headerTimeout` (a duration) and `maxHeaderSize`
     * (bytes); null when none is set. Throws [IllegalArgumentException] for a value the block refuses, a value that does
     * not parse, or the other two keys without `trustedSources`.
     */
    private fun parseProxyProtocol(
        config: ApplicationConfig,
        k: Keys,
    ): ProxyProtocolConfig? {
        val base = "kuicksilver.connector.proxyProtocol"
        val sourcesKey = config.propertyOrNull("$base.trustedSources")
        if (sourcesKey == null) {
            require(k.value("$base.headerTimeout") == null && k.value("$base.maxHeaderSize") == null) {
                "$base.headerTimeout and maxHeaderSize need $base.trustedSources"
            }
            return null
        }
        val sources =
            (runCatching { sourcesKey.getList() }.getOrNull() ?: sourcesKey.getString().split(','))
                .map { it.trim() }
                .filter { it.isNotEmpty() }
        val b = ProxyProtocolConfig.Builder()
        k.named("$base.trustedSources") { b.trust(*sources.toTypedArray()) }
        k.duration("$base.headerTimeout") { b.headerTimeout = it }
        k.int("$base.maxHeaderSize") { b.maxHeaderSize = it }
        var built: ProxyProtocolConfig? = null
        k.named(base) { built = b.build() }
        return built
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
}
