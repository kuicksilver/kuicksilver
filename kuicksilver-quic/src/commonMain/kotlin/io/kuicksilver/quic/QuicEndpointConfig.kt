// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class)

package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.annotations.KuicksilverDsl
import io.kuicksilver.quic.core.ServerEarlyData
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.QuicCrypto
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.CoroutineDispatcher
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours

/**
 * Client side of a connection: TLS plus transport settings. [Builder.build] throws `TlsException.Config` for a TLS config QUIC cannot use
 * (TLS 1.2, empty ALPN, CCM_8, `sniSelector`; RFC 9001 section 4); build one with `quicClientConfig(tls) { }`.
 *
 * @property tls The client's TLS settings: the server name to verify, trust, ALPN.
 * @property quic The transport settings of the connection.
 */
public class QuicClientConfig private constructor(
    public val tls: TlsConfig,
    public val quic: QuicConfig,
    /** Whether this client resumes and sends 0-RTT (ADR-0015); see [Builder.earlyData]. */
    @property:ExperimentalKuicksilverApi
    public val earlyData: EarlyDataState,
) {
    /**
     * The mutable side of [QuicClientConfig].
     *
     * @property tls The client TLS settings; [build] checks them against RFC 9001 section 4.
     */
    @KuicksilverDsl
    public class Builder(
        public val tls: TlsConfig,
    ) {
        /** Default [QuicConfig.Default]; the transport settings of the connection. */
        public var quic: QuicConfig = QuicConfig.Default

        /**
         * Default [EarlyDataState.Disabled]. Otherwise the endpoint keeps the server's session tickets (per endpoint, single
         * use) and `QuicEndpoint.connectEarly` sends what the application writes before the handshake completes in 0-RTT.
         * 0-RTT data can be replayed by an attacker (RFC 8446 section 8): send early only what is safe to execute twice.
         */
        @ExperimentalKuicksilverApi
        public var earlyData: EarlyDataState = EarlyDataState.Disabled

        /** A [QuicClientConfig]; IllegalArgumentException for a server [tls], `TlsException.Config` for one QUIC cannot use. */
        public fun build(): QuicClientConfig {
            require(tls.role == TlsRole.Client) { "client config needs a client TlsConfig" }
            tls.checkQuicCompatible()
            return QuicClientConfig(tls, quic, earlyData)
        }
    }
}

/**
 * Server side of an endpoint: TLS identity plus transport settings. [Builder.build] rejects a TLS config QUIC cannot use, like
 * [QuicClientConfig]; build one with `quicServerConfig(tls) { }`.
 *
 * @property tls The server's TLS identity (certificate chain and key), ALPN and client authentication.
 * @property quic The transport settings of every connection the server accepts.
 */
public class QuicServerConfig private constructor(
    public val tls: TlsConfig,
    public val quic: QuicConfig,
    /** Whether the server accepts 0-RTT (ADR-0015); see [Builder.earlyData]. */
    @property:ExperimentalKuicksilverApi
    public val earlyData: Boolean,
    private val earlyDataContext: ByteArray?,
    /** How long a NEW_TOKEN token this server issues stays valid, or null when it issues none; see [Builder.newTokenLifetime]. */
    @property:ExperimentalKuicksilverApi
    public val newTokenLifetime: Duration?,
) {
    private val early = AtomicReference<ServerEarlyData?>(null)

    /**
     * The 0-RTT setup shared by every loop of the endpoints built from this config: the configuration digest and the process's
     * replay register ([ProcessReplayRegister], shared with every other endpoint of the process; keyed with [random] of the
     * first loop that asks, a CSPRNG in production).
     */
    internal fun earlySetup(random: Random): ServerEarlyData? {
        if (!earlyData) return null
        early.load()?.let { return it }
        val made =
            ServerEarlyData.of(
                quic,
                tls.alpn,
                earlyDataContext,
                ProcessReplayRegister.get(random),
                ProcessReplayRegister::now,
                ProcessReplayRegister::wallMillis,
            )
        return if (early.compareAndSet(null, made)) made else early.load()
    }

    /**
     * The mutable side of [QuicServerConfig].
     *
     * @property tls The server TLS settings; [build] checks them against RFC 9001 section 4.
     */
    @KuicksilverDsl
    public class Builder(
        public val tls: TlsConfig,
    ) {
        /** Default [QuicConfig.Default]; its `connectionIdLength` must equal the endpoint's. */
        public var quic: QuicConfig = QuicConfig.Default

        /**
         * Default false. True issues session tickets that allow 0-RTT and accepts early data (RFC 9001 section 4.6): fresh
         * (OpenSSL's ±10 s ticket-age check), once per ticket (the server's replay register) and only for the configuration
         * that issued the ticket. A connection then reaches `accept()` as soon as its 0-RTT is accepted, before the handshake
         * completes: early data can still be a replay, so the application acts on anything not safe to repeat only after
         * `QuicConnection.awaitHandshake()`. Not with client certificates.
         */
        @ExperimentalKuicksilverApi
        public var earlyData: Boolean = false

        /**
         * Application settings a 0-RTT client relies on (HTTP/3 SETTINGS, RFC 9114 section 7.2.4.2), bound into tickets with
         * the ALPN and the transport limits: a ticket from another configuration gets no early data. At most 256 bytes.
         */
        @ExperimentalKuicksilverApi
        public var earlyDataContext: ByteArray? = null

        /**
         * Default 24 hours; null issues none. Once a connection's handshake is confirmed the server sends the client one NEW_TOKEN
         * token (RFC 9000 section 8.1.3), and another after the client moved to a new IP address (at most four per connection). A
         * client that presents one on its next connection from the same IP address, within this lifetime and for the first time,
         * counts as validated ([ConnectionAttempt.addressValidated]): no Retry under [ConnectionAdmission.AlwaysRetry] and no
         * anti-amplification limit on the first flight. A token that does not validate is treated as absent, never refused.
         * Tokens are sealed with keys that live only in this process (rotated hourly); at most 7 days.
         */
        @ExperimentalKuicksilverApi
        public var newTokenLifetime: Duration? = 24.hours

        /** A [QuicServerConfig]; IllegalArgumentException for a client [tls], `TlsException.Config` for one QUIC cannot use. */
        public fun build(): QuicServerConfig {
            require(tls.role == TlsRole.Server) { "server config needs a server TlsConfig" }
            tls.checkQuicCompatible()
            require(!earlyData || tls.clientAuth == ClientAuth.None) { "earlyData cannot be combined with client certificates" }
            require((earlyDataContext?.size ?: 0) <= 256) { "earlyDataContext is at most 256 bytes" }
            newTokenLifetime?.let {
                require(
                    it.isPositive() && it <= 7.days,
                ) { "newTokenLifetime must be positive and at most 7 days, or null" }
            }
            return QuicServerConfig(tls, quic, earlyData, earlyDataContext?.copyOf(), newTokenLifetime)
        }
    }
}

/** An endpoint: optionally a server, the crypto provider, and the admission limits (docs/guide/quic.md, "Admission and endpoint limits"). */
public class QuicEndpointConfig private constructor(
    /** The server side; null makes a client-only endpoint, which admits no incoming connection. */
    public val server: QuicServerConfig?,
    /**
     * The TLS and packet-protection provider of every connection and of the endpoint's Retry and reset keys; [KslQuicCrypto] (OpenSSL) by
     * default.
     */
    public val crypto: QuicCrypto,
    /** New Initial packets are dropped silently beyond this many connections. */
    public val maxConnections: Int,
    /**
     * Handshaken connections waiting for `accept()` (shared by all [loops]), never more. While this many wait, a new client
     * Initial is answered statelessly with an Initial CONNECTION_CLOSE carrying CONNECTION_REFUSED (0x02), under the
     * stateless rate limits, so the client fails at once instead of at its handshake timeout and no TLS handshake is spent
     * on it; a handshake admitted earlier that completes while this many wait is closed with CONNECTION_REFUSED instead of
     * joining the queue. Handshakes in flight are not counted (unvalidated, possibly spoofed Initials must not lock real
     * clients out); they are bounded by [maxConnections], [maxConnectionsPerIp] and the [ConnectionAdmission] policy.
     */
    public val acceptQueue: Int,
    /**
     * The single-threaded dispatcher of the endpoint loop; null means `Dispatchers.Default.limitedParallelism(1)`. While
     * datagrams keep coming, the loop reads the ones already queued at the socket on this dispatcher's thread. On its own
     * dispatcher (null here) it also waits there for the next ones, at most 1 ms at a time and never past its next timer (not
     * on Windows); on a dispatcher supplied here it never waits, as other work shares the thread (a UI, or a second endpoint
     * whose datagram it would be waiting for).
     */
    public val dispatcher: CoroutineDispatcher?,
    /** How the loop opens its socket; null means [DatagramIo.open]. */
    public val io: (suspend (InetSocketAddress) -> DatagramIo)?,
    /** Length of every connection ID this endpoint issues; short headers are parsed with it, so every connection's `QuicConfig.connectionIdLength` must match. */
    public val connectionIdLength: Int,
    /** Decides per new client Initial: create, Retry, drop or refuse; the default asks for a Retry above 256 handshakes in flight or 8 MiB of handshake buffers. */
    public val admission: ConnectionAdmission,
    /** Initials waiting for [admission] after one receive batch; more are dropped (1024 by default). */
    public val initialQueueCap: Int,
    /** Connections one client IP may hold at once, ports ignored; null disables the limit. The excess is dropped silently. */
    public val maxConnectionsPerIp: Int?,
    /** A server connection older than this is closed with NO_ERROR, whatever its activity; null means no limit. */
    public val maxConnectionLifetime: Duration?,
    /** Drop Initials whose source port is 53, 123, 1900, 5353 or 11211: a reflection attempt, never a real client (threat-model 3.1). */
    public val rejectInitialFromReflectivePorts: Boolean,
    /** Stateless answers (Retry, Version Negotiation, Stateless Reset, INVALID_TOKEN close) per client address per second (RFC 9000 section 8: amplification). */
    public val statelessPerAddressPerSecond: Int,
    /** Stateless answers per second over all addresses (like msquic `MaxBindingStatelessOperations`). */
    public val statelessTotalPerSecond: Int,
    /** Endpoint loops sharing the port with SO_REUSEPORT (docs/guide/quic.md, "Several loops on one port"): more than one needs a server and the accelerated transport with SO_REUSEPORT flow hashing (Linux, Android; not Apple or Windows), else `bind` throws `UnsupportedOperationException`. */
    public val loops: Int,
    /** Where the endpoint's diagnostics go (docs/guide/quic.md, "Observability"); [KuicksilverLogger.Stderr] (warnings on standard error) by default. */
    @property:ExperimentalKuicksilverApi
    public val logger: KuicksilverLogger,
    /** Hears every connection's lifecycle on the endpoint loop; null (the default) for none. */
    @property:ExperimentalKuicksilverApi
    public val listener: ConnectionListener?,
) {
    /** The mutable side of [QuicEndpointConfig] behind `quicEndpointConfig { }`; [build] validates the values together. */
    @KuicksilverDsl
    public class Builder {
        /** Default null: a client-only endpoint. See [QuicEndpointConfig.server]. */
        public var server: QuicServerConfig? = null

        /** Default [KslQuicCrypto]; see [QuicEndpointConfig.crypto]. */
        public var crypto: QuicCrypto = KslQuicCrypto

        /** Default 10 000, at least 1; see [QuicEndpointConfig.maxConnections]. */
        public var maxConnections: Int = 10_000

        /** Default 128, at least 1; see [QuicEndpointConfig.acceptQueue]. */
        public var acceptQueue: Int = 128

        /**
         * Default null (a one-thread view of `Dispatchers.Default`); must stay null with more than one of [loops]. The loop
         * never waits in a socket on a dispatcher set here; see [QuicEndpointConfig.dispatcher].
         */
        public var dispatcher: CoroutineDispatcher? = null

        /** Default null ([DatagramIo.open]); `kuicksilver-testing`'s `MemoryNetwork.open` runs the endpoint in memory. */
        public var io: (suspend (InetSocketAddress) -> DatagramIo)? = null

        /**
         * Default 8 bytes (4..20); must equal the server's `QuicConfig.connectionIdLength`. See [QuicEndpointConfig.connectionIdLength].
         */
        public var connectionIdLength: Int = 8

        /**
         * Default `ConnectionAdmission.default()` (Retry above 256 handshakes in flight or 8 MiB of their buffers); see
         * [QuicEndpointConfig.admission].
         */
        public var admission: ConnectionAdmission = ConnectionAdmission.default()

        /** Default 1024, at least 1; see [QuicEndpointConfig.initialQueueCap]. */
        public var initialQueueCap: Int = 1024

        /** Default 256; null disables the limit. See [QuicEndpointConfig.maxConnectionsPerIp]. */
        public var maxConnectionsPerIp: Int? = 256

        /** Default null (no limit); positive otherwise. See [QuicEndpointConfig.maxConnectionLifetime]. */
        public var maxConnectionLifetime: Duration? = null

        /** Default true; see [QuicEndpointConfig.rejectInitialFromReflectivePorts]. */
        public var rejectInitialFromReflectivePorts: Boolean = true

        /** Default 8 per second, at least 1; see [QuicEndpointConfig.statelessPerAddressPerSecond]. */
        public var statelessPerAddressPerSecond: Int = 8

        /** Default 1000 per second, at least 1; see [QuicEndpointConfig.statelessTotalPerSecond]. */
        public var statelessTotalPerSecond: Int = 1000

        /** Default 1 (1..255); more needs a [server] and no [dispatcher]. See [QuicEndpointConfig.loops]. */
        public var loops: Int = 1

        /** Default [KuicksilverLogger.Stderr]; see [QuicEndpointConfig.logger]. */
        @ExperimentalKuicksilverApi
        public var logger: KuicksilverLogger = KuicksilverLogger.Stderr

        /** Default null; see [QuicEndpointConfig.listener]. */
        @ExperimentalKuicksilverApi
        public var listener: ConnectionListener? = null

        /**
         * An immutable [QuicEndpointConfig]; IllegalArgumentException for a value out of range or a combination that cannot work
         * (connection ID lengths that differ, loops without a server).
         */
        public fun build(): QuicEndpointConfig {
            require(maxConnections >= 1) { "maxConnections must be positive" }
            require(acceptQueue >= 1) { "acceptQueue must be positive" }
            require(connectionIdLength in 4..20) { "connectionIdLength must be 4..20" }
            require(initialQueueCap >= 1) { "initialQueueCap must be positive" }
            require((maxConnectionsPerIp ?: 1) >= 1) { "maxConnectionsPerIp must be positive or null" }
            require(maxConnectionLifetime?.isPositive() != false) { "maxConnectionLifetime must be positive or null" }
            require(statelessPerAddressPerSecond >= 1 && statelessTotalPerSecond >= 1) { "stateless rate limits must be positive" }
            server?.let {
                require(it.quic.connectionIdLength == connectionIdLength) {
                    "server QuicConfig.connectionIdLength (${it.quic.connectionIdLength}) must equal the endpoint's connectionIdLength ($connectionIdLength): short headers are parsed with one length"
                }
            }
            require(loops in 1..255) { "loops must be 1..255 (the routing byte)" }
            require(loops == 1 || server != null) { "loops > 1 needs a server" }
            require(loops == 1 || dispatcher == null) { "loops > 1 cannot share one dispatcher" }
            return QuicEndpointConfig(
                server,
                crypto,
                maxConnections,
                acceptQueue,
                dispatcher,
                io,
                connectionIdLength,
                admission,
                initialQueueCap,
                maxConnectionsPerIp,
                maxConnectionLifetime,
                rejectInitialFromReflectivePorts,
                statelessPerAddressPerSecond,
                statelessTotalPerSecond,
                loops,
                logger,
                listener,
            )
        }
    }

    /** A builder pre-filled with these values (for a layer above that adjusts one setting, such as `Http3Endpoint` binding SETTINGS into 0-RTT tickets). */
    @ExperimentalKuicksilverApi
    public fun toBuilder(): Builder =
        Builder().also {
            it.server = server
            it.crypto = crypto
            it.maxConnections = maxConnections
            it.acceptQueue = acceptQueue
            it.dispatcher = dispatcher
            it.io = io
            it.connectionIdLength = connectionIdLength
            it.admission = admission
            it.initialQueueCap = initialQueueCap
            it.maxConnectionsPerIp = maxConnectionsPerIp
            it.maxConnectionLifetime = maxConnectionLifetime
            it.rejectInitialFromReflectivePorts = rejectInitialFromReflectivePorts
            it.statelessPerAddressPerSecond = statelessPerAddressPerSecond
            it.statelessTotalPerSecond = statelessTotalPerSecond
            it.loops = loops
            it.logger = logger
            it.listener = listener
        }

    /** Holds [Default]. */
    public companion object { /** A client-only endpoint with every default. */
        public val Default: QuicEndpointConfig = Builder().build()
    }
}
