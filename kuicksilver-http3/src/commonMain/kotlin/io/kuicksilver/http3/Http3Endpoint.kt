// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.TlsConfig
import kotlinx.coroutines.CancellationException

/**
 * HTTP/3 over a bound QUIC endpoint: the transport surface the Ktor engines use (layer rule, ADR-0005). TLS
 * configurations must offer ALPN `h3` (RFC 9114 section 3.1); an accepted connection that negotiated anything else is
 * closed. `SETTINGS_H3_DATAGRAM` follows the transport: it is 1 only when [QuicConfig.maxDatagramFrameSize] is not 0.
 */
public class Http3Endpoint private constructor(
    private val endpoint: QuicEndpoint,
    private val serverSettings: Http3Settings,
) : AutoCloseable {
    /** The bound UDP address, with the real port when [bind] was given port 0. */
    public val localAddress: InetSocketAddress get() = endpoint.localAddress

    /** Opens a client connection to [remote]; the handshake and our SETTINGS are done when this returns. */
    public suspend fun connect(
        remote: InetSocketAddress,
        tls: TlsConfig,
        quic: QuicConfig = QuicConfig.Default,
        settings: Http3Settings = Http3Settings.Default,
    ): Http3Connection {
        require(H3 in tls.alpn) { "the TLS configuration must offer ALPN \"h3\"" }
        val c = endpoint.connect(remote, QuicClientConfig.Builder(tls).apply { this.quic = quic }.build())
        return try {
            Http3Connection.client(c, settings.withTransport(quic))
        } catch (e: Throwable) {
            c.close()
            throw e
        }
    }

    /**
     * As [connect] with 0-RTT (ADR-0015): resumes a ticket this endpoint kept from an earlier connection to the same
     * server and returns as soon as 0-RTT keys exist. Requests with `allowEarlyData` (safe methods without a body) then
     * go out in 0-RTT; every other request waits for the handshake. [earlyData] must not be [EarlyDataState.Disabled].
     * Early requests can be replayed by an attacker (RFC 8446 section 8).
     */
    @ExperimentalKuicksilverApi
    public suspend fun connectEarly(
        remote: InetSocketAddress,
        tls: TlsConfig,
        quic: QuicConfig = QuicConfig.Default,
        settings: Http3Settings = Http3Settings.Default,
        earlyData: EarlyDataState = EarlyDataState.Allowed,
    ): Http3Connection {
        require(H3 in tls.alpn) { "the TLS configuration must offer ALPN \"h3\"" }
        require(earlyData != EarlyDataState.Disabled) { "connectEarly needs earlyData Allowed or Required" }
        val c =
            endpoint.connectEarly(
                remote,
                QuicClientConfig
                    .Builder(tls)
                    .apply {
                        this.quic = quic
                        this.earlyData = earlyData
                    }.build(),
            )
        return try {
            Http3Connection.client(c, settings.withTransport(quic))
        } catch (e: Throwable) {
            c.close()
            throw e
        }
    }

    /** The next server connection that negotiated `h3`. */
    public suspend fun accept(): Http3Connection {
        while (true) {
            val c = endpoint.accept()
            if (c.negotiatedAlpn != H3) {
                c.close(Http3ErrorCode.NO_ERROR, "ALPN h3 required")
                continue
            }
            try {
                return Http3Connection.server(c, serverSettings)
            } catch (
                e: CancellationException,
            ) {
                throw e
            } catch (_: Throwable) {
                c.close()
            }
        }
    }

    override fun close(): Unit = endpoint.close()

    /** The ALPN token and the factory. */
    public companion object {
        /** The ALPN token of HTTP/3. */
        public const val H3: String = "h3"

        /** Binds [local]; with `config.server` set the endpoint accepts HTTP/3 connections using [settings]. */
        public suspend fun bind(
            local: InetSocketAddress,
            config: QuicEndpointConfig = QuicEndpointConfig.Default,
            settings: Http3Settings = Http3Settings.Default,
        ): Http3Endpoint {
            config.server?.let { require(H3 in it.tls.alpn) { "the server TLS configuration must offer ALPN \"h3\"" } }
            val server = config.server?.let { settings.withTransport(it.quic) } ?: settings
            return Http3Endpoint(QuicEndpoint.bind(local, config.withEarlyDataContext(server)), server)
        }

        /** A 0-RTT server binds its SETTINGS into its tickets (RFC 9114 section 7.2.4.2): changed SETTINGS refuse early data. */
        @OptIn(ExperimentalKuicksilverApi::class)
        private fun QuicEndpointConfig.withEarlyDataContext(settings: Http3Settings): QuicEndpointConfig {
            val s = server ?: return this
            if (!s.earlyData) return this
            return toBuilder()
                .apply {
                    server =
                        QuicServerConfig
                            .Builder(s.tls)
                            .apply {
                                quic = s.quic
                                earlyData = true
                                earlyDataContext = settings.earlyDataContext()
                            }.build()
                }.build()
        }

        private fun Http3Settings.withTransport(q: QuicConfig): Http3Settings =
            if (h3Datagram &&
                q.maxDatagramFrameSize == 0L
            ) {
                toBuilder().apply { h3Datagram = false }.build()
            } else {
                this
            }
    }
}
