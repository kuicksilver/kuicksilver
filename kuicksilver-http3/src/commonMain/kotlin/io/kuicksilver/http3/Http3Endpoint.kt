// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.quic.EndpointStats
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.closeWith
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.TlsConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlin.time.Duration

/**
 * HTTP/3 over a bound QUIC endpoint: the transport surface the Ktor engines use (layer rule, ADR-0005). TLS
 * configurations must offer ALPN `h3` (RFC 9114 section 3.1); an accepted connection that negotiated anything else is
 * closed, and [connect]/[connectEarly] fail with H3_GENERAL_PROTOCOL_ERROR ([Http3Exception.Protocol]) when the server chose
 * another protocol the client offered. `SETTINGS_H3_DATAGRAM` follows the transport: it is 1 only when [QuicConfig.maxDatagramFrameSize] is not 0.
 * [QuicConfig.maxUniStreams] must be at least 3, so the peer can open its control and QPACK streams (RFC 9114 section
 * 6.2): [bind], [connect] and [connectEarly] throw IllegalArgumentException for a smaller value.
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
        requireCriticalStreams(quic)
        val c = endpoint.connect(remote, QuicClientConfig.Builder(tls).apply { this.quic = quic }.build())
        return try {
            requireH3(c)
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
        requireCriticalStreams(quic)
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
            if (c.isHandshakeComplete) requireH3(c)
            Http3Connection.client(c, settings.withTransport(quic)).also { h ->
                // 0-RTT: the protocol is settled by the handshake (a resumed session offers its own, a rejected 0-RTT may end elsewhere)
                if (!c.isHandshakeComplete) {
                    h.session.scope.launch {
                        try {
                            c.awaitHandshake()
                        } catch (_: QuicException) {
                            return@launch
                        }
                        if (c.negotiatedAlpn != H3) h.session.fail(Http3ErrorCode.GENERAL_PROTOCOL_ERROR, notH3(c.negotiatedAlpn))
                    }
                }
            }
        } catch (e: Throwable) {
            c.close()
            throw e
        }
    }

    /**
     * A client offering more than `h3` may end on another of its protocols (RFC 7301): HTTP/3 must not be spoken there. The
     * TLS layer already refuses a handshake without ALPN (RFC 9001 section 8.1, `no_application_protocol`).
     */
    private suspend fun requireH3(c: QuicConnection) {
        if (c.negotiatedAlpn == H3) return
        val message = notH3(c.negotiatedAlpn)
        c.close(Http3ErrorCode.GENERAL_PROTOCOL_ERROR, message)
        throw Http3Exception.Protocol(Http3ErrorCode.GENERAL_PROTOCOL_ERROR, Initiator.Local, null, message)
    }

    private fun notH3(alpn: String?): String = "the server chose ALPN \"$alpn\", not \"$H3\""

    /**
     * The next server connection that negotiated `h3`. Never waits on a client once its QUIC handshake is done: HTTP/3 starts
     * in the background ([Http3Connection.server]), so one client cannot hold back the ones behind it.
     */
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

    /**
     * Closes the endpoint and every connection on it with H3_NO_ERROR (RFC 9114 section 5.2), at once and without GOAWAY;
     * [shutdown] is the graceful way. Asynchronous: the CONNECTION_CLOSE frames go out on the endpoint loop after it returns.
     */
    override fun close() {
        @OptIn(InternalKuicksilverApi::class)
        endpoint.closeWith(Http3ErrorCode.NO_ERROR, "endpoint closed")
    }

    /** The QUIC endpoint's counters (`QuicEndpoint.stats`): admission, handshakes, 0-RTT, datagrams, failures. */
    public val stats: EndpointStats get() = endpoint.stats

    /**
     * Graceful shutdown of the QUIC endpoint (`QuicEndpoint.shutdown`): new clients are refused at once, live connections
     * get [grace] to finish, then the rest close with [code] (H3_NO_ERROR by default). Send GOAWAY on every live connection
     * ([Http3Connection.goAway]) first or meanwhile, so clients stop sending new requests and finish the ones in flight.
     */
    @ExperimentalKuicksilverApi
    public suspend fun shutdown(
        grace: Duration,
        code: Long = Http3ErrorCode.NO_ERROR,
        reason: String = "shutdown",
    ): Unit = endpoint.shutdown(grace, code, reason)

    /** The ALPN token and the factory. */
    public companion object {
        /** The ALPN token of HTTP/3. */
        public const val H3: String = "h3"

        /**
         * Binds [local]; with `config.server` set the endpoint accepts HTTP/3 connections using [settings]. The server's
         * `QuicConfig.defaultStreamErrorCode`, when left at 0, becomes H3_REQUEST_REJECTED (RFC 9114 section 4.1.1): it is the
         * code of a request stream given up before the server saw it.
         */
        public suspend fun bind(
            local: InetSocketAddress,
            config: QuicEndpointConfig = QuicEndpointConfig.Default,
            settings: Http3Settings = Http3Settings.Default,
        ): Http3Endpoint {
            config.server?.let {
                require(H3 in it.tls.alpn) { "the server TLS configuration must offer ALPN \"h3\"" }
                requireCriticalStreams(it.quic)
            }
            val server = config.server?.let { settings.withTransport(it.quic) } ?: settings
            return Http3Endpoint(QuicEndpoint.bind(local, config.forHttp3Server(server)), server)
        }

        /**
         * The server side of an HTTP/3 endpoint. A 0-RTT server binds its SETTINGS into its tickets (RFC 9114 section 7.2.4.2):
         * changed SETTINGS refuse early data. A request stream the QUIC layer gives up before the server saw it (its acceptor was
         * cancelled) is reset with `QuicConfig.defaultStreamErrorCode`: QUIC's default 0 is no HTTP/3 code (a client reads it as
         * H3_NO_ERROR, section 9), so it becomes H3_REQUEST_REJECTED, which says the request was not processed and may be
         * retried (sections 4.1.1 and 8.1). A code set explicitly is kept. Every stream the HTTP/3 layer handled is reset with a
         * code of its own, never this default.
         */
        @OptIn(ExperimentalKuicksilverApi::class)
        internal fun QuicEndpointConfig.forHttp3Server(settings: Http3Settings): QuicEndpointConfig {
            val s = server ?: return this
            val quic =
                if (s.quic.defaultStreamErrorCode == 0L) {
                    s.quic
                        .toBuilder()
                        .apply { defaultStreamErrorCode = Http3ErrorCode.REQUEST_REJECTED }
                        .build()
                } else {
                    s.quic
                }
            if (!s.earlyData && quic === s.quic) return this
            return toBuilder()
                .apply {
                    server =
                        QuicServerConfig
                            .Builder(s.tls)
                            .apply {
                                this.quic = quic
                                newTokenLifetime = s.newTokenLifetime
                                if (s.earlyData) {
                                    earlyData = true
                                    earlyDataContext = settings.earlyDataContext()
                                }
                            }.build()
                }.build()
        }

        /**
         * RFC 9114 section 6.2: our transport parameters "MUST allow the peer to create at least three unidirectional
         * streams" (its control and QPACK streams). A configuration that grants fewer is refused, never raised quietly.
         */
        private fun requireCriticalStreams(q: QuicConfig) {
            require(q.maxUniStreams >= 3) {
                "HTTP/3 needs QuicConfig.maxUniStreams >= 3 (RFC 9114 section 6.2: the peer opens its control and QPACK " +
                    "streams), not ${q.maxUniStreams}"
            }
        }

        @OptIn(ExperimentalKuicksilverApi::class)
        private fun Http3Settings.withTransport(q: QuicConfig): Http3Settings =
            if (h3Datagram &&
                q.maxDatagramFrameSize == 0L
            ) {
                // WebTransport sessions carry HTTP datagrams: refused, never quietly turned off with them
                require(!webTransport) { "Http3Settings.webTransport needs QUIC datagrams: QuicConfig.maxDatagramFrameSize is 0" }
                toBuilder().apply { h3Datagram = false }.build()
            } else {
                this
            }
    }
}
