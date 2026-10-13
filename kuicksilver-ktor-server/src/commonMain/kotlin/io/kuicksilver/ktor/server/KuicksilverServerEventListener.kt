// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.http.HttpProtocolVersion
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.ApplicationCall
import io.ktor.util.logging.Logger
import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/**
 * Hears the server engine's connections and requests over HTTP/1.1 and HTTP/3 (docs/guide/ktor.md, "Observability"); set it
 * with `eventListener` in the engine configuration. Every method has an empty default. A connection reports
 * [connectionOpened] once its TLS handshake (HTTP/1.1) or QUIC handshake (HTTP/3) completed, and [connectionClosed] when
 * the engine is done with it; each request reports [requestStarted] before the application's pipeline and [requestEnded]
 * after it.
 *
 * Callbacks run on the engine's coroutines and must return quickly; an exception out of one (a CancellationException
 * included) is logged as a warning on the application's log and otherwise ignored.
 */
@ExperimentalKuicksilverApi
public abstract class KuicksilverServerEventListener {
    /** A client connected over [protocol] (`HTTP_1_1`, `HTTP_1_0` for plain connectors alike, or `HTTP_3_0`) from [remote]. */
    public open fun connectionOpened(
        protocol: HttpProtocolVersion,
        remote: InetSocketAddress?,
    ) {}

    /** The connection from [remote] over [protocol] is over. */
    public open fun connectionClosed(
        protocol: HttpProtocolVersion,
        remote: InetSocketAddress?,
    ) {}

    /** A TCP client from [remote] failed its TLS handshake with [cause]; it never became a connection. */
    public open fun tlsHandshakeFailed(
        remote: InetSocketAddress?,
        cause: Throwable,
    ) {}

    /** [call] arrived over [protocol] and enters the application's pipeline. */
    public open fun requestStarted(
        protocol: HttpProtocolVersion,
        call: ApplicationCall,
    ) {}

    /** [call] left the pipeline: `call.response.status()` holds what was answered; [cause] is the pipeline's failure, if any. */
    public open fun requestEnded(
        protocol: HttpProtocolVersion,
        call: ApplicationCall,
        cause: Throwable?,
    ) {}
}

/** The engine's [KuicksilverServerEventListener], never failing a connection or a request (an exception is logged). */
@OptIn(ExperimentalKuicksilverApi::class)
internal class ServerEvents(
    val listener: KuicksilverServerEventListener?,
    val log: Logger,
) {
    inline fun emit(
        what: String,
        call: KuicksilverServerEventListener.() -> Unit,
    ) {
        val l = listener ?: return
        try {
            l.call()
        } catch (e: Throwable) {
            // a CancellationException too: the callbacks are not suspending, so it is the listener's bug, and rethrowing it
            // would end the HTTP/3 accept loop or a connection's handler as if they were cancelled
            runCatching { log.warn("Kuicksilver server event listener failed in $what", e) }
        }
    }
}
