// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.soak

import io.ktor.http.ContentType
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.receiveChannel
import io.ktor.server.response.respondText
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.utils.io.discard
import io.kuicksilver.ktor.server.Kuicksilver
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking

/**
 * The server `tools/interop/h3spec.sh` runs h3spec (kazu-yamamoto/h3spec, RFC 9000, RFC 9001, RFC 9114 and RFC 9204
 * conformance of an HTTP/3 server) against: the Ktor engine with one TLS connector (the test PKI's server identity), its
 * HTTP/3 endpoint on the same UDP port, HTTP/2 off (h3spec speaks only QUIC), 0-RTT accepted (`http3 { earlyData { enabled } }`: h3spec's case of CRYPTO in 0-RTT,
 * RFC 9001 section 8.3, needs a server that takes 0-RTT), otherwise the default QUIC settings and `Http3Settings`. Every
 * request, whatever its method and path, reads its content to the end and gets a 200 with a short text body. Arguments:
 * `[host] [port]` (default 127.0.0.1, 0). The bound port (TCP and UDP) is printed as `h3spec-server listening on <port>`
 * once the server accepts connections. Runs until the process is killed.
 *
 * h3spec runs on the same host as the server, or in the same container, and connects to 127.0.0.1, the name the test
 * identity holds: the misdirected-request check (RFC 9110 section 7.4) stays on, unlike for h2spec's server on a Mac
 * ([h2specServerMain]). h3spec does not validate the certificate (`-n`).
 */
public fun h3specServerMain(args: Array<String>) {
    val host = args.getOrNull(0) ?: "127.0.0.1"
    val port = args.getOrNull(1)?.toInt() ?: 0
    require(args.size <= 2) { "usage: h3spec-server [host] [port]" }
    runBlocking {
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { identity = SoakPki.identity() }
                    this.host = host
                    this.port = port
                }
                http2 { enabled = false }
                http3 {
                    enabled = true
                    earlyData { enabled = true }
                }
            }) {
                routing {
                    route("{...}") {
                        handle {
                            val read = call.receiveChannel().discard()
                            call.respondText("h3spec ${call.request.local.method.value} $read\n", ContentType.Text.Plain)
                        }
                    }
                }
            }
        server.startSuspend(false)
        val bound =
            server.engine
                .resolvedConnectors()
                .first()
                .port
        println("h3spec-server listening on $bound")
        awaitCancellation()
    }
}
