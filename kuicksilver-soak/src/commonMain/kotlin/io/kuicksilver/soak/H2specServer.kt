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
 * The server `tools/interop/h2spec.sh` runs h2spec (summerwind/h2spec, RFC 9113 and RFC 7541 conformance) against: the
 * Ktor engine with HTTP/2 on one TLS connector (the test PKI's server identity), HTTP/3 off, default `Http2Settings`.
 * Every request, whatever its method and path, reads its content to the end and gets a 200 with a short text body: h2spec
 * needs a response with DATA (section 6.9.1 with a window of 1 octet) and a handler that keeps its stream open while the
 * client grants no window (section 5.1.2). Arguments: `[host] [port] [trusted-gateway] [h2c]` (default 127.0.0.1, 0, the
 * misdirected-request check on, TLS); `h2c` serves HTTP/2 over cleartext TCP with prior knowledge instead (a plain connector
 * with `H2cMode.Only`, RFC 9113 section 3.3; h2spec without `-t`), with the same settings and handler. The bound port is
 * printed as `h2spec-server listening on <port>` once the server accepts connections. Runs until the process is killed.
 *
 * h2spec sends the host it connects to as `:authority`. The test identity names 127.0.0.1: a server that h2spec reaches
 * as 127.0.0.1 (on a Linux host, and in the linux-x64 container, on a Mac too) keeps the check on. A server on a macOS
 * host (the jvm and macos kinds of h2spec.sh) is reached through Docker Desktop as host.docker.internal, which the
 * identity does not name, and runs with `trusted-gateway`, the check off: every request would be a misdirected one
 * otherwise (421, RFC 9110 section 7.4), and h2spec's cases that wait for DATA would see only the 421 HEADERS.
 */
public fun h2specServerMain(args: Array<String>) {
    val host = args.getOrNull(0) ?: "127.0.0.1"
    val port = args.getOrNull(1)?.toInt() ?: 0
    val flags = args.drop(2)
    flags.firstOrNull { it != "trusted-gateway" && it != "h2c" }?.let { throw IllegalArgumentException("unknown argument: $it") }
    val gateway = "trusted-gateway" in flags
    val h2c = "h2c" in flags
    runBlocking {
        val server =
            embeddedServer(Kuicksilver, configure = {
                if (h2c) {
                    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                    plainConnector {
                        this.host = host
                        this.port = port
                        trustedGateway = gateway
                        this.h2c = io.kuicksilver.ktor.server.H2cMode.Only
                    }
                } else {
                    tlsConnector(SoakPki.identity()) {
                        this.host = host
                        this.port = port
                        trustedGateway = gateway
                    }
                }
                http2 = true
                http3 = false
            }) {
                routing {
                    route("{...}") {
                        handle {
                            val read = call.receiveChannel().discard()
                            call.respondText("h2spec ${call.request.local.method.value} $read\n", ContentType.Text.Plain)
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
        println("h2spec-server listening on $bound")
        awaitCancellation()
    }
}
