// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.soak

import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.routing.routing
import io.ktor.server.websocket.webSocket
import io.ktor.websocket.DefaultWebSocketSession
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.ktor.server.Kuicksilver
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking
import io.ktor.client.plugins.websocket.WebSockets as ClientWebSockets
import io.ktor.server.websocket.WebSockets as ServerWebSockets
import io.kuicksilver.ktor.client.Kuicksilver as KuicksilverClient

/**
 * The WebSocket server `tools/interop/autobahn.sh` runs the Autobahn|Testsuite's fuzzing client against (RFC 6455 and RFC
 * 7692 conformance): the Ktor engine on one plain connector (HTTP/1.1, the upgrade of RFC 6455 section 4; HTTP/2 and
 * HTTP/3 off explicitly, so the run tests that upgrade whatever the engine's defaults), Ktor's `WebSockets` plugin with
 * this library's `PerMessageDeflate`, the engine's default limits (`webSockets { maxMessageSize }`, 16 MiB). Every path is an echo: each Text and Binary frame goes back as it came (its FIN bit kept, so a fragmented
 * message is echoed fragment by fragment); the engine answers each Ping as soon as it reads it (`WebSocketPongs`, the
 * session's own Pong for it dropped), Ktor's session answers the Close. Arguments: `[host] [port]` (default 127.0.0.1, 0); the bound port is printed as
 * `autobahn-server listening on <port>` once the server accepts connections. Runs until the process is killed.
 */
public fun autobahnServerMain(args: Array<String>) {
    require(args.size <= 2) { "usage: autobahn-server [host] [port]" }
    val host = args.getOrNull(0) ?: "127.0.0.1"
    val port = args.getOrNull(1)?.toInt() ?: 0
    runBlocking {
        val server =
            embeddedServer(Kuicksilver, configure = {
                plainConnector {
                    this.host = host
                    this.port = port
                }
                http2 { enabled = false }
                http3 { enabled = false }
            }) {
                install(ServerWebSockets) { extensions { install(PerMessageDeflate) } }
                routing { webSocket("{...}") { echo() } }
            }
        server.startSuspend(false)
        val bound =
            server.engine
                .resolvedConnectors()
                .first()
                .port
        println("autobahn-server listening on $bound")
        awaitCancellation()
    }
}

/**
 * The WebSocket client `tools/interop/autobahn.sh` runs against the Autobahn|Testsuite's fuzzing server: the Ktor client
 * engine over HTTP/1.1 (`ws://`), Ktor's `WebSockets` plugin with this library's `PerMessageDeflate`, the engine's
 * default limits. It asks the fuzzing server for the number of cases (`/getCaseCount`), runs each one
 * (`/runCase?case=<n>&agent=<agent>`: the same echo as [autobahnServerMain]'s, until the session ends) and then has the
 * server write its reports (`/updateReports?agent=<agent>`). A case whose session fails is printed and the next one
 * runs: the verdict is the report's, not this client's. Arguments: `host port agent`; prints `autobahn-client done
 * <count> cases` at the end.
 */
public fun autobahnClientMain(args: Array<String>) {
    require(args.size == 3) { "usage: autobahn-client <host> <port> <agent>" }
    val (host, portText, agent) = args
    val port = portText.toInt()
    runBlocking {
        HttpClient(KuicksilverClient) {
            install(ClientWebSockets) { extensions { install(PerMessageDeflate) } }
        }.use { client ->
            var count = 0
            client.webSocket(host = host, port = port, path = "/getCaseCount") {
                count = (incoming.receive() as Frame.Text).readText().toInt()
            }
            println("autobahn-client: $count cases")
            for (case in 1..count) {
                try {
                    client.webSocket(host = host, port = port, path = "/runCase?case=$case&agent=$agent") { echo() }
                } catch (e: Exception) {
                    println("autobahn-client: case $case: $e")
                }
            }
            client.webSocket(host = host, port = port, path = "/updateReports?agent=$agent") {}
            println("autobahn-client done $count cases")
        }
    }
}

/** Sends every Text and Binary frame back as it came, its FIN bit kept, until the session's input ends. */
private suspend fun DefaultWebSocketSession.echo() {
    for (frame in incoming) {
        when (frame) {
            is Frame.Text -> {
                send(Frame.Text(frame.fin, frame.data))
            }

            is Frame.Binary -> {
                send(Frame.Binary(frame.fin, frame.data))
            }

            else -> {}
        }
    }
}
