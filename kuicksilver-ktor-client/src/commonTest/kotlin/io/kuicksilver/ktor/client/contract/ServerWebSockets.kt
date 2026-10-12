// Copyright 2014-2025 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Vendored from Ktor 3.6.0 ktor-test-server/src/main/kotlin/test/server/tests/WebSockets.kt, adapted to the Kuicksilver engine.
package io.kuicksilver.ktor.client.contract

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.websocket.*
import io.ktor.util.*
import io.ktor.websocket.*

internal fun Application.webSockets() {
    routing {
        route("websockets") {
            webSocket("echo") {
                for (frame in incoming) {
                    when (frame) {
                        is Frame.Text -> {
                            val text = frame.readText()
                            send(Frame.Text(text))
                        }

                        is Frame.Close -> {
                            close()
                        }

                        is Frame.Binary -> {
                            send(Frame.Binary(fin = true, frame.data))
                        }

                        else -> {
                            error("Unsupported frame type: ${frame.frameType}.")
                        }
                    }
                }
            }
            webSocket("receive-backpressure") {
                for (i in 0..1000) {
                    send(Frame.Text("Hello $i"))
                }
            }
            webSocket("headers") {
                val headers = call.request.headers.toMap()
                val headersJson = headers.toString() // kotlinx-serialization is not a dependency; the JSON client test is excluded
                send(Frame.Text(headersJson))
            }
            webSocket("close") {
                for (packet in incoming) {
                    val data = packet.data
                    if (data.decodeToString() == "End") {
                        close(CloseReason(1000, "End"))
                    }
                }
            }
            webSocket("echo-query") {
                val param = call.parameters["param"] ?: error("No param provided")
                send(Frame.Text(param))
            }
            webSocketRaw("count-pong") {
                send(Frame.Ping("ping".encodeToByteArray()))

                var countPong = 0
                for (frame in incoming) {
                    when (frame) {
                        is Frame.Pong -> countPong++
                        is Frame.Text -> send(Frame.Text("$countPong"))
                        else -> error("Unsupported frame type: ${frame.frameType}.")
                    }
                }
            }
            webSocket("sub-protocol", protocol = "test-protocol") {
                for (frame in incoming) {
                    when (frame) {
                        is Frame.Text -> {
                            val text = frame.readText()
                            send(Frame.Text(text))
                        }

                        is Frame.Binary -> {
                            send(Frame.Binary(fin = true, frame.data))
                        }

                        else -> {
                            error("Unsupported frame type: ${frame.frameType}.")
                        }
                    }
                }
            }
            webSocket("text") {
                val size = call.request.queryParameters["size"]?.toIntOrNull() ?: error("No size provided")
                val payload = "x".repeat(size)
                send(Frame.Text(payload))
            }
            get("500") {
                call.respond(HttpStatusCode.InternalServerError)
            }
        }
    }
}
