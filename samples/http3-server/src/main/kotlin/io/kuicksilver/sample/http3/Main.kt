// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.http3

import io.ktor.server.application.Application
import io.ktor.server.plugins.origin
import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.ktor.server.EngineMain

/** TLS, HTTP/3 on UDP, HTTP/2 and HTTP/1.1 on TCP, one port: all of it from `application.conf`. */
fun main(args: Array<String>) = EngineMain.main(args)

/** A plain Ktor module: it neither knows nor cares which protocol a request came over. */
fun Application.module() {
    routing {
        get("/") {
            call.respondText("Hello over ${call.request.httpVersion} from ${call.request.origin.remoteAddress}\n")
        }
    }
}
