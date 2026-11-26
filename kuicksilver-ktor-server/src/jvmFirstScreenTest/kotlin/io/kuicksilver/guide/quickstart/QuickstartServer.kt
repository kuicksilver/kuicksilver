// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// The server code of docs/guide/quickstart.md, compiled with no opt-in and warnings as errors (src/jvmFirstScreenTest):
// the quickstart shows stable API only. The import block below is the page's import block, line for line. Compiled,
// never run.
package io.kuicksilver.guide.quickstart

// guide:quickstart:server-imports
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.ktor.server.Kuicksilver

// guide:quickstart:server
fun main() {
    embeddedServer(Kuicksilver, configure = {
        tls { pemFiles("fullchain.pem", "privkey.pem") } // the key: unencrypted PKCS#8, "BEGIN PRIVATE KEY"
        tlsConnector { port = 8443 } // TCP 8443: HTTP/2 and HTTP/1.1; UDP 8443: HTTP/3
    }) {
        routing {
            get("/") { call.respondText("Hello over ${call.request.httpVersion}\n") }
        }
    }.start(wait = true)
}
