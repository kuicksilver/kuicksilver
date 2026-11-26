// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// The server code of docs/guide/migrating-ktor-engines.md, compiled with no opt-in and warnings as errors. Compiled,
// never run.
package io.kuicksilver.guide.migration

import io.ktor.server.application.Application
import io.ktor.server.engine.embeddedServer
import io.kuicksilver.ktor.server.Kuicksilver

@Suppress("UNUSED_PARAMETER")
internal fun Application.module() {}

internal fun swappedServer() {
    // guide:engines:server
    embeddedServer(Kuicksilver, configure = {
        tls { pemFiles("/etc/tls/fullchain.pem", "/etc/tls/privkey.pem") } // the key unencrypted PKCS#8
        tlsConnector { port = 8443 } // HTTP/1.1, HTTP/2 and HTTP/3 on one port
    }, module = Application::module).start(wait = true)
}
