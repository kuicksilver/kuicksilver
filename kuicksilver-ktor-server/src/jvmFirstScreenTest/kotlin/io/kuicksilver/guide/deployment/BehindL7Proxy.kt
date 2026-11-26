// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// The recipe of docs/guide/deployment.md for a server behind a TLS-terminating L7 proxy, compiled with no opt-in and
// warnings as errors. Compiled, never run.
package io.kuicksilver.guide.deployment

import io.ktor.server.application.Application
import io.ktor.server.engine.embeddedServer
import io.kuicksilver.ktor.server.Kuicksilver

@Suppress("UNUSED_PARAMETER")
internal fun Application.module() {}

internal fun behindL7Proxy() {
    // guide:deployment:behind-l7-proxy
    embeddedServer(Kuicksilver, configure = {
        plainConnector { port = 8080 } // cleartext HTTP/1.1 from the proxy: no TLS here, so no HTTP/3 and no Alt-Svc
    }, module = Application::module).start(wait = true)
}
