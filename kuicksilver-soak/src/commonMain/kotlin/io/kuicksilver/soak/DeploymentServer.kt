// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.soak

import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.plugins.autohead.AutoHeadResponse
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.ktor.server.Kuicksilver
import io.kuicksilver.tls.TlsIdentity
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.readString

/**
 * The server `tools/check/deployment-guide.sh` runs the commands of docs/guide/deployment.md against: the Ktor engine as
 * that guide deploys it, one TLS connector with the engine's defaults (HTTP/1.1 with `Alt-Svc`, HTTP/3 on the same UDP
 * port), its identity read from PEM files. `GET /` (and `HEAD /`) answers `ok`. Arguments: `host port chain.pem key.pem`; the bound port is
 * printed as `deployment-server listening on <port>` once the server accepts connections. Runs until the process is killed.
 */
public fun deploymentServerMain(args: Array<String>) {
    require(args.size == 4) { "usage: deployment-server <host> <port> <chain.pem> <key.pem>" }
    val (host, port, chain, key) = args
    val identity = TlsIdentity.fromPem(readText(chain), readText(key).toCharArray())
    runBlocking {
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector(identity) {
                    this.host = host
                    this.port = port.toInt()
                }
            }) {
                install(AutoHeadResponse) // the guide checks with `curl -I` (HEAD)
                routing { get("/") { call.respondText("ok\n") } }
            }
        server.startSuspend(false)
        val bound =
            server.engine
                .resolvedConnectors()
                .first()
                .port
        println("deployment-server listening on $bound")
        awaitCancellation()
    }
}

private fun readText(path: String): String = SystemFileSystem.source(Path(path)).buffered().use { it.readString() }
