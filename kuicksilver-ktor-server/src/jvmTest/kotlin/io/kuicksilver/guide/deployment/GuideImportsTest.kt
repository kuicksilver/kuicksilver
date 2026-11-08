// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.guide.deployment

// guide:deployment:imports
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.ktor.server.Http3Advertising
import io.kuicksilver.ktor.server.Kuicksilver
import io.kuicksilver.ktor.server.KuicksilverApplicationEngine
import io.kuicksilver.tls.TlsIdentity

/**
 * The import block docs/guide/deployment.md shows for its samples (`guide:deployment:imports`), in a package of its own so
 * that every import is a real one: [everyDeploymentImport] uses each.
 */
fun everyDeploymentImport(identity: TlsIdentity) {
    lateinit var engine: KuicksilverApplicationEngine
    val server =
        embeddedServer(Kuicksilver, configure = {
            tlsConnector(identity) { port = 0 }
        }) {
            intercept(ApplicationCallPipeline.Plugins) {
                call.response.header("Alt-Svc", if (engine.http3Advertising == Http3Advertising.On) "h3=\":443\"" else "clear")
            }
            routing { get("/healthz") { call.respondText("ok") } }
        }
    engine = server.engine
}
