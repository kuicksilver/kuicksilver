// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// The first screen of the server (docs/guide/configuration.md, "First screen"; ADR-0026): this source set opts in to
// nothing and its warnings are errors, so an experimental option here fails the build.
package io.kuicksilver.guide.server

import io.ktor.server.application.Application
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.kuicksilver.ktor.server.Kuicksilver
import io.kuicksilver.ktor.server.KuicksilverApplicationEngine
import io.kuicksilver.tls.TlsVersions
import kotlin.time.Duration.Companion.hours

@Suppress("UNUSED_PARAMETER")
internal fun Application.module() {}

// Compiled, never run: the guide's `main` of the first screen.
// guide:ktor:first-screen-server
fun main() {
    embeddedServer(Kuicksilver, configure = {
        tls {
            pemFiles(
                "/etc/letsencrypt/live/example.com/fullchain.pem", // the key must be unencrypted PKCS#8
                "/etc/letsencrypt/live/example.com/privkey.pem", // (-----BEGIN PRIVATE KEY-----)
            )
            reloadInterval = 1.hours // pick up certbot renewals
        }
        tlsConnector { port = 443 } // TCP 443: HTTP/2 and HTTP/1.1; UDP 443: HTTP/3, announced with Alt-Svc
    }, module = Application::module).start(wait = true)
}

/** The second line of the first screen: the recipes for common deployments, every one of them stable. */
internal fun firstScreenServerRecipes(): EmbeddedServer<KuicksilverApplicationEngine, KuicksilverApplicationEngine.Configuration> =
    // guide:ktor:first-screen-server-recipes
    embeddedServer(Kuicksilver, configure = {
        http3 { endpoint { maxConnectionsPerIp = null } } // behind a NAT or kube-proxy
        tcp { maxConnectionsPerIp = 256 } // facing the internet directly
        tlsConnector { proxyProtocol { trust("10.0.0.0/8") } } // behind an L4 load balancer
        tls { versions = TlsVersions.Tls12And13 } // old clients without TLS 1.3
    }, module = Application::module)
