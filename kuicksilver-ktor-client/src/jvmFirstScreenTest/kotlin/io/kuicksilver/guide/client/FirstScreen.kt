// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// The first screen of the client (docs/guide/ktor.md, "Minimal example"; docs/guide/client.md, "First screen"; docs/guide/configuration.md, "First screen"): this
// source set opts in to nothing and its warnings are errors, so an experimental option here fails the build (ADR-0026).
// The mobile recipe's one experimental line (http3 { migration }) is compiled in androidDeviceTest's FirstScreenMobileSample.
package io.kuicksilver.guide.client

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.kuicksilver.ktor.client.FileAltSvcStore
import io.kuicksilver.ktor.client.HostPort
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TrustConfig
import java.io.File
import kotlin.time.Duration.Companion.seconds

internal suspend fun firstScreenClient() {
    // guide:ktor:first-screen-client
    val client = HttpClient(Kuicksilver) // explicit engine: HttpClient() may pick OkHttp/Android first (ServiceLoader)
    println(client.get("https://example.com/").bodyAsText())
    client.close()
}

internal fun firstScreenMobileStable(
    cacheDir: File,
    remoteHttp3Enabled: () -> Boolean,
    privateCa: Certificate,
): HttpClient {
    // the mobile recipe without its experimental http3 { migration } line: everything else is stable
    val client =
        HttpClient(Kuicksilver) {
            engine {
                connectTimeout = 10.seconds
                http3 {
                    hints = setOf(HostPort("api.example.com", 443)) // HTTP/3 from the first request
                    altSvcStore = FileAltSvcStore(File(cacheDir, "alt-svc")) // remember HTTP/3 across restarts
                    allowed = remoteHttp3Enabled // remote kill switch
                }
                tls { trust = TrustConfig.AnchoredCa(listOf(privateCa)) } // only for a private CA
                observability { logger = KuicksilverLogger.platform(LogLevel.Info) } // while you debug "why not HTTP/3"
            }
        }
    return client
}

internal fun privateCaClient(caPem: String): HttpClient {
    // guide:ktor:private-ca
    val internal =
        HttpClient(Kuicksilver) {
            engine { tls { trust = TrustConfig.AnchoredCa(Certificate.parsePem(caPem)) } } // caPem: your CA's PEM text
        }
    return internal
}
