// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// The client code of docs/guide/quickstart.md, compiled with no opt-in and warnings as errors (src/jvmFirstScreenTest):
// the quickstart shows stable API only. The import block below is the page's import block, line for line.
package io.kuicksilver.guide.quickstart

// guide:quickstart:client-imports
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.delay
import java.io.File
import kotlin.time.Duration.Companion.seconds

// guide:quickstart:client
suspend fun main() {
    val client = HttpClient(Kuicksilver) // name the engine: HttpClient() alone may pick another one
    repeat(3) {
        val response = client.get("https://example.com/")
        println(response.version) // HTTP/2.0 (or HTTP/1.1) first; HTTP/3.0 once the server announced it
        delay(1.seconds)
    }
    client.close()
}

internal fun quickstartLocalClient(): HttpClient {
    // guide:quickstart:local-client
    val client =
        HttpClient(Kuicksilver) {
            engine { tls { trust = TrustConfig.AnchoredCa(Certificate.parsePem(File("ca.pem").readText())) } }
        }
    return client
}
