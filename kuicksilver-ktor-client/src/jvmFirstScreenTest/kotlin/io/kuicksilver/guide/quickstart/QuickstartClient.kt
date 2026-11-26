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
    val client =
        HttpClient(Kuicksilver) {
            // name the engine: HttpClient() alone may pick another one
            engine { tls { trust = TrustConfig.AnchoredCa(Certificate.parsePem(File("ca.pem").readText())) } }
        }
    repeat(3) {
        println(client.get("https://localhost:8443/").version) // HTTP/2.0, then HTTP/3.0 from about the third request
        delay(1.seconds)
    }
    client.close()
}
