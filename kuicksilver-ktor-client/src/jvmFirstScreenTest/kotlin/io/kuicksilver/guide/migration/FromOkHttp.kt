// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// The Kotlin code of docs/guide/migrating-from-okhttp.md, compiled with no opt-in and warnings as errors
// (src/jvmFirstScreenTest): the migration shows stable API only. The import block below is the page's, line for line.
package io.kuicksilver.guide.migration

// guide:okhttp:imports
import io.ktor.client.HttpClient
import io.ktor.client.plugins.HttpRequestRetry
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.api.createClientPlugin
import io.ktor.client.plugins.cache.HttpCache
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TrustConfig
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

internal fun migratedClient(
    currentPin: String,
    backupPin: String,
    token: () -> String,
): HttpClient {
    // guide:okhttp:client
    val client =
        HttpClient(Kuicksilver) {
            engine {
                connectTimeout = 10.seconds // connectTimeout
                tls {
                    trust =
                        TrustConfig.Pinned( // certificatePinner: for every host of this client
                            setOf(
                                SpkiSha256.parse(currentPin), // "sha256/...", the same text as in OkHttp
                                SpkiSha256.parse(backupPin), // a key you hold offline
                            ),
                            base = TrustConfig.Platform,
                        )
                }
                pool {
                    maxIdleConnectionsPerRoute = 5 // connectionPool(ConnectionPool(5, 5, MINUTES))
                    idleTimeout = 5.minutes
                }
            }
            install(HttpTimeout) {
                socketTimeoutMillis = 15_000 // readTimeout and writeTimeout: time without progress
                requestTimeoutMillis = 60_000 // callTimeout
            }
            install(HttpRequestRetry) {
                // your own retries: GET only, a POST is never sent twice
                retryOnExceptionIf(maxRetries = 2) { request, _ -> request.method == HttpMethod.Get }
            }
            install(HttpCookies) // cookieJar
            install(HttpCache) // cache, in memory
            install(
                createClientPlugin("BearerHeader") {
                    // addInterceptor: an application interceptor that sets a header
                    onRequest { request, _ -> request.headers[HttpHeaders.Authorization] = "Bearer ${token()}" }
                },
            )
        }
    return client
}

internal suspend fun migratedCall(client: HttpClient) {
    // guide:okhttp:call
    val body = client.get("https://api.example.com/users/42").bodyAsText() // a non-2xx status does not throw
    println(body)
}
