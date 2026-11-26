// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import android.content.Context
import android.net.ConnectivityManager
import io.ktor.client.HttpClient
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TrustConfig
import java.io.File
import kotlin.time.Duration.Companion.seconds

/** The mobile recipe of the client's first screen (docs/guide/ktor.md), compiled for Android; not run. */
internal object FirstScreenMobileSample {
    class RemoteConfig(
        val http3Enabled: Boolean,
    )

    fun client(
        context: Context,
        connectivity: ConnectivityManager,
        remoteConfig: RemoteConfig,
        privateCa: Certificate,
    ): HttpClient {
        // guide:ktor:first-screen-mobile
        val client =
            HttpClient(Kuicksilver) {
                engine {
                    connectTimeout = 10.seconds
                    socketTimeout = 10.seconds // no progress this long fails the call
                    http3 {
                        hints = setOf(HostPort("api.example.com", 443)) // HTTP/3 from the first request
                        altSvcStore = FileAltSvcStore(File(context.cacheDir, "alt-svc")) // remember HTTP/3 across restarts
                        allowed = { remoteConfig.http3Enabled } // remote kill switch
                        migration = Http3ConnectionMigration.followDefaultNetwork(connectivity) // Wi-Fi <-> LTE without a reset
                    }
                    tls { trust = TrustConfig.AnchoredCa(listOf(privateCa)) } // only for a private CA
                    observability { logger = KuicksilverLogger.platform(LogLevel.Info) } // while you debug "why not HTTP/3"
                }
            }
        return client
    }
}
