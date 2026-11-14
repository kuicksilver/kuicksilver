// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.compose

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.kuicksilver.ktor.client.Http3ConnectionMigration
import io.kuicksilver.ktor.client.followDefaultNetwork
import io.kuicksilver.quic.defaultNetworks
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSession
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/** Android: OkHttp as the TCP reference, `ConnectivityManager` for the network and for connection migration. */
class AndroidDemoPlatform(
    context: Context,
) : DemoPlatform {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)

    override val name: String = "Android"

    // the host machine as the emulator reaches it; on a phone, the machine's LAN address
    override val defaultHost: String = "10.0.2.2"

    override val referenceNote: String =
        "OkHttp is the TCP reference (HTTP/1.1 over TLS: the demo server does not offer HTTP/2, which would not move either)."

    override fun migration(): Http3ConnectionMigration = Http3ConnectionMigration.followDefaultNetwork(connectivity)

    override fun networkId(): String? = connectivity.activeNetwork?.toString()

    override fun networks(): Flow<String> = connectivity.defaultNetworks().map { describe(it) }

    private fun describe(n: Network?): String {
        if (n == null) return "no network"
        val caps = connectivity.getNetworkCapabilities(n)
        val kind =
            when {
                caps == null -> "unknown"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "mobile"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
                else -> "other"
            }
        return "$kind (network $n)"
    }

    override fun referenceLanes(server: DemoServer): List<Lane> =
        listOf(Lane("OkHttp (TCP)", "HTTP/1.1 over TLS; OkHttp's defaults", okHttpClient(), server.https(""), isKuicksilver = false))
}

/**
 * Ktor's OkHttp engine trusting the demo CA only and checking the certificate for [DEMO_SERVER_NAME], as the Kuicksilver
 * lane does ([demoTrust]); everything else is OkHttp's default (timeouts, retries, connection pool).
 */
fun okHttpClient(): HttpClient {
    // trimmed: the text starts with a line break, and Android's CertificateFactory (Conscrypt) reads PEM only when the
    // input starts with "-----BEGIN"; anything else is parsed as DER and fails with DECODE_ERROR
    val ca = CertificateFactory.getInstance("X.509").generateCertificate(DemoCerts.caPem.trim().byteInputStream()) as X509Certificate
    val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
        load(null, null)
        setCertificateEntry("demo-ca", ca)
    }
    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
    val tm = tmf.trustManagers.filterIsInstance<X509TrustManager>().single()
    val tls = SSLContext.getInstance("TLS").apply { init(null, arrayOf(tm), null) }
    return HttpClient(OkHttp) {
        engine {
            config {
                sslSocketFactory(tls.socketFactory, tm)
                hostnameVerifier { _, session -> namesDemoServer(session) }
            }
        }
    }
}

/** The leaf's subject alternative names include [DEMO_SERVER_NAME] (the chain itself was verified against the demo CA). */
private fun namesDemoServer(session: SSLSession): Boolean {
    val leaf = session.peerCertificates.firstOrNull() as? X509Certificate ?: return false
    // each entry is [type, value]; type 2 is a DNS name (RFC 5280 GeneralName dNSName)
    return leaf.subjectAlternativeNames.orEmpty().any { it.getOrNull(0) == 2 && it.getOrNull(1) == DEMO_SERVER_NAME }
}
