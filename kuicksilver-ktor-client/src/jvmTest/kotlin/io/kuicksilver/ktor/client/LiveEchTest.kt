// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsBytes
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.kuicksilver.ktor.client.dns.DnsMessage
import io.kuicksilver.tls.EchConfigList
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Encrypted Client Hello against a public deployment: Cloudflare's `crypto.cloudflare.com`, whose HTTPS record carries an
 * `ech` parameter and whose `/cdn-cgi/trace` reports `sni=encrypted` when the server decrypted the ClientHello. Opt-in, as
 * it needs the network: skipped unless the build runs with `-Pkuicksilver.liveEch=true`
 * (`:kuicksilver-ktor-client:jvmTest --tests '*LiveEchTest*' -Pkuicksilver.liveEch=true`). The HTTPS records come from
 * Cloudflare's DNS over HTTPS (`cloudflare-dns.com`), asked by a second client with GREASE ECH only.
 */
class LiveEchTest {
    private val enabled = System.getProperty("kuicksilver.liveEch") == "true"

    private val doh by lazy { HttpClient(Kuicksilver) { engine { http3 { discovery = Http3DiscoveryMode.H1Only } } } }

    private val exchange: suspend (ByteArray) -> ByteArray = { query ->
        doh
            .post("https://cloudflare-dns.com/dns-query") {
                contentType(ContentType("application", "dns-message"))
                setBody(query)
            }.bodyAsBytes()
    }

    private fun skipped(name: String): Boolean {
        if (!enabled) println("LiveEchTest.$name skipped: run with -Pkuicksilver.liveEch=true")
        return !enabled
    }

    /** The `ech` of the HTTPS record (RFC 9848), the client's own SVCB resolution: TCP or HTTP/3 as the records allow. */
    @Test fun httpsRecordEchIsAcceptedByCloudflare() =
        runBlocking {
            if (skipped("httpsRecordEchIsAcceptedByCloudflare")) return@runBlocking
            withTimeout(60.seconds) {
                HttpClient(Kuicksilver) {
                    engine {
                        http3 { httpsRecords = HttpsRecordSource.Exchange(secure = true, exchange = exchange) }
                    }
                }.use { c ->
                    val trace = c.get("https://crypto.cloudflare.com/cdn-cgi/trace").bodyAsText()
                    assertTrue("sni=encrypted" in trace, trace)
                }
            }
            doh.close()
        }

    /** A configuration given for the host (`ech.configLists`), over TCP only and over HTTP/3 only. */
    @Test fun hostConfigurationIsAcceptedByCloudflareOverTcpAndHttp3() =
        runBlocking {
            if (skipped("hostConfigurationIsAcceptedByCloudflareOverTcpAndHttp3")) return@runBlocking
            withTimeout(60.seconds) {
                val name = "crypto.cloudflare.com"
                val answer = DnsMessage.read(exchange(DnsMessage.query(name)), name)
                val ech = assertNotNull(answer.records.firstNotNullOfOrNull { it.ech }, "no ech in the HTTPS record of $name")
                val list = EchConfigList.parse(ech)
                for (mode in listOf(Http3DiscoveryMode.H1Only, Http3DiscoveryMode.H3Only)) {
                    HttpClient(Kuicksilver) {
                        engine {
                            http3 { discovery = mode }
                            ech { configLists = mapOf(name to list) }
                        }
                    }.use { c ->
                        val trace = c.get("https://$name/cdn-cgi/trace").bodyAsText()
                        assertTrue("sni=encrypted" in trace, "$mode: $trace")
                    }
                }
            }
            doh.close()
        }
}
