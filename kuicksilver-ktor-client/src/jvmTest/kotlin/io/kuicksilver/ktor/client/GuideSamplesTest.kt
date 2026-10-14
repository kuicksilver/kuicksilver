// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.request.HttpRequestData
import io.ktor.http.HttpProtocolVersion
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.qlog.AsyncQlogSink
import io.kuicksilver.quic.qlog.DirectoryQlogSink
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TrustConfig
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/** The client code blocks of docs/guide/ktor.md, kept compiling and running (block markers `guide:ktor:client*`). */
class GuideSamplesTest {
    @Test fun guideHasEveryMarker() {
        val guide =
            generateSequence(File("").absoluteFile) {
                it.parentFile
            }.map { File(it, "docs/guide/ktor.md") }.first { it.exists() }.readText()
        assertTrue("guide:ktor:client" in guide, "marker client")
        assertTrue("guide:ktor:pool" in guide, "marker pool")
    }

    @Test fun observabilityAndZeroRttSamples() {
        // guide:ktor:client-observability
        val observed =
            HttpClient(Kuicksilver) {
                engine {
                    eventListener =
                        object : KuicksilverEventListener() {
                            override fun protocolSelected(
                                request: HttpRequestData,
                                protocol: HttpProtocolVersion,
                                reason: ProtocolReason,
                            ) {
                                println("${request.url}: $protocol ($reason)")
                            }
                        }
                    http3 { qlog = AsyncQlogSink(DirectoryQlogSink("qlog")) }
                }
            }
        observed.close()
        // guide:ktor:zero-rtt-client
        val client =
            HttpClient(Kuicksilver) {
                engine { http3 { earlyData = true } }
            }
        client.close()
    }

    @Test
    fun poolSample() {
        // guide:ktor:pool
        val client =
            HttpClient(Kuicksilver) {
                engine {
                    maxConnectionsCount = 1000 // HTTP/1.1 connections of the engine, idle ones included
                    maxConnectionsPerRoute = 100 // ... to one route (scheme, host, port, proxy)
                    maxIdleConnectionsPerRoute = 4 // idle keep-alive connections kept per route
                    idleTimeout = 5.minutes // idle HTTP/1.1 and HTTP/3 connections are closed after this
                    maxConnectionLifetime = Duration.INFINITE // age after which a connection takes no new requests
                }
            }
        client.use {
            val config = it.engine.config as KuicksilverEngineConfig
            assertEquals(1000, config.maxConnectionsCount)
            assertEquals(5.minutes, config.idleTimeout)
        }
    }

    @Test fun clientSample() {
        // guide:ktor:client
        val client =
            HttpClient(Kuicksilver) {
                engine {
                    trust =
                        TrustConfig.Pinned(
                            setOf(SpkiSha256.parse("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")),
                            base = TrustConfig.Platform,
                        )
                    http3 { discovery = Http3DiscoveryMode.Auto } // the default: HTTP/1.1 first, HTTP/3 after Alt-Svc
                }
                install(HttpTimeout) {
                    connectTimeoutMillis = 5_000
                    socketTimeoutMillis = 15_000
                }
            }
        client.use {
            val config = it.engine.config as KuicksilverEngineConfig
            assertTrue(config.trust is TrustConfig.Pinned)
            assertEquals(Http3DiscoveryMode.Auto, config.http3.discovery)
        }
    }
}
