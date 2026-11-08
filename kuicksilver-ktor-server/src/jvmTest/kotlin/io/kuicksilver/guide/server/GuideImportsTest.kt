// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.guide.server

// guide:ktor:server-imports
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.utils.io.copyTo
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http3.Http3EarlyDataPolicy
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.ktor.server.Http3Advertising
import io.kuicksilver.ktor.server.Kuicksilver
import io.kuicksilver.ktor.server.KuicksilverServerEventListener
import io.kuicksilver.ktor.server.peerCertificates
import io.kuicksilver.ktor.server.priority
import io.kuicksilver.ktor.server.receivedEarly
import io.kuicksilver.ktor.server.webTransport
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.qlog.AsyncQlogSink
import io.kuicksilver.quic.qlog.DirectoryQlogSink
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.io.IOException
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * The import block docs/guide/ktor.md shows for its server samples (`guide:ktor:server-imports`), in a package of its own so
 * that every import is a real one: [everyServerImport] uses each, so a name that moves breaks this file.
 */
fun everyServerImport(
    chainFile: String,
    keyFile: String,
    module: Application.() -> Unit,
) {
    val identity = TlsIdentity.fromPem(File(chainFile).readText(), File(keyFile).readText().toCharArray())
    val server =
        embeddedServer(Kuicksilver, configure = {
            tlsConnector(identity) {
                clientAuth = ClientAuth.Required
                trust = TrustConfig.AnchoredCa(Certificate.parsePem(File(chainFile).readText()))
            }
            http2Settings = Http2Settings(maxConcurrentStreams = 50)
            http3Settings = http3Settings { earlyData = Http3EarlyDataPolicy.Reject425() }
            logger = KuicksilverLogger.stderr(LogLevel.Info)
            qlog = AsyncQlogSink(DirectoryQlogSink("qlog"))
            eventListener =
                object : KuicksilverServerEventListener() {
                    override fun requestEnded(
                        protocol: HttpProtocolVersion,
                        call: ApplicationCall,
                        cause: Throwable?,
                    ) {}
                }
        }) {
            module()
            launch {
                delay(1.hours)
                try {
                    File(chainFile).readText()
                } catch (e: IOException) {
                } catch (e: TlsException) {
                }
            }
            install(WebSockets) { extensions { install(PerMessageDeflate) } }
            routing {
                get("/") {
                    call.response.priority(urgency = 4)
                    call.respondText("${call.request.peerCertificates.size} ${call.request.receivedEarly} ${call.request.priority}")
                }
                webTransport("/echo") { session ->
                    val stream = session.acceptBidi()
                    stream.input.copyTo(stream.output)
                }
            }
        }
    server.engine.http3Advertising = Http3Advertising.Drain
    kotlinx.coroutines.runBlocking {
        withTimeoutOrNull(1.minutes) { while (server.engine.http3Stats.sumOf { it.connectionsActive } > 0) delay(1.seconds) }
    }
}
